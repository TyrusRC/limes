"""API discovery for owned hosts that answered over HTTP: look for a published OpenAPI/Swagger document or a GraphQL
endpoint, record each API as an `api` asset, and run the provisional api.* checks (limes.checks.api).

GET only. Every request goes through safe_fetch.pinned_get: the host is resolved once, every answer vetted, the vetted IP
pinned, and the getter refuses any URL that is not on that host, so nothing here can reach a host the project does not
own. Bodies are capped at BODY_CAP and parsed with the stdlib json only; nothing from a document is executed. Titles,
paths and scheme names from a document are untrusted text: clipped here, escaped by every renderer."""
import json
import logging
import re
from urllib.parse import urlsplit

import requests
from celery.exceptions import SoftTimeLimitExceeded
from django.utils import timezone

from limes import safe_fetch, scope
from limes.checks import api as api_checks
from limes.checks.catalogue import CHECKS
from limes.identity import ScanIdentity
from limes.intel import ratelimit
from limes.scoring import _root_of
from startScan.models import Asset, RiskCheck

log = logging.getLogger(__name__)

SPEC_PATHS = ('/openapi.json', '/swagger.json', '/v2/api-docs', '/v3/api-docs', '/api-docs',
              '/swagger/v1/swagger.json', '/api/openapi.json', '/api/swagger.json')
UI_PATHS = ('/docs', '/redoc', '/swagger-ui/')  # evidence only
GRAPHQL_PATH = '/graphql'
DOC_PATHS = SPEC_PATHS + UI_PATHS + (GRAPHQL_PATH,)  # 12
BODY_CAP = 2 * 1024 * 1024
MAX_PROBE_PATHS = 20
MAX_HOSTS = 100
MAX_SERVERS = 10
MAX_SPEC_PATHS = 5000  # operations read from one document
HOST_SECONDS = 90  # one host's total wall clock (safe_fetch.Deadline)
TIMEOUT = 5
PROVIDER = 'api_discovery'
# NOTE: a daily ceiling on discovery requests over all projects (ratelimit.take_daily, which fails closed when the cache
# is down). Upgrade path: a setting, or a per-project budget.
DAILY_BUDGET = 20000
HTTP_METHODS = ('get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace')
PATH_OK = re.compile(r"^[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$")
OWNED = ('owned_root', 'owned_host')
DEFAULT_PORTS = {'http': 80, 'https': 443}


class BudgetSpent(Exception):
    """The daily request budget is used up (or could not be read): stop, fail closed."""


def clip(value, n=200):
    """Untrusted text from a document, as printable text of at most n characters; None when it is not text."""
    if not isinstance(value, str):
        return None
    return ''.join(c for c in value if c.isprintable())[:n]


# --- canonical values ---------------------------------------------------------------------------------------------

def canonical(url, host, scheme='https'):
    """('same', value) for a server URL on `host`: scheme://host[:port]/base/path, lower-case host, default port,
    query, fragment and trailing slash dropped. ('other', text) for a URL on another host (text only, never an
    asset); (None, None) when the URL is unusable (userinfo, template variables, odd characters)."""
    if not isinstance(url, str) or not url or len(url) > 500 or '{' in url or '\\' in url \
            or any(c.isspace() or ord(c) < 32 for c in url):
        return None, None
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None, None
    if parts.scheme or parts.netloc:  # absolute (or scheme-relative)
        s = (parts.scheme or scheme).lower()
        if s not in DEFAULT_PORTS or not parts.netloc or '@' in parts.netloc:
            return None, None
        name = (parts.hostname or '').rstrip('.').lower()
        if not name:
            return None, None
    else:
        s, name, port = scheme, host, None
        if not parts.path.startswith('/'):
            parts = parts._replace(path='/' + parts.path)
    path = parts.path.rstrip('/')
    if len(path) > 200 or not PATH_OK.match(path) or '..' in path.split('/'):
        return None, None
    shown = f'{s}://{name}{"" if port in (None, DEFAULT_PORTS[s]) else f":{port}"}{path}'
    if name != host:
        return 'other', clip(shown, 200)
    return 'same', shown


# --- reading documents --------------------------------------------------------------------------------------------

def read_body(resp):
    """(bytes, size, oversized): at most BODY_CAP bytes are kept; a longer body is reported oversized and dropped."""
    buf = b''
    for chunk in resp.iter_content(chunk_size=8192):
        buf += chunk
        if len(buf) > BODY_CAP:
            return b'', BODY_CAP + 1, True
    return buf, len(buf), False


def fetch(get, url, ua, counter):
    """{'status': int | 'error', 'size': int, 'json': object | None}. One GET; JSON only for a 200 within the cap."""
    if not ratelimit.take_daily(PROVIDER, DAILY_BUDGET):
        raise BudgetSpent()
    counter['requests'] = counter.get('requests', 0) + 1
    out = {'status': 'error', 'size': 0, 'json': None}
    try:
        resp = get(url, headers={'User-Agent': ua, 'Accept': 'application/json'}, timeout=TIMEOUT,
                   allow_redirects=False, stream=True)
        try:
            out['status'] = resp.status_code
            body, out['size'], oversized = read_body(resp)
            if not oversized and resp.status_code in (200, 400) and body:
                try:
                    out['json'] = json.loads(body)
                except (ValueError, RecursionError):  # includes bad UTF-8
                    pass
        finally:
            resp.close()
    except SoftTimeLimitExceeded:
        raise
    except (requests.exceptions.RequestException, OSError, TimeoutError, ValueError):
        out['status'] = 'error'
    return out


def parse_spec(doc):
    """What a valid OpenAPI 3 / Swagger 2 document says, or None when it is not one."""
    if not isinstance(doc, dict) or not isinstance(doc.get('paths'), dict):
        return None
    oas3 = isinstance(doc.get('openapi'), str) and doc['openapi'].startswith('3')
    swagger2 = isinstance(doc.get('swagger'), str) and doc['swagger'].startswith('2')
    if not (oas3 or swagger2):
        return None
    info = doc.get('info') if isinstance(doc.get('info'), dict) else {}
    methods, get_paths, endpoints = set(), [], 0
    for path, item in list(doc['paths'].items())[:MAX_SPEC_PATHS]:
        if not isinstance(path, str) or not isinstance(item, dict):
            continue
        endpoints += 1
        for m in HTTP_METHODS:
            if isinstance(item.get(m), dict):
                methods.add(m.upper())
                if m == 'get' and path.startswith('/') and '{' not in path and '?' not in path \
                        and len(path) <= 200 and PATH_OK.match(path) and '..' not in path.split('/'):
                    get_paths.append(path)
    defs = (doc.get('components') or {}).get('securitySchemes') if oas3 and isinstance(doc.get('components'), dict) \
        else doc.get('securityDefinitions')
    defs = defs if isinstance(defs, dict) else {}
    auth = set()
    for scheme in list(defs.values())[:50]:
        if isinstance(scheme, dict) and clip(scheme.get('type'), 40):
            kind = clip(scheme.get('type'), 40)
            sub = clip(scheme.get('scheme'), 20) if kind == 'http' else None
            auth.add(f'{kind}:{sub}' if sub else kind)
    return {'title': clip(info.get('title')), 'version': clip(info.get('version'), 50), 'endpoints': endpoints,
            'methods': sorted(methods), 'auth_schemes': sorted(auth)[:10], 'schemes': len(defs),
            'get_paths': sorted(set(get_paths))[:MAX_PROBE_PATHS], 'servers': _servers(doc, oas3)}


def _servers(doc, oas3):
    if oas3:
        urls = [s.get('url') for s in (doc.get('servers') or []) if isinstance(s, dict)] \
            if isinstance(doc.get('servers'), list) else []
        return (urls or ['/'])[:MAX_SERVERS]
    base = doc.get('basePath') if isinstance(doc.get('basePath'), str) else '/'
    host = doc.get('host') if isinstance(doc.get('host'), str) else None
    schemes = [s for s in (doc.get('schemes') or []) if isinstance(s, str)] if isinstance(doc.get('schemes'), list) else []
    if not host:
        return [base]
    return [f'{s}://{host}{base}' for s in (schemes or ['https'])][:MAX_SERVERS]


def looks_like_graphql(result):
    j = result['json']
    return result['status'] in (200, 400) and isinstance(j, dict) and (isinstance(j.get('errors'), list) or 'data' in j)


# --- one host -----------------------------------------------------------------------------------------------------

def _tier(parent):
    return 'owned_host' if parent.scope_tier == 'owned_root' else parent.scope_tier  # an API is never a root


def _upsert(host, value, enrichment, now):
    asset, created = Asset.objects.get_or_create(
        project_id=host.project_id, kind='api', value=value,
        defaults={'parent': host, 'scope_tier': _tier(host), 'active_authorized': host.active_authorized,
                  'sources': [{'source': 'api_discovery', 'evidence': host.value, 'seen_at': now.isoformat()}],
                  'enrichment': enrichment, 'first_seen': now, 'last_seen': now})
    if not created:
        asset.enrichment, asset.state, asset.missed_count, asset.last_seen = enrichment, 'active', 0, now
        asset.scope_tier, asset.active_authorized = _tier(host), host.active_authorized
        asset.save(update_fields=['enrichment', 'state', 'missed_count', 'last_seen', 'scope_tier', 'active_authorized'])
    return asset


def _probe(get, base, paths, ua, counter):
    """Unauthenticated GET of each documented path once; 'open' = answered 200 with a JSON body."""
    probe = {'tested': 0, 'errors': 0, 'open': []}
    for path in paths[:MAX_PROBE_PATHS]:
        r = fetch(get, base + path, ua, counter)
        probe['tested'] += 1
        if r['status'] == 'error':
            probe['errors'] += 1
        elif r['status'] == 200 and r['json'] is not None:
            probe['open'].append({'path': path, 'status': 200, 'size': r['size']})
    return probe


def _write_checks(asset, results, now):
    for r in results:
        RiskCheck.objects.update_or_create(
            asset=asset, check_id=r.check,
            defaults={'status': r.status, 'severity': CHECKS[r.check].severity, 'evidence': r.evidence, 'last_checked': now})


def discover_host(host, get, ua, now, counter):
    """Find and record the APIs served from one host; returns the api assets seen."""
    scheme = 'https'
    base = f'{scheme}://{host.value}'
    docs = {p: fetch(get, base + p, ua, counter) for p in DOC_PATHS}
    ui = [{'path': p, 'status': docs[p]['status'], 'size': docs[p]['size']} for p in UI_PATHS if docs[p]['status'] == 200]
    found = {}  # value -> {'enrichment', 'obs'}
    for path in SPEC_PATHS:
        r = docs[path]
        spec = parse_spec(r['json']) if r['status'] == 200 else None
        if spec is None:
            continue
        same, other = [], []
        for url in spec['servers']:
            kind, value = canonical(url, host.value, scheme)
            if kind == 'same':
                same.append(value)
            elif kind == 'other':
                other.append(value)
        probe_ok = bool(same)
        for value in (same or [base]):
            if value in found:
                continue
            enrichment = {'spec_url': base + path, 'title': spec['title'], 'version': spec['version'],
                          'endpoints': spec['endpoints'], 'methods': spec['methods'], 'auth_schemes': spec['auth_schemes']}
            if other:
                enrichment['other_servers'] = sorted(set(other))[:5]  # text only: no asset, no request
            if ui:
                enrichment['docs_ui'] = ui
            found[value] = {'enrichment': enrichment, 'spec': spec, 'path': path, 'size': r['size'], 'probe_ok': probe_ok}
    if looks_like_graphql(docs[GRAPHQL_PATH]):
        value = base + GRAPHQL_PATH
        found.setdefault(value, {'enrichment': {'protocol': 'graphql', 'spec_url': value, 'status': docs[GRAPHQL_PATH]['status'],
                                                'size': docs[GRAPHQL_PATH]['size']}, 'spec': None})
    assets = []
    for value, f in found.items():
        asset = _upsert(host, value, f['enrichment'], now)
        assets.append(asset)
        if f['spec'] is None:
            _write_checks(asset, api_checks.evaluate({'protocol': 'graphql'}), now)
            continue
        spec = f['spec']
        probe = _probe(get, value, spec['get_paths'], ua, counter) if spec['schemes'] and f['probe_ok'] else None
        _write_checks(asset, api_checks.evaluate({'spec': {'path': f['path'], 'status': 200, 'size': f['size'],
                                                           'schemes': spec['schemes']}, 'probe': probe}), now)
    seen = {a.pk for a in assets}
    for old in Asset.objects.filter(parent=host, kind='api').exclude(pk__in=seen):
        old.mark_missing_or_seen(False)  # the host answered, the API did not show: ages like any asset
    return assets


# --- the stage ----------------------------------------------------------------------------------------------------

def _hosts(project, root):
    cands = [a for a in Asset.objects.filter(project=project, kind__in=('hostname', 'root_domain'), http_status__isnull=False,
                                             scope_tier__in=OWNED + ('co_brand',)).exclude(state='retired')
             if _root_of(a.value, [root.value])]
    allowed, _refused = scope.may_attack(project, [a.value for a in cands])  # active scanning allowed, public addresses
    ok = set(allowed)
    return sorted((a for a in cands if a.value in ok), key=lambda a: a.value)[:MAX_HOSTS]


def _pinned(host):
    ip, reason = safe_fetch.resolve_vetted(host)
    if reason:
        log.info('api discovery: %s not contacted: %s', host, reason)
        return None
    return safe_fetch.pinned_get(host, ip, deadline=safe_fetch.Deadline(HOST_SECONDS))


def discover(project, root, now=None, make_get=_pinned):
    """Run API discovery for the hosts under one owned root. Never raises into the stage for one host's trouble."""
    now = now or timezone.now()
    counter, apis, hosts = {'requests': 0}, 0, 0
    try:
        for host in _hosts(project, root):
            get = make_get(host.value)
            if get is None:
                continue
            ua = ScanIdentity.for_domain(host if host.request_headers else root).ua
            try:
                apis += len(discover_host(host, get, ua, now, counter))
                hosts += 1
            except (BudgetSpent, SoftTimeLimitExceeded):
                raise
            except Exception as e:  # noqa: BLE001 - one host never stops the rest; type only
                log.error('api discovery failed for %s: %s', host.value, type(e).__name__)
    except BudgetSpent:
        log.warning('api discovery: the daily request budget is spent; stopping')
    return {'hosts': hosts, 'apis': apis, 'requests': counter['requests']}
