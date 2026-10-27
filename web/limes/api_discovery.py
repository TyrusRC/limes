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
MAX_APIS_PER_HOST = 10
MAX_SPECS_PER_HOST = 3  # valid documents followed per host
WEB_PORTS = (None, 443, 8443)  # a document may name only these (https only); anything else is text
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


class HostDeadline(Exception):
    """The host's time is up: no more requests to it, and no budget spent on requests that cannot happen."""


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
    if port == DEFAULT_PORTS[s]:
        port = None
    shown = f'{s}://{name}{"" if port is None else f":{port}"}{path}'
    # the document picks neither the scheme nor the port of what we request: https on 443/8443 of this host only
    if name != host or s != 'https' or port not in WEB_PORTS:
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


def fetch(get, url, ua, counter, deadline):
    """{'status': int | 'error', 'size': int, 'json': object | None}. One GET; JSON only for a 200 within the cap.
    The host deadline is checked before the budget is touched, so a late request costs nothing."""
    if deadline.expired():
        raise HostDeadline()
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
    """The api asset for this sighting, or None when a person (reject) or time (retired) has settled it: those are
    left exactly as they are. An existing asset follows its parent's tier and is seen like any other asset."""
    asset, created = Asset.objects.get_or_create(
        project_id=host.project_id, kind='api', value=value,
        defaults={'parent': host, 'scope_tier': _tier(host), 'active_authorized': host.active_authorized,
                  'sources': [{'source': 'api_discovery', 'evidence': host.value, 'seen_at': now.isoformat()}],
                  'enrichment': enrichment, 'first_seen': now, 'last_seen': now})
    if created:
        return asset
    if asset.scope_tier == 'rejected' or asset.state == 'retired':
        return None
    asset.enrichment, asset.scope_tier, asset.active_authorized = enrichment, _tier(host), host.active_authorized
    asset.save(update_fields=['enrichment', 'scope_tier', 'active_authorized'])  # (a rejected asset returned above)
    asset.mark_missing_or_seen(True)  # a sighting resets the miss count and revives a missing or stale asset
    return asset


def _probe(get, base, paths, ua, counter, budget, deadline):
    """Unauthenticated GET of each documented path once; 'open' = answered 200 with a JSON body. The host's probe
    budget (20 URLs) is shared by all its APIs, and a URL already fetched is not fetched again. A path the host's
    time did not allow counts as an error, so a sweep cut short is never a pass."""
    probe = {'tested': 0, 'errors': 0, 'open': []}
    for path in paths:
        url = base + path
        if url in budget['seen'] or budget['left'] <= 0:
            continue
        budget['seen'].add(url)
        budget['left'] -= 1
        probe['tested'] += 1
        try:
            r = fetch(get, url, ua, counter, deadline)
        except HostDeadline:
            probe['errors'] += 1
            continue
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


def discover_host(host, get, ua, now, counter, deadline):
    """Find and record the APIs served from one host; returns the api assets seen. Per host: 12 documentation GETs,
    at most MAX_SPECS_PER_HOST documents followed, MAX_APIS_PER_HOST assets and one shared 20-URL probe budget."""
    scheme = 'https'
    base = f'{scheme}://{host.value}'
    docs = {}
    for p in DOC_PATHS:
        try:
            docs[p] = fetch(get, base + p, ua, counter, deadline)
        except HostDeadline:
            docs[p] = {'status': 'error', 'size': 0, 'json': None}
    answered = any(isinstance(r['status'], int) for r in docs.values())
    ui = [{'path': p, 'status': docs[p]['status'], 'size': docs[p]['size']} for p in UI_PATHS if docs[p]['status'] == 200]
    found, followed = {}, 0  # value -> {'enrichment', 'spec', ...}
    for path in SPEC_PATHS:
        r = docs[path]
        spec = parse_spec(r['json']) if r['status'] == 200 else None
        if spec is None:
            continue
        followed += 1
        if followed > MAX_SPECS_PER_HOST:
            break
        same, other = [], []
        for url in spec['servers']:
            kind, value = canonical(url, host.value, scheme)
            if kind == 'same':
                same.append(value)
            elif kind == 'other':
                other.append(value)
        for value in (same or [base]):
            if value in found:
                continue
            enrichment = {'spec_url': base + path, 'title': spec['title'], 'version': spec['version'],
                          'endpoints': spec['endpoints'], 'methods': spec['methods'], 'auth_schemes': spec['auth_schemes']}
            if other:
                enrichment['other_servers'] = sorted(set(other))[:5]  # text only: no asset, no request
            if ui:
                enrichment['docs_ui'] = ui
            found[value] = {'enrichment': enrichment, 'spec': spec, 'path': path, 'size': r['size'], 'probe_ok': bool(same)}
    if looks_like_graphql(docs[GRAPHQL_PATH]):
        value = base + GRAPHQL_PATH
        found.setdefault(value, {'enrichment': {'protocol': 'graphql', 'spec_url': value, 'status': docs[GRAPHQL_PATH]['status'],
                                                'size': docs[GRAPHQL_PATH]['size']}, 'spec': None})
    budget = {'left': MAX_PROBE_PATHS, 'seen': set()}
    assets = []
    for value, f in list(found.items())[:MAX_APIS_PER_HOST]:
        asset = _upsert(host, value, f['enrichment'], now)
        if asset is None:  # rejected by a person or retired: untouched, and not probed
            continue
        assets.append(asset)
        if f['spec'] is None:
            _write_checks(asset, api_checks.evaluate({'protocol': 'graphql'}), now)
            continue
        spec = f['spec']
        probe = _probe(get, value, spec['get_paths'], ua, counter, budget, deadline) if spec['schemes'] and f['probe_ok'] else None
        _write_checks(asset, api_checks.evaluate({'spec': {'path': f['path'], 'status': 200, 'size': f['size'],
                                                           'schemes': spec['schemes']}, 'probe': probe}), now)
    if answered:  # only a host that answered can say an API is gone; an outage ages nothing
        stale = Asset.objects.filter(parent=host, kind='api').exclude(pk__in={a.pk for a in assets}) \
            .exclude(scope_tier='rejected').exclude(state='retired')
        for old in stale:
            old.mark_missing_or_seen(False)
    return assets


def sync_tiers(project):
    """An API's tier follows its parent's (an owned_root parent gives owned_host): a host that was rejected or fell
    back to candidate takes its APIs with it, and gives them back when it is owned again. A reject made on the API
    itself stays: only a 'rejected' set here (marked rejected_with_parent) is ever undone here."""
    changed = []
    for api in Asset.objects.filter(project=project, kind='api').select_related('parent'):
        if api.parent is None:
            continue
        enrichment = dict(api.enrichment or {})
        by_parent = enrichment.get('rejected_with_parent') is True
        if api.scope_tier == 'rejected' and not by_parent:
            continue  # a person's decision
        want = _tier(api.parent)
        if want == api.scope_tier and not (by_parent and want != 'rejected'):
            continue
        if want == 'rejected':
            enrichment['rejected_with_parent'] = True
        else:
            enrichment.pop('rejected_with_parent', None)
        api.scope_tier, api.active_authorized, api.enrichment = want, api.parent.active_authorized, enrichment
        changed.append(api)
    if changed:
        Asset.objects.bulk_update(changed, ['scope_tier', 'active_authorized', 'enrichment'])


# --- the stage ----------------------------------------------------------------------------------------------------

def _hosts(project, root):
    cands = [a for a in Asset.objects.filter(project=project, kind__in=('hostname', 'root_domain'), http_status__isnull=False,
                                             scope_tier__in=OWNED).exclude(state='retired')
             if _root_of(a.value, [root.value])]
    allowed, _refused = scope.may_attack(project, [a.value for a in cands], allow_co_brand=False)  # owned, public addresses
    ok = set(allowed)
    return sorted((a for a in cands if a.value in ok), key=lambda a: a.value)[:MAX_HOSTS]


def _pinned(host, deadline):
    ip, reason = safe_fetch.resolve_vetted(host)
    if reason:
        log.info('api discovery: %s not contacted: %s', host, reason)
        return None
    return safe_fetch.pinned_get(host, ip, deadline=deadline)


def discover(project, root, now=None, make_get=_pinned):
    """Run API discovery for the hosts under one owned root. Never raises into the stage for one host's trouble."""
    now = now or timezone.now()
    counter, apis, hosts = {'requests': 0}, 0, 0
    try:
        sync_tiers(project)
        for host in _hosts(project, root):
            deadline = safe_fetch.Deadline(HOST_SECONDS)  # one clock for the pinned fetcher and for our own checks
            get = make_get(host.value, deadline)
            if get is None:
                continue
            ua = ScanIdentity.for_domain(host if host.request_headers else root).ua
            try:
                apis += len(discover_host(host, get, ua, now, counter, deadline))
                hosts += 1
            except (BudgetSpent, SoftTimeLimitExceeded):
                raise
            except Exception as e:  # noqa: BLE001 - one host never stops the rest; type only
                log.error('api discovery failed for %s: %s', host.value, type(e).__name__)
    except BudgetSpent:
        log.warning('api discovery: the daily request budget is spent; stopping')
    return {'hosts': hosts, 'apis': apis, 'requests': counter['requests']}
