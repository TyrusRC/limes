"""Secrets and backends referenced by crawled client JavaScript.

A detected secret key is never kept: only its shape (kind plus last 4 characters) leaves scan_text, and nothing
here logs, stores or raises with a token. The check is provisional (limes.checks.catalogue.PROVISIONAL)."""
import base64
import json
import logging
import os
import re

from urllib.parse import urlsplit

from limes import scope
from limes.checks.catalogue import CHECKS
from limes.tasks import intel
from startScan.models import Asset, RiskCheck

log = logging.getLogger(__name__)

SB_SECRET_RE = re.compile(r'\bsb_secret_[A-Za-z0-9_-]{16,}')
# Bounded so a hostile file cannot make matching quadratic; scan_text feeds it one candidate at a time.
JWT_RE = re.compile(r'\beyJ[A-Za-z0-9_-]{10,4096}\.eyJ[A-Za-z0-9_-]{10,4096}\.[A-Za-z0-9_-]{10,4096}')
BACKEND_RES = (
    ('supabase', re.compile(r'https://[a-z0-9-]{1,63}\.supabase\.co')),
    ('firebase', re.compile(r'https://[a-z0-9-]{1,63}\.(?:firebaseio\.com|firebaseapp\.com)')),
    # labels exclude '.', so every split of a host is unambiguous (no backtracking blow-up)
    ('s3', re.compile(r'https://(?:[a-z0-9-]{1,63}\.){1,4}s3(?:[.-][a-z0-9]{1,20}){0,3}\.amazonaws\.com')),
)
RUN_RE = re.compile(r'[A-Za-z0-9_.-]{30,}')  # maximal token runs: a JWT is one run, found in linear time
MAX_RUN = 16384
MAX_BACKENDS = 20
MAX_READ = 5 * 1024 * 1024
OWNED = ('owned_root', 'owned_host')
CHECK = 'leak.supabase_secret_key'
CODE_EXTS = ('.js', '.mjs', '.map')
PLACEHOLDER_RE = re.compile(r'(?i)xxxx|your|example|placeholder|changeme|insert|replace')
# JSON-escaped separators inside source maps' sourcesContent glue a key to the preceding letter ("\\n" + key)
_ESCAPES = ('\\n', '\\t', '\\r', '\\"', "\\'")


def shape(token, kind):
    return ('sb_secret_…' if kind == 'sb_secret' else 'JWT(service_role)…') + token[-4:]


def _service_role(token):
    try:
        payload = token.split('.')[1]
        data = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
    except Exception:  # noqa: BLE001 - hostile input (RecursionError, bad UTF-8, ...) is simply not a key
        return False
    return isinstance(data, dict) and data.get('role') == 'service_role'


def _real_secret(token):
    body = token[len('sb_secret_'):]
    return len(set(body)) >= 6 and not PLACEHOLDER_RE.search(body)


def _jwts(text):
    for run in RUN_RE.findall(text):
        if len(run) > MAX_RUN or 'eyJ' not in run:
            continue
        parts = run.split('.')
        for i in range(len(parts) - 2):
            cand = '.'.join(parts[i:i + 3])
            if parts[i].startswith('eyJ') and parts[i + 1].startswith('eyJ') and JWT_RE.fullmatch(cand):
                yield cand


def scan_text(text):
    for esc in _ESCAPES:
        text = text.replace(esc, ' ')
    secrets = [{'kind': 'sb_secret', 'shape': shape(m, 'sb_secret')} for m in SB_SECRET_RE.findall(text)
               if _real_secret(m)]
    secrets += [{'kind': 'jwt_service_role', 'shape': shape(m, 'jwt_service_role')}
                for m in _jwts(text) if _service_role(m)]
    backends, seen = [], set()
    for kind, rx in BACKEND_RES:
        for m in rx.finditer(text):
            ref = m.group(0)[:200]
            if ref not in seen and len(backends) < MAX_BACKENDS:
                seen.add(ref)
                backends.append({'kind': kind, 'ref': ref})
    return {'secrets': secrets, 'backends': backends}


def _read(path):
    with open(path, 'rb') as f:
        return f.read(MAX_READ).decode('utf-8', 'replace')


def scan_artifacts(art_dir, mapping, project, now):
    """Write leak.supabase_secret_key per owned host serving scanned .js/.map files, and merge the backends found.
    # NOTE: a key in JS served from a third-party CDN host is not attributed. Upgrade path: attribute by the page
    # that loaded it."""
    by_host = {}
    for name, url in mapping.items():
        host = scope.target_host(url) if name.lower().endswith(CODE_EXTS) else None
        if host:
            by_host.setdefault(host, []).append((name, url))
    assets = {a.value: a for a in Asset.objects.filter(
        project=project, kind__in=('hostname', 'root_domain'), scope_tier__in=OWNED, value__in=list(by_host))
        .exclude(state='retired')}
    per_host = {}
    for host in assets:  # only owned hosts are read and parsed
        entry = per_host[host] = {'secrets': [], 'backends': [], 'url': None}
        for name, url in by_host[host]:
            try:
                found = scan_text(_read(os.path.join(art_dir, os.path.basename(name))))
            except Exception as e:  # noqa: BLE001 - one bad file never stops the others; type only, never the text
                log.warning('leak scan: skipped an artifact (%s)', type(e).__name__)
                continue
            entry['backends'] += found['backends']
            if found['secrets'] and not entry['secrets']:
                u = urlsplit(url)  # scheme, host and path only: no userinfo, query or fragment
                entry['url'] = f'{u.scheme}://{host}{u.path}'[:500]
            entry['secrets'] += found['secrets']
    hosts = secrets = 0
    for host, entry in per_host.items():
        asset = assets[host]
        hosts += 1
        secrets += len(entry['secrets'])
        if entry['secrets']:
            first = entry['secrets'][0]
            status, evidence = 'fail', {'artifact_url': entry['url'], 'key_shape': first['shape'], 'kind': first['kind']}
        else:
            status, evidence = 'pass', {}
        RiskCheck.objects.update_or_create(
            asset=asset, check_id=CHECK,
            defaults={'status': status, 'severity': CHECKS[CHECK].severity, 'evidence': evidence, 'last_checked': now})
        if entry['backends']:
            old = ((asset.enrichment or {}).get('backends') or {}).get('items') or []
            items = []
            for b in old + entry['backends']:
                if b not in items and len(items) < MAX_BACKENDS:
                    items.append(b)
            intel._store(asset, 'backends', {'items': items}, now)
    log.info('leak scan: %d hosts, %d secret keys', hosts, secrets)
    return {'hosts': hosts, 'secrets': secrets}
