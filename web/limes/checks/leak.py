"""Secrets and backends referenced by crawled client JavaScript.

A detected secret key is never kept: only its shape (kind plus last 4 characters) leaves scan_text, and nothing
here logs, stores or raises with a token. The check is provisional (limes.checks.catalogue.PROVISIONAL)."""
import base64
import json
import logging
import os
import re

from limes import scope
from limes.tasks import intel
from startScan.models import Asset, RiskCheck

log = logging.getLogger(__name__)

SB_SECRET_RE = re.compile(r'\bsb_secret_[A-Za-z0-9_-]{16,}')
JWT_RE = re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')
BACKEND_RES = (
    ('supabase', re.compile(r'https://[a-z0-9-]+\.supabase\.co')),
    ('firebase', re.compile(r'https://[a-z0-9-]+\.(?:firebaseio\.com|firebaseapp\.com)')),
    ('s3', re.compile(r'https://[a-z0-9.-]+\.s3[a-z0-9.-]*\.amazonaws\.com')),
)
MAX_BACKENDS = 20
MAX_READ = 5 * 1024 * 1024
OWNED = ('owned_root', 'owned_host')
CHECK = 'leak.supabase_secret_key'


def shape(token, kind):
    return ('sb_secret_…' if kind == 'sb_secret' else 'JWT(service_role)…') + token[-4:]


def _service_role(token):
    try:
        payload = token.split('.')[1]
        data = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
    except (ValueError, IndexError):  # binascii.Error and UnicodeDecodeError are ValueErrors
        return False
    return isinstance(data, dict) and data.get('role') == 'service_role'


def scan_text(text):
    secrets = [{'kind': 'sb_secret', 'shape': shape(m, 'sb_secret')} for m in SB_SECRET_RE.findall(text)]
    secrets += [{'kind': 'jwt_service_role', 'shape': shape(m, 'jwt_service_role')}
                for m in JWT_RE.findall(text) if _service_role(m)]
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
    per_host = {}
    for name, url in mapping.items():
        if not name.lower().endswith(('.js', '.map')):
            continue
        host = scope.target_host(url)
        if not host:
            continue
        try:
            found = scan_text(_read(os.path.join(art_dir, os.path.basename(name))))
        except OSError as e:
            log.warning('leak scan: cannot read an artifact (%s)', type(e).__name__)
            continue
        entry = per_host.setdefault(host, {'secrets': [], 'backends': [], 'url': None})
        entry['backends'] += found['backends']
        if found['secrets'] and not entry['secrets']:
            entry['url'] = url.split('?')[0].split('#')[0][:500]  # a query string could carry a key
        entry['secrets'] += found['secrets']
    assets = {a.value: a for a in Asset.objects.filter(
        project=project, kind__in=('hostname', 'root_domain'), scope_tier__in=OWNED, value__in=list(per_host))
        .exclude(state='retired')}
    hosts = secrets = 0
    for host, entry in per_host.items():
        asset = assets.get(host)
        if asset is None:
            continue
        hosts += 1
        secrets += len(entry['secrets'])
        if entry['secrets']:
            first = entry['secrets'][0]
            status, evidence = 'fail', {'artifact_url': entry['url'], 'key_shape': first['shape'], 'kind': first['kind']}
        else:
            status, evidence = 'pass', {}
        RiskCheck.objects.update_or_create(
            asset=asset, check_id=CHECK,
            defaults={'status': status, 'severity': 4, 'evidence': evidence, 'last_checked': now})
        if entry['backends']:
            old = ((asset.enrichment or {}).get('backends') or {}).get('items') or []
            items = []
            for b in old + entry['backends']:
                if b not in items and len(items) < MAX_BACKENDS:
                    items.append(b)
            intel._store(asset, 'backends', {'items': items}, now)
    log.info('leak scan: %d hosts, %d secret keys', hosts, secrets)
    return {'hosts': hosts, 'secrets': secrets}
