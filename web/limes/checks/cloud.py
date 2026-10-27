"""Open cloud storage from listing probes of buckets named after an owned root. Pure: no I/O.

A bucket is flagged only when the response proves anonymous listing (an S3/GCS ListBucketResult or an Azure
EnumerationResults document). Evidence is provider, name, status and a capped object COUNT: object names and
contents are never read into it. The bucket names derive from the owned root, so they are not hostile text, but the
renderers escape them like any evidence."""
import re

from limes.checks.catalogue import Result

CHECK = 'cloud.open_storage'
MAX_NAMES = 24  # per root
MAX_COUNT = 1000  # object count is capped (the body is capped at 1 MB anyway)
MAX_LISTED = 10
SUFFIXES = ('backup', 'backups', 'assets', 'static', 'prod', 'dev', 'data', 'staging', 'media', 'files', 'public',
            'uploads', 'logs', 'test', 'cdn', 'images', 'docs', 'internal', 'archive', 'db', 'web', 'www')
NAME_RE = re.compile(r'[a-z0-9][a-z0-9-]{1,61}[a-z0-9]')
LABEL_RE = re.compile(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?')

# Only these hosts are ever fetched: exact hosts, and one label under the suffix entries (limes.safe_fetch.host_allowed)
ALLOW_EXACT = ('storage.googleapis.com',)
ALLOW_SUFFIX = ('s3.amazonaws.com', 'blob.core.windows.net')
PROVIDERS = ('s3', 'azure', 'gcs')


def names(root):
    """At most MAX_NAMES candidate bucket names for a root domain: its first label, the whole root with dashes, and
    the label with common suffixes. Only DNS-label-safe names survive, so a name can never carry a host, a path or a
    query into a URL."""
    root = (root or '').strip().rstrip('.').lower()
    label = root.split('.')[0]
    if not root or not LABEL_RE.fullmatch(label):
        return []
    base = [label]
    dashed = root.replace('.', '-')
    if dashed != label:
        base.append(dashed)
    out = []
    for n in base + [f'{label}-{s}' for s in SUFFIXES]:
        if NAME_RE.fullmatch(n) and '--' not in n and n not in out:
            out.append(n)
    return out[:MAX_NAMES]


def url(provider, name):
    """The one GET for a provider and a name, or None when the name does not fit the provider (Azure account names
    are 3 to 24 letters and digits)."""
    if provider == 's3':
        return f'https://{name}.s3.amazonaws.com/'
    if provider == 'gcs':
        return f'https://storage.googleapis.com/{name}/'
    if provider == 'azure':
        account = name.replace('-', '')
        if 3 <= len(account) <= 24:
            return f'https://{account}.blob.core.windows.net/{name}?restype=container&comp=list'
    return None


def listing(provider, status, body):
    """Object count (capped) when the response proves anonymous listing, else None."""
    if status != 200 or not isinstance(body, (bytes, bytearray)):
        return None
    head = bytes(body[:1024])
    if provider in ('s3', 'gcs') and b'<ListBucketResult' in head:
        return min(body.count(b'<Key>'), MAX_COUNT)
    if provider == 'azure' and b'<EnumerationResults' in head:
        return min(body.count(b'<Blob>'), MAX_COUNT)
    return None


def evaluate(probes, complete):
    """One Result. probes = [{'provider', 'name', 'status': int | 'error' | None, 'objects': int | None}]; complete is
    False when the sweep was cut short (budget, rate limit): an unfinished sweep is never a pass."""
    hits = [p for p in probes if p['objects'] is not None]
    if hits:
        shown = [{'provider': p['provider'], 'name': p['name'], 'status': p['status'], 'objects': p['objects']}
                 for p in hits[:MAX_LISTED]]
        return Result(CHECK, 'fail', {'buckets': shown, 'count': len(hits)})
    errors = sum(1 for p in probes if p['status'] == 'error')
    if not complete:
        return Result(CHECK, 'error', {'reason': 'sweep cut short', 'tested': len(probes)})
    if probes and errors * 2 > len(probes):
        return Result(CHECK, 'error', {'reason': 'most probes failed', 'tested': len(probes), 'errors': errors})
    return Result(CHECK, 'pass', {'tested': len(probes)})
