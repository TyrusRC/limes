"""Dangling-DNS takeover from a hostname's CNAME target and what the provider answers. Pure: no I/O.

PROVIDERS is a small curated table: a CNAME that ends in one of its suffixes is a candidate. It is flagged when the
name no longer resolves (the CNAME points at a provider resource that is gone), or when the provider answers a GET for
the owned hostname with its well-known 'unclaimed' page. Evidence is the provider id, the CNAME target (the owner's own
DNS, clipped), the status code and the fingerprint ID: never the body."""
import re

from limes.checks.catalogue import Result

CHECK = 'dns.dangling_takeover'
MAX_TARGET = 255

# id -> (suffixes or None, regex or None, statuses, marker); marker (bytes) None: no 'unclaimed' page is known, only
# an NXDOMAIN counts.
# NOTE: curated from public takeover write-ups; providers change their pages and their rules. Upgrade path: a data file
# reviewed against can-i-take-over-xyz, with a test per row.
_AZURE = ('azurewebsites.net', 'cloudapp.azure.com', 'cloudapp.net', 'trafficmanager.net', 'blob.core.windows.net',
          'azureedge.net')
PROVIDERS = {
    'github_pages': (('github.io',), None, (404,), b"There isn't a GitHub Pages site here"),
    'heroku': (('herokuapp.com', 'herokudns.com'), None, (404,), b'No such app'),
    's3_bucket': (None, re.compile(r'(?:^|\.)s3[a-z0-9.-]*\.amazonaws\.com$'), (404,), b'NoSuchBucket'),
    'azure': (_AZURE, None, (), None),
    'fastly': (('fastly.net',), None, (404, 500, 503), b'Fastly error: unknown domain'),
    'shopify': (('myshopify.com',), None, (404, 503), b'Sorry, this shop is currently unavailable'),
    'netlify': (('netlify.app', 'netlify.com'), None, (404,), b'Not Found - Request ID'),
    'surge': (('surge.sh',), None, (404,), b'project not found'),
    'bitbucket': (('bitbucket.io',), None, (404,), b'Repository not found'),
    'ghost': (('ghost.io',), None, (404,), b'The thing you were looking for is no longer here'),
    'pantheon': (('pantheonsite.io',), None, (404,), b'404 error unknown site'),
}


def match(target):
    """The provider id a CNAME target belongs to, or None."""
    t = (target or '').strip().rstrip('.').lower()
    for pid, (suffixes, rx, *_rest) in PROVIDERS.items():
        if suffixes and any(t == s or t.endswith('.' + s) for s in suffixes):
            return pid
        if rx and rx.search(t):
            return pid
    return None


def fingerprint(provider, status, body):
    """The fingerprint id when the provider's 'unclaimed' page answered, else None."""
    _s, _rx, statuses, marker = PROVIDERS[provider]
    if marker and status in statuses and isinstance(body, (bytes, bytearray)) and marker in body:
        return f'{provider}-{status}'
    return None


def evaluate(obs):
    """One Result. obs = {'provider': id | None, 'target': str, 'nxdomain': True | False | None,
    'probe': None | {'status': int | 'error' | None, 'fingerprint': str | None}}."""
    pid = obs.get('provider')
    if not pid:
        return Result(CHECK, 'not_applicable', {})
    base = {'provider': pid, 'target': (obs.get('target') or '')[:MAX_TARGET]}
    probe = obs.get('probe')
    if obs.get('nxdomain'):
        return Result(CHECK, 'fail', {**base, 'status': None, 'fingerprint': 'nxdomain'})
    if probe and probe.get('fingerprint'):
        return Result(CHECK, 'fail', {**base, 'status': probe['status'], 'fingerprint': probe['fingerprint']})
    if obs.get('nxdomain') is None or (probe and probe.get('status') == 'error'):
        return Result(CHECK, 'error', {**base, 'reason': 'could not tell'})
    return Result(CHECK, 'pass', base)
