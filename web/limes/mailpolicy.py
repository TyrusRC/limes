"""Provisional mail-policy checks and dns.dangling_ns for one owned root domain (limes.checks.mailpolicy, checks.dns).

DNS only, except one GET: when the domain has an MTA-STS TXT record, its policy file at
https://mta-sts.<domain>/.well-known/mta-sts.txt, fetched through safe_fetch.pinned_get (host resolved once and vetted,
connection pinned to that IP, certificate verified, no redirect, 64 KB read) after a slot of the shared daily budget
(fails closed: a spent budget or a busy limiter makes the check an error, never a pass). The mail checks apply only to a
domain that has MX hosts; one without them gets not_applicable rows. The name-server check apply to every owned root."""
import logging
import time

import dns.resolver
import requests
from celery.exceptions import SoftTimeLimitExceeded
from django.utils import timezone

from limes import safe_fetch
from limes.checks import collect, dns as dns_checks, mailpolicy
from limes.checks.catalogue import Result
from limes.checks.run import _write
from limes.identity import ScanIdentity
from limes.intel import ratelimit

log = logging.getLogger(__name__)

PROVIDER = 'mtasts'
DAILY_BUDGET = 2000  # NOTE: shared by all projects, a quarter each (ratelimit.take_shared); upgrade path: a setting
INTERVAL = 0.25
MAX_WAIT = 5
BODY_CAP = 64 * 1024
TIMEOUT = 5
MAX_NS = 10  # name servers looked up per root


def _read(resp):
    buf = b''
    for chunk in resp.iter_content(chunk_size=8192):
        buf += chunk[:BODY_CAP - len(buf)]
        if len(buf) >= BODY_CAP:
            break
    return buf


def fetch_policy(domain, ua, resolve, sleep, session_factory=requests.Session, clock=time.time, project_id=0):
    """{'status': int | 'unresolved' | 'error', 'body': bytes | None, 'reason': str | None} for the MTA-STS policy file."""
    host = f'mta-sts.{domain}'
    ip, reason = safe_fetch.resolve_vetted(host, resolve=resolve)
    if reason:
        # a name that does not exist is a real gap (no policy host); any other refusal is unknown
        if reason.endswith(safe_fetch.NOT_RESOLVED):
            return {'status': 'unresolved', 'body': None, 'reason': 'policy_host_unresolved'}
        return {'status': 'error', 'body': None, 'reason': 'policy host not contactable'}
    if not ratelimit.take_shared(PROVIDER, DAILY_BUDGET, project_id):
        return {'status': 'error', 'body': None, 'reason': 'budget'}
    wait = ratelimit.reserve(PROVIDER, INTERVAL, clock())
    if wait is None or wait > MAX_WAIT:
        return {'status': 'error', 'body': None, 'reason': 'busy'}
    if wait:
        sleep(wait)
    get = safe_fetch.pinned_get(host, ip, session_factory=session_factory)
    try:
        resp = get(f'https://{host}/.well-known/mta-sts.txt', headers={'User-Agent': ua}, timeout=TIMEOUT,
                   allow_redirects=False, stream=True)
        try:
            return {'status': resp.status_code, 'body': _read(resp) if resp.status_code == 200 else None, 'reason': None}
        finally:
            resp.close()
    except SoftTimeLimitExceeded:
        raise
    except (requests.exceptions.RequestException, OSError, TimeoutError, ValueError):
        return {'status': 'error', 'body': None, 'reason': 'fetch failed'}


_host = collect._lookup


def nameserver_obs(root, resolve):
    ns = _host(resolve, root, 'NS')
    if ns == 'error':
        return {'ns': ns, 'gone': [], 'unknown': 0}
    names = sorted({n.rstrip('.').lower() for n in ns if n.strip('.')})[:MAX_NS]
    gone, unknown = [], 0
    for n in names:
        try:
            resolve(n, 'A')
        except dns.resolver.NXDOMAIN:
            gone.append(n)
        except dns.resolver.NoAnswer:
            pass
        except Exception:  # noqa: BLE001 - any other failure is "unknown", never a finding
            unknown += 1
    return {'ns': names, 'gone': gone, 'unknown': unknown}


def mail_results(root, ua, resolve, sleep, session_factory=requests.Session, clock=time.time, project_id=0):
    mx = collect._mx_hosts(_host(resolve, root, 'MX'))
    if mx == 'error':
        return [Result(r.check, 'error', {}) for r in mailpolicy.not_applicable()]
    if not mx:
        return mailpolicy.not_applicable()
    obs = {'mx': mx, 'sts': _host(resolve, f'_mta-sts.{root}', 'TXT'), 'policy': None,
           'tlsrpt': _host(resolve, f'_smtp._tls.{root}', 'TXT'), 'bimi': _host(resolve, f'default._bimi.{root}', 'TXT'),
           'dmarc': _host(resolve, f'_dmarc.{root}', 'TXT')}
    if obs['sts'] != 'error' and mailpolicy.first(obs['sts'], 'v=stsv1'):
        obs['policy'] = fetch_policy(root, ua, resolve, sleep, session_factory, clock, project_id)
    return mailpolicy.evaluate(obs)


def results(root, resolve=collect._resolve, sleep=time.sleep, session_factory=requests.Session, clock=time.time):
    """The five results for an owned root_domain asset, in one list."""
    ua = ScanIdentity.for_domain(root).ua
    return (mail_results(root.value, ua, resolve, sleep, session_factory, clock, root.project_id)
            + [dns_checks.evaluate_ns(nameserver_obs(root.value, resolve))])


def discover(project, root, now=None, resolve=collect._resolve, sleep=time.sleep, session_factory=requests.Session,
             clock=time.time):
    """Write the rows for one owned root. Never raises into the stage (the caller also guards it)."""
    if root.kind != 'root_domain' or root.scope_tier != 'owned_root':
        return {'checked': 0}
    got = results(root, resolve, sleep, session_factory, clock)
    _write(root, got, now or timezone.now())
    return {'checked': len(got), 'flagged': sum(r.status == 'fail' for r in got)}
