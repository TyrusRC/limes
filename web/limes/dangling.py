"""dns.dangling_takeover for owned hostnames whose CNAME points at a takeover-prone provider (limes.checks.takeover).

Stored data first: the CNAME comes from the asset (dnsx / the DNS watch) and 'it resolves' from the stored answer, so
a healthy host costs no query at all. Only a host that does not look resolved gets one DNS query (never the target's own
address). A host that resolves and whose provider has a known 'unclaimed' page gets ONE plain-HTTP GET of the OWNED
hostname (the page is the provider's answer for a name it does not serve), through safe_fetch.pinned_get on the vetted
IP, no redirect followed, 64 KB read, after a slot of the shared daily budget (fails closed). The body is only
searched for the marker: the evidence keeps the provider, the status and a fingerprint id. Provisional (0 points)."""
import logging
import time
from datetime import timedelta

import dns.exception
import dns.resolver
import requests
from celery.exceptions import SoftTimeLimitExceeded
from django.utils import timezone

from limes import safe_fetch, scope
from limes.checks import collect, takeover
from limes.checks.catalogue import Result
from limes.checks.run import _write
from limes.identity import ScanIdentity
from limes.intel import ratelimit
from limes.scoring import _root_of
from startScan.models import Asset, RiskCheck

log = logging.getLogger(__name__)

PROVIDER = 'dangling'
DAILY_BUDGET = 2000  # NOTE: shared by all projects, a quarter each (ratelimit.take_shared); upgrade path: a setting
RUN_SECONDS = 15 * 60  # total wall clock per root; hosts not reached go first next run
INTERVAL = 0.25
MAX_WAIT = 5
BODY_CAP = 64 * 1024
TIMEOUT = 5
MAX_HOSTS = 200
REFRESH = timedelta(hours=20)
ERROR_RETRY = timedelta(hours=6)
OWNED = ('owned_root', 'owned_host')


def stored_cname(asset):
    """The CNAME target on record (first hop), or None. The DNS watch's answer is the live record and wins, an empty
    list meaning 'no CNAME'; Asset.cname is never cleared by dnsx, so it is only the fallback when no answer is stored."""
    rec = (asset.enrichment or {}).get('dns')
    if isinstance(rec, dict) and 'cname' in rec:
        chain = rec.get('cname') or []
        return str(chain[0]).rstrip('.').lower() if chain else None
    if asset.cname:
        return asset.cname.split(',')[0].strip().rstrip('.').lower() or None
    return None


def stored_resolves(asset):
    """True when the stored answer has an address; None when there is no stored answer or it was empty."""
    rec = (asset.enrichment or {}).get('dns') or {}
    return True if (rec.get('a') or rec.get('aaaa')) else None


def live_cname(resolve, host):
    """The host's CNAME target now: a name, None when it has none (NXDOMAIN or no CNAME), 'error' when the lookup failed."""
    try:
        got = resolve(host, 'CNAME')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    except (dns.exception.DNSException, OSError, ValueError):
        return 'error'
    return str(got[0]).rstrip('.').lower() if got else None


def nxdomain(resolve, host):
    """True: NXDOMAIN. False: the name exists. None: the lookup failed (unknown, never a finding)."""
    try:
        resolve(host, 'A')
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except dns.resolver.NoAnswer:
        return False
    except (dns.exception.DNSException, OSError, ValueError):
        return None


def _read(resp):
    buf = b''
    for chunk in resp.iter_content(chunk_size=8192):
        buf += chunk[:BODY_CAP - len(buf)]
        if len(buf) >= BODY_CAP:
            break
    return buf


class Stop(Exception):
    """Budget spent or provider busy: no more probes this run."""


def probe(host, pid, ua, resolve, sleep, session_factory=requests.Session, clock=time.time, project_id=0):
    """{'status', 'fingerprint'} for one GET of http://host/. Raises Stop when the budget or rate slot is not there."""
    ip, reason = safe_fetch.resolve_vetted(host, resolve=resolve)
    if reason:
        log.info('dangling: %s not contacted: %s', host, reason)
        return {'status': 'error', 'fingerprint': None}
    if not ratelimit.take_shared(PROVIDER, DAILY_BUDGET, project_id):
        raise Stop('budget')
    wait = ratelimit.reserve(PROVIDER, INTERVAL, clock())
    if wait is None or wait > MAX_WAIT:
        raise Stop('busy')
    if wait:
        sleep(wait)
    out = {'status': 'error', 'fingerprint': None}
    get = safe_fetch.pinned_get(host, ip, session_factory=session_factory)
    try:
        resp = get(f'http://{host}/', headers={'User-Agent': ua}, timeout=TIMEOUT, allow_redirects=False, stream=True)
        try:
            out['status'] = resp.status_code
            out['fingerprint'] = takeover.fingerprint(pid, resp.status_code, _read(resp))
        finally:
            resp.close()
    except SoftTimeLimitExceeded:
        raise
    except (requests.exceptions.RequestException, OSError, TimeoutError, ValueError):
        out['status'] = 'error'
    return out


def _candidates(project, root, now):
    """Owned hostnames under root worth looking at, oldest-checked first: those whose stored CNAME matches a provider
    (pure, no I/O) and those that still carry a finding or an error to settle, minus rows checked recently. The cap
    comes after this filter, so every candidate is reached over successive runs."""
    hosts = [a for a in Asset.objects.filter(project=project, kind='hostname', scope_tier__in=OWNED)
             .exclude(state='retired') if _root_of(a.value, [root.value])]
    rows = {r.asset_id: r for r in RiskCheck.objects.filter(asset__in=hosts, check_id=takeover.CHECK)}
    out = []
    for a in hosts:
        row = rows.get(a.id)
        if row and now - row.last_checked < (ERROR_RETRY if row.status == 'error' else REFRESH):
            continue
        if takeover.match(stored_cname(a)) or (row and row.status in ('fail', 'error')):
            out.append((row.last_checked if row else None, a.value, a, row))
    out.sort(key=lambda t: (t[0] is not None, t[0] or now, t[1]))
    return [(a, row) for _t, _v, a, row in out]


def check_host(asset, ua, resolve, sleep, counter, session_factory=requests.Session):
    """The Result for one host, or None when it has no takeover-prone CNAME. The stored CNAME only nominates the
    host: it is confirmed with a live CNAME query before anything is flagged."""
    stored = takeover.match(stored_cname(asset))
    target = live_cname(resolve, asset.value)
    if target == 'error':
        return Result(takeover.CHECK, 'error', {'reason': 'could not tell'}) if stored else None
    pid = takeover.match(target)
    if not pid:
        return None
    obs = {'provider': pid, 'target': target, 'nxdomain': False if stored_resolves(asset) else nxdomain(resolve, asset.value),
           'probe': None}
    if obs['nxdomain'] is False and takeover.PROVIDERS[pid][3]:
        if not scope.may_contact(asset.project, [asset.value])[0]:  # DNS above needs no guard; contact does
            obs['probe'] = {'status': 'error', 'fingerprint': None}
            return takeover.evaluate(obs)
        obs['probe'] = probe(asset.value, pid, ua, resolve, sleep, session_factory, project_id=asset.project_id)
        counter['requests'] += 1
    return takeover.evaluate(obs)


def discover(project, root, now=None, resolve=collect._resolve, sleep=time.sleep, session_factory=requests.Session,
             clock=time.monotonic):
    """dns.dangling_takeover for the hostnames under one owned root. Never raises into the stage for one host. At most
    MAX_HOSTS candidates and RUN_SECONDS per run; what is not reached keeps its old row and goes first next run."""
    now = now or timezone.now()
    counter = {'requests': 0, 'hosts': 0, 'flagged': 0}
    ua = ScanIdentity.for_domain(root).ua
    start = clock()
    try:
        for asset, row in _candidates(project, root, now)[:MAX_HOSTS]:
            if clock() - start > RUN_SECONDS:
                log.warning('dangling: time budget reached; the rest waits for the next run')
                break
            try:
                result = check_host(asset, ua, resolve, sleep, counter, session_factory)
            except (Stop, SoftTimeLimitExceeded):
                raise
            except Exception as e:  # noqa: BLE001 - one host never stops the rest; type only
                log.error('dangling check failed for %s: %s', asset.value, type(e).__name__)
                continue
            if result is None:
                if row and row.status in ('fail', 'error'):  # no provider CNAME any more: the finding ends (a pass closes the issue)
                    _write(asset, [Result(takeover.CHECK, 'pass', {})], now)
                continue
            _write(asset, [result], now)
            counter['hosts'] += 1
            counter['flagged'] += result.status == 'fail'
    except Stop as e:
        log.warning('dangling: stopped early (%s)', e)
    return counter
