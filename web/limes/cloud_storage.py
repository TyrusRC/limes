"""cloud.open_storage: for each owned root, test whether buckets named after it list anonymously.

At most MAX_NAMES names per root, one HTTPS GET per provider and name (S3, Azure Blob, GCS), through
safe_fetch.allowlisted_get: only the three providers' hostnames can be fetched, each vetted and pinned, no redirect is
followed. Bodies are read up to BODY_CAP and only searched for the listing marker and counted: object names and
contents are never kept. Every GET spends the shared daily budget (ratelimit.take_daily, which fails closed) and a
rate-limit slot. The check is provisional (0 points)."""
import logging
import time
from datetime import timedelta

import requests
from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.utils import timezone

from limes import safe_fetch
from limes.checks import cloud
from limes.checks.catalogue import CHECKS
from limes.checks.run import _write
from limes.identity import ScanIdentity
from limes.intel import ratelimit
from startScan.models import RiskCheck

log = logging.getLogger(__name__)

PROVIDER = 'cloud_storage'
# NOTE: a daily ceiling on probe GETs over all projects, plus a 0.25 s spacing between them. Upgrade path: a setting,
# or a per-project budget.
DAILY_BUDGET = 2000
INTERVAL = 0.25
MAX_WAIT = 5
BODY_CAP = 1024 * 1024
TIMEOUT = 5
ROOT_SECONDS = 120  # total wall clock for one root's sweep
REFRESH = timedelta(hours=20)  # a root already swept inside this window is left alone


class Stop(Exception):
    """Budget spent, provider busy or time up: end the sweep (the root's row says 'error', never 'pass')."""


def _read(resp):
    buf = b''
    for chunk in resp.iter_content(chunk_size=65536):
        buf += chunk[:BODY_CAP - len(buf)]
        if len(buf) >= BODY_CAP:
            break
    return buf


def probe(get, provider, name, target, ua, sleep, clock=time.time):
    """{'provider', 'name', 'status', 'objects'} for one GET. status: an int, None (no such host) or 'error'."""
    out = {'provider': provider, 'name': name, 'status': 'error', 'objects': None}
    if not ratelimit.take_daily(PROVIDER, DAILY_BUDGET):
        raise Stop('budget')
    wait = ratelimit.reserve(PROVIDER, INTERVAL, clock())
    if wait is None or wait > MAX_WAIT:
        raise Stop('busy')
    if wait:
        sleep(wait)
    try:
        resp = get(target, headers={'User-Agent': ua}, timeout=TIMEOUT, allow_redirects=False, stream=True)
        try:
            out['status'] = resp.status_code
            if resp.status_code == 200:
                out['objects'] = cloud.listing(provider, 200, _read(resp))
        finally:
            resp.close()
    except SoftTimeLimitExceeded:
        raise
    except requests.exceptions.ConnectionError:
        out['status'] = None  # the host does not exist or was refused: nothing there
    except (requests.exceptions.RequestException, OSError, TimeoutError, ValueError):
        out['status'] = 'error'
    return out


def sweep_root(root, now, get, ua, sleep=time.sleep):
    """Probe every provider for every candidate name of one root and write its cloud.open_storage row."""
    probes, complete = [], True
    deadline = time.monotonic() + ROOT_SECONDS
    try:
        for name in cloud.names(root.value):
            for provider in cloud.PROVIDERS:
                target = cloud.url(provider, name)
                if target is None:
                    continue
                if time.monotonic() > deadline:
                    raise Stop('time')
                probes.append(probe(get, provider, name, target, ua, sleep))
    except Stop as e:
        complete = False
        log.warning('cloud storage: sweep of a root stopped early (%s)', e)
    result = cloud.evaluate(probes, complete)
    _write(root, [result], now)
    return {'requests': len(probes), 'open': result.evidence.get('count', 0) if result.status == 'fail' else 0}


def _due(root, now):
    row = RiskCheck.objects.filter(asset=root, check_id=cloud.CHECK).first()
    return row is None or now - row.last_checked >= REFRESH or row.status == 'error'


def discover(project, root, now=None, make_get=None, sleep=time.sleep):
    """cloud.open_storage for one owned root. Off with LIMES_CLOUD_CHECKS=false. Never raises into the stage."""
    if not settings.CLOUD_CHECKS or root.kind != 'root_domain' or root.scope_tier != 'owned_root' \
            or root.state == 'retired':
        return {'requests': 0, 'open': 0, 'skipped': True}
    now = now or timezone.now()
    if not _due(root, now):
        return {'requests': 0, 'open': 0, 'skipped': True}
    get = (make_get or (lambda: safe_fetch.allowlisted_get(cloud.ALLOW_EXACT, cloud.ALLOW_SUFFIX)))()
    try:
        return sweep_root(root, now, get, ScanIdentity.for_domain(root).ua, sleep)
    except SoftTimeLimitExceeded:
        raise
    except Exception as e:  # noqa: BLE001 - type only
        log.error('cloud storage failed: %s', type(e).__name__)
        return {'requests': 0, 'open': 0, 'failed': True}
