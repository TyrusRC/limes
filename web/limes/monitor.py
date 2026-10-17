"""Light monitor (monitor_assets beat task): owned hostnames, IPs and roots that no scan covers are resolved,
refreshed from InternetDB, risk-checked and aged on UpGuard's activity rule (active daily, inactive monthly).
Every contact goes through limes.safe_fetch: the host is resolved once, every answer vetted, the vetted IP pinned."""
import logging
import time
from datetime import timedelta

from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.db import connection
from django.db.models import Exists, OuterRef, Q
from django.utils import timezone

from dashboard.models import Project
from dashboard.stats import invalidate
from limes import owned_ranges, scope
from limes.alerts import events
from limes.alerts.deliver import deliver_immediate
from limes.alerts.issues import sync_issues
from limes.celery import app
from limes.checks import collect, run
from limes.continuous import CADENCE_INTERVALS, IN_PROGRESS
from limes.intel import http, internetdb, ratelimit
from limes.scan_target import has_scan_target
from limes.scoring import _root_of
from limes.tasks import inventory
from limes.tasks.intel import _fresh, _store
from startScan.models import Asset, ScanHistory
from targetApp.models import Domain

logger = logging.getLogger(__name__)

ACTIVE_INTERVAL = timedelta(hours=24)
INACTIVE_INTERVAL = timedelta(days=30)
# NOTE: at most MAX_PER_TICK assets per 60 s tick (about 28,800 a day), oldest due first. Upgrade path: a larger
# per-tick share or more ticks once inventories outgrow it.
MAX_PER_TICK = 20
# NOTE: the budget is checked between assets, so one slow host can overrun it: its worst case is a few 5 s timeouts
# (plain http, up to 4 https hops, 3 TLS handshakes). The advisory lock keeps ticks from overlapping meanwhile, and
# the beat entry expires at 55 s. Upgrade path: a per-host deadline passed down to the collectors.
TICK_BUDGET = timedelta(seconds=50)
MONITOR_LOCK = 0x4C494D47  # Postgres advisory lock key: one monitor_assets tick at a time
OWNED = ('owned_root', 'owned_host')
KINDS = ('hostname', 'ip', 'root_domain')


def effective_interval(asset):
    """How often this asset is checked: None when off; a retired asset monthly (a sighting revives it); an explicit
    cadence as set; otherwise daily while active (open port, live HTTP or MX), monthly while not."""
    if asset.cadence_tier not in CADENCE_INTERVALS:
        return None
    enrichment = asset.enrichment or {}
    if asset.state == 'retired':
        return INACTIVE_INTERVAL
    if enrichment.get('cadence_explicit'):
        return CADENCE_INTERVALS[asset.cadence_tier]
    return ACTIVE_INTERVAL if (enrichment.get('monitor') or {}).get('active') else INACTIVE_INTERVAL


def monitored(project=None):
    """Owned hostnames, IPs and roots, cadence not off. Roots with a scan target are left to the root scans
    (the same test as scan_target.has_scan_target, as one subquery)."""
    target = Domain.objects.filter(project_id=OuterRef('project_id'), name=OuterRef('value'))
    rows = Asset.objects.filter(scope_tier__in=OWNED, kind__in=KINDS).exclude(cadence_tier='off')
    if project is not None:
        rows = rows.filter(project=project)
    return rows.annotate(has_target=Exists(target)).exclude(kind='root_domain', has_target=True)


def due_assets(now, limit=MAX_PER_TICK):
    """Monitored assets whose interval has elapsed, never-checked first, then oldest. Hostnames under a root whose
    scan is in progress wait for it (root scans stamp last_resolved_at on the hosts they cover).
    NOTE: loads every prefiltered row to apply effective_interval in Python. Upgrade path: store next_due_at."""
    rows = monitored().filter(Q(last_resolved_at__isnull=True) | Q(last_resolved_at__lt=now - ACTIVE_INTERVAL))
    scanning = {}
    for pid, name in ScanHistory.objects.filter(scan_status__in=IN_PROGRESS).values_list('domain__project_id', 'domain__name'):
        scanning.setdefault(pid, []).append(name)
    due = []
    for a in rows.order_by('id'):
        interval = effective_interval(a)
        if interval is None or (a.last_resolved_at is not None and a.last_resolved_at > now - interval):
            continue
        if a.kind == 'hostname' and _root_of(a.value, scanning.get(a.project_id, [])):
            continue
        due.append((a.last_resolved_at is not None, a.last_resolved_at, a.id, a))
    due.sort(key=lambda d: d[:3])
    return [d[3] for d in due[:limit]]


def _ours(asset):
    """The asset as stored now, or None unless it is still ours to check (tier and cadence re-read)."""
    a = Asset.objects.filter(pk=asset.pk).first()
    if a is None or a.scope_tier not in OWNED or a.kind not in KINDS or a.cadence_tier not in CADENCE_INTERVALS:
        return None
    if a.kind == 'root_domain' and has_scan_target(a):
        return None  # gained a scan target since it was picked: the root scans cover it
    return a


def _once(resolve):
    """resolve with each (name, rdtype) asked once per check: what is recorded is exactly what is vetted."""
    seen = {}

    def lookup(name, rdtype):
        key = (name, rdtype)
        if key not in seen:
            try:
                seen[key] = (True, list(resolve(name, rdtype)))
            except Exception as e:
                seen[key] = (False, e)
        ok, value = seen[key]
        if ok:
            return list(value)
        raise value
    return lookup


def _names(a, resolve):
    """Resolve a hostname or root; record the answer. (status, reason, new owned ip assets)."""
    name = a.value.rstrip('.').lower()
    v4, v6 = collect._lookup(resolve, name, 'A'), collect._lookup(resolve, name, 'AAAA')
    if 'error' in (v4, v6):
        return 'unresolved', f'DNS lookup failed for {name}', []  # no evidence either way: lifecycle unchanged
    if not v4 and not v6:
        a.mark_missing_or_seen(False)
        return 'unresolved', f'{name} does not resolve', []
    cname = collect._lookup(resolve, name, 'CNAME')
    addrs = list(v4) + list(v6)
    before = set(Asset.objects.filter(project_id=a.project_id, kind='ip', value__in=addrs).values_list('value', flat=True))
    inventory.record_resolution(a, {'a': v4, 'aaaa': v6, 'cname': [c.rstrip('.') for c in cname] if cname != 'error' else []})
    a.mark_missing_or_seen(True)
    new = list(Asset.objects.filter(project_id=a.project_id, kind='ip', value__in=set(addrs) - before, scope_tier__in=OWNED))
    return 'ok', None, new


def _internetdb(ip, get, now):
    """(data, fetched): the fresh InternetDB record, {} when it has none, None when unknown (provider failed or the
    daily budget is spent: take_daily fails closed)."""
    if _fresh(ip, 'internetdb', now):
        return (ip.enrichment or {}).get('internetdb') or {}, False
    if not ratelimit.take_daily('internetdb', settings.INTERNETDB_DAILY_BUDGET):
        return None, False
    status, body = get(internetdb.build_url(ip.value), provider='internetdb')
    if status == 404:
        data = None
    elif status == 200:
        data = internetdb.parse(body)
    else:
        return None, False
    _store(ip, 'internetdb', data or {'no_data': True}, now)
    return data or {}, True


def check_asset(asset, now=None, resolve=collect._resolve, get=http.get_json, observers=None):
    """One light check of one monitored asset. Re-reads the row first: stopped, rejected or covered assets are
    skipped untouched. Returns the stored enrichment['monitor'] plus the project id, or {'status': 'skipped'}."""
    now = now or timezone.now()
    a = _ours(asset)
    if a is None:
        return {'status': 'skipped'}
    resolve = _once(resolve)
    status, reason, new = 'ok', None, []
    if a.kind != 'ip':
        status, reason, new = _names(a, resolve)
    ips = [a] if a.kind == 'ip' else list(Asset.objects.filter(
        project_id=a.project_id, kind='ip', scope_tier__in=OWNED,
        value__in=list(a.ip_addresses.values_list('address', flat=True))))
    found_hosts = []
    for ip in ips:
        if scope.is_reserved_ip(ip.value):
            continue
        data, fetched = _internetdb(ip, get, now)
        if fetched and data:
            found_hosts += owned_ranges.place_names(a.project, data.get('hostnames', []), ip.value, f'internetdb:{ip.value}')
        if a.kind == 'ip':
            names = owned_ranges.resolve_ptr(ip.value, resolve) if ratelimit.take_daily('ptr', settings.PTR_DAILY_BUDGET) else None
            found_hosts += owned_ranges.place_names(a.project, names or [], ip.value, f'ptr:{ip.value}')
            if bool(data and (data.get('ports') or data.get('hostnames'))) or bool(names):
                a.mark_missing_or_seen(True)
            elif data is not None and names is not None:
                a.mark_missing_or_seen(False)
    open_ports = {ip.value: collect.ports_for_ip(ip, now)[0] for ip in ips}  # after the refresh above
    ports = {p for found in open_ports.values() for p in found}
    mx = False
    if a.kind != 'ip':
        hosts = collect._mx_hosts(collect._lookup(resolve, a.value.rstrip('.').lower(), 'MX'))
        mx = hosts != 'error' and bool(hosts)
    result = {'http_live': False}
    if status == 'ok':
        result = run.run_asset_checks(a, now=now, observers=observers, resolve=resolve)
        if result['refused']:
            status, reason = 'refused', result['refused']
    for ip in new:
        events.record_asset_new(a.project, ip, ports=open_ports.get(ip.value, ()))
    for host in found_hosts:
        events.record_asset_new(a.project, host)
    monitor = {'checked_at': now.isoformat(), 'active': bool(ports) or result['http_live'] or mx,
               'status': status, 'reason': reason}
    a.refresh_from_db(fields=['enrichment'])  # _store may have written this very row (an ip)
    a.enrichment = {**(a.enrichment or {}), 'monitor': monitor}
    a.last_resolved_at = now  # the "Last checked" stamp, for every kind
    a.save(update_fields=['enrichment', 'last_resolved_at'])
    return {**monitor, 'project_id': a.project_id}


def _lock():
    with connection.cursor() as c:
        c.execute('SELECT pg_try_advisory_lock(%s)', [MONITOR_LOCK])
        return c.fetchone()[0]


def _unlock():
    with connection.cursor() as c:
        c.execute('SELECT pg_advisory_unlock(%s)', [MONITOR_LOCK])


@app.task(name='monitor_assets', bind=False)
def monitor_assets():
    """Beat tick: check the due assets within TICK_BUDGET, then sync issues and send alerts per touched project."""
    if not settings.CONTINUOUS_SCANS:
        return {'checked': 0, 'reason': 'disabled'}
    if not _lock():
        return {'checked': 0, 'reason': 'locked'}
    try:
        return _tick()
    finally:
        _unlock()


def _tick():
    now = timezone.now()
    deadline = time.monotonic() + TICK_BUDGET.total_seconds()
    checked, touched = 0, set()
    for asset in due_assets(now):
        if time.monotonic() > deadline:
            break
        try:
            out = check_asset(asset)
        except SoftTimeLimitExceeded:
            raise
        except Exception:
            logger.exception('monitor check failed for asset %s', asset.pk)
            continue
        if out.get('status') != 'skipped':
            checked += 1
            touched.add(asset.project_id)
    for pid in sorted(touched):
        project = Project.objects.get(pk=pid)
        for step in (sync_issues, deliver_immediate):
            try:
                step(project)
            except SoftTimeLimitExceeded:
                raise
            except Exception:
                logger.exception('monitor %s failed for project %s', step.__name__, pid)
        invalidate(pid)
    return {'checked': checked}
