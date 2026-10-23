"""Light monitor (monitor_assets beat task): owned hostnames, IPs and roots that no scan covers are resolved,
refreshed from InternetDB, risk-checked and aged on UpGuard's activity rule (active daily, inactive monthly).
Every contact goes through limes.safe_fetch: the host is resolved once, every answer vetted, the vetted IP pinned."""
import logging
import time
from datetime import timedelta

from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.db import transaction
from django.db.models import Exists, OuterRef, Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from dashboard.models import Project
from dashboard.stats import invalidate
from limes import owned_ranges, scope
from limes.alerts import events
from limes.alerts.deliver import deliver_immediate
from limes.alerts.issues import sync_issues
from limes.celery import app
from limes.checks import collect, run
from limes.continuous import CADENCE_INTERVALS, IN_PROGRESS, tick_lock
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
# NOTE: the budget is checked between assets, so a tick ends at most one asset past it. One asset's worst case:
# host contact capped by safe_fetch.HOST_DEADLINE (30 s, plus at most one 5 s step begun just before it), up to 8
# DNS queries at 5 s each (A, AAAA, CNAME, MX; a root's TXT, _dmarc TXT, DS, CAA), a PTR for an ip, and up to ~93 s
# per owned IP whose InternetDB record is stale (intel.http: 30 s x 3 attempts + 3 s back-off). The outer ceiling
# is the IO queue's 15-minute hard limit (13-minute soft); the attempt is stamped before any contact, so a killed
# check rotates to the back as 'timeout'. The tick lock (continuous.tick_lock) keeps ticks from overlapping and the beat entry
# expires at 55 s. Upgrade path: one deadline for the whole asset check, DNS and InternetDB included.
TICK_BUDGET = timedelta(seconds=50)
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


# Assets-page labels for the raw source names in Asset.sources.
FOUND_BY = {'manual': 'manual', 'discovery': 'scan', 'probe': 'scan', 'dns': 'scan', 'crtsh': 'CT',
            'ct': 'CT', 'certspotter_api': 'CT',
            'internetdb': 'InternetDB', 'cidr': 'CIDR', 'asn': 'ASN', 'attribution': 'attribution'}
ENUMERATION_OFF = 'Enumeration off (operator setting)'


def found_by(asset):
    """Unique labels for the asset's sources, in source order. Unknown sources read 'other'; none read 'manual' for
    an asset a user added, else 'target'."""
    labels = []
    for s in asset.sources or []:
        label = FOUND_BY.get(s.get('source') if isinstance(s, dict) else None, 'other')
        if label not in labels:
            labels.append(label)
    return labels or ['manual' if asset.added_by_id else 'target']


def _interval_label(delta):
    hours = int(delta.total_seconds() // 3600)
    return f'{hours}h' if hours < 48 else f'{hours // 24}d'


def monitor_state(asset):
    """What the Assets page shows about tracking, from stored fields only (no queries when the list view has
    annotated has_target). interval is None when off or not monitored; next_due = last check + interval."""
    out = {'interval': None, 'next_due': None, 'last_checked': None, 'status': None, 'reason': None}
    enrichment = asset.enrichment or {}
    last = asset.last_resolved_at
    if asset.scope_tier not in OWNED:
        return out
    if asset.kind in ('cidr', 'asn'):
        info = enrichment.get('asn' if asset.kind == 'asn' else 'enum') or {}
        out['status'], out['reason'] = info.get('status'), info.get('reason')
        if asset.kind == 'cidr' and out['status'] != 'refused' and not settings.RANGE_ENUMERATION:
            out['status'], out['reason'] = 'enumeration_off', ENUMERATION_OFF
        stamp = (info.get('refreshed_at') or info.get('checked_at')) if asset.kind == 'asn' else info.get('last_pass_at')
        last = last or (parse_datetime(stamp) if isinstance(stamp, str) else None)
        interval = CADENCE_INTERVALS.get(asset.cadence_tier)
    elif asset.kind == 'ip' and asset.parent_id is not None and range_owns(asset.parent):
        out['status'] = 'range_sweep'  # owned_ranges refreshes it, the light monitor does not (see monitored())
        interval = None
    elif asset.kind in KINDS:
        has_target = getattr(asset, 'has_target', None)
        if asset.kind == 'root_domain' and asset.scope_tier == 'owned_root' and (
                has_scan_target(asset) if has_target is None else has_target):
            interval = CADENCE_INTERVALS.get(asset.cadence_tier)  # the root scans' cadence
        else:
            interval = effective_interval(asset)
            mon = enrichment.get('monitor') or {}
            out['status'], out['reason'] = mon.get('status'), mon.get('reason')
    else:
        return out
    out['last_checked'] = last.isoformat() if last else None
    if interval is not None:
        out['interval'] = _interval_label(interval)
        out['next_due'] = (last + interval).isoformat() if last else None
    return out


def range_owns(rng):
    """True when a range is responsible for the IPs under it: it is being swept (enumeration on, owned, not retired,
    not refused, its ASN too), or the user stopped it, so its IPs stop with it. A refused range, or one whose sweep
    the operator switched off, hands its IPs back to the light monitor."""
    if rng is None or rng.kind != 'cidr':
        return False
    chain = [rng] + ([rng.parent] if rng.parent_id is not None else [])
    if any(r.cadence_tier == 'off' for r in chain):
        return True
    return (settings.RANGE_ENUMERATION and all(r.scope_tier in OWNED and r.state != 'retired' for r in chain)
            and ((rng.enrichment or {}).get('enum') or {}).get('status') != 'refused')


def monitored(project=None):
    """Owned hostnames, IPs and roots, cadence not off. Owned roots with a scan target are left to the continuous
    root scans (the same test as scan_target.has_scan_target, as one subquery); an owned_host root is never scanned
    continuously, so the monitor keeps it even when it has a Domain. IPs under a range that owns them (range_owns)
    are left to owned_ranges, which owns their refresh and their InternetDB/PTR budget.
    NOTE: loads every cidr row to apply range_owns in Python. Upgrade path: store the sweep state in a column."""
    target = Domain.objects.filter(project_id=OuterRef('project_id'), name=OuterRef('value'))
    rows = Asset.objects.filter(scope_tier__in=OWNED, kind__in=KINDS).exclude(cadence_tier='off')
    ranges = Asset.objects.filter(kind='cidr').select_related('parent')
    if project is not None:
        rows, ranges = rows.filter(project=project), ranges.filter(project=project)
    rows = rows.exclude(kind='ip', parent_id__in=[r.id for r in ranges if range_owns(r)])
    return rows.annotate(has_target=Exists(target)).exclude(kind='root_domain', scope_tier='owned_root', has_target=True)


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
    if a.kind == 'root_domain' and a.scope_tier == 'owned_root' and has_scan_target(a):
        return None  # gained a scan target since it was picked: the continuous root scans cover it
    if a.kind == 'ip' and a.parent_id is not None and range_owns(a.parent):
        return None  # a range sweep took it over since it was picked
    return a


def _mark_attempt(a, now):
    """Stamp the attempt before any contact, committed on its own: a check that is killed mid-way (soft time limit,
    worker loss) still rotates to the back and reads 'timeout', instead of coming first again every tick."""
    with transaction.atomic():
        row = Asset.objects.select_for_update().get(pk=a.pk)
        prev = (row.enrichment or {}).get('monitor') or {}
        row.enrichment = {**(row.enrichment or {}),
                          'monitor': {**prev, 'status': 'timeout', 'attempted_at': now.isoformat()}}
        row.last_resolved_at = now
        row.save(update_fields=['enrichment', 'last_resolved_at'])
    a.enrichment, a.last_resolved_at = row.enrichment, now


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


def _names(a, resolve, now):
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
    Asset.objects.filter(pk=a.pk).update(last_resolved_at=now)  # record_resolution stamps the wall clock
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
    baseline = a.last_resolved_at is None  # the first check records silently, like a range's first sweep
    _mark_attempt(a, now)
    status, reason, new = 'ok', None, []
    if a.kind != 'ip':
        status, reason, new = _names(a, resolve, now)
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
    # an unresolved or refused name still gets its no-answer rows (no contact), and a root its DNS-only email/dns
    result = run.run_asset_checks(a, now=now, observers=observers, resolve=resolve)
    if result['refused'] and status == 'ok':
        status, reason = 'refused', result['refused']
    if result['timeout']:
        status, reason = 'timeout', 'the host did not finish answering within the check deadline'
    if not baseline:
        for ip in new:
            events.record_asset_new(a.project, ip, ports=open_ports.get(ip.value, ()))
        for host in found_hosts:
            events.record_asset_new(a.project, host)
    monitor = {'checked_at': now.isoformat(), 'active': bool(ports) or result['http_live'] or mx,
               'status': status, 'reason': reason, 'attempted_at': now.isoformat(),
               'dns_only': a.kind == 'root_domain' and status != 'ok' and result['checked'] > 0}
    with transaction.atomic():  # locked like SetAssetCadence, so a cadence_explicit set meanwhile is kept
        row = Asset.objects.select_for_update().get(pk=a.pk)  # _store may also have written this very row (an ip)
        row.enrichment = {**(row.enrichment or {}), 'monitor': monitor}
        row.last_resolved_at = now  # the "Last checked" stamp, for every kind
        row.save(update_fields=['enrichment', 'last_resolved_at'])
    return {**monitor, 'project_id': a.project_id}


@app.task(name='monitor_assets', bind=False)
def monitor_assets():
    """Beat tick: check the due assets within TICK_BUDGET, then sync issues and send alerts per touched project."""
    if not settings.CONTINUOUS_SCANS:
        return {'checked': 0, 'reason': 'disabled'}
    with tick_lock('monitor_assets') as got:
        return _tick() if got else {'checked': 0, 'reason': 'locked'}


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
