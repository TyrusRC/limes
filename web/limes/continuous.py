"""Continuous monitoring (A5b): cadence-driven rediscovery of owned roots and asset aging."""
import logging
from contextlib import contextmanager
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django_redis import get_redis_connection
from redis.exceptions import LockError, RedisError

from limes.celery import app
from limes.celery_routing import TASK_PLAN
from limes.common_func import create_scan_object
from limes.definitions import INITIATED_TASK, LIVE_SCAN, RUNNING_TASK
from limes.tasks.control import initiate_scan
from scanEngine.models import EngineType
from startScan.asset_models import CADENCE_TIERS
from startScan.models import Asset, CertSighting, ScanHistory
from targetApp.models import Domain

logger = logging.getLogger(__name__)

CADENCE_INTERVALS = {'crown_jewel': timedelta(hours=24), 'standard': timedelta(days=7),
                     'inactive': timedelta(days=30)}  # 'off' is never automatic
MAX_IN_FLIGHT = 2  # NOTE: global ceiling: automation waits while this many scans run; upgrade: capacity-aware budget
MAX_DISPATCH_PER_TICK = 1
MAX_ATTEMPTS_PER_TICK = 5
IN_PROGRESS = (INITIATED_TASK, RUNNING_TASK)

CADENCE_KINDS = ('root_domain', 'hostname', 'ip', 'cidr', 'asn')


def set_cadence(asset, tier):
    """Set how often an owned asset is rediscovered or monitored. Explicit: it overrides the monitor's activity
    rule ('off' stops monitoring). Returns (ok, message); the REST view and the MCP tool both call this."""
    if asset.kind not in CADENCE_KINDS:
        return False, 'cadence applies to roots, hostnames, IPs, ranges and ASNs only'
    if asset.scope_tier not in ('owned_root', 'owned_host'):
        return False, 'cadence applies to owned assets only'
    if not isinstance(tier, str) or tier not in dict(CADENCE_TIERS):
        return False, 'unknown cadence tier'
    with transaction.atomic():
        row = Asset.objects.select_for_update().get(pk=asset.pk)
        row.cadence_tier = tier
        row.enrichment = {**(row.enrichment or {}), 'cadence_explicit': True}
        row.save(update_fields=['cadence_tier', 'enrichment'])
    from dashboard.stats import invalidate
    invalidate(asset.project_id)
    return True, f'cadence set to {tier}'


def project_scan_busy(project_id):
    """True while any scan of the project is queued or running (the cap on manual full scans)."""
    return ScanHistory.objects.filter(domain__project_id=project_id, scan_status__in=IN_PROGRESS).exists()


def start_asm_scan(asset, engine_id=None, initiated_by_id=None, mode='asm'):
    """Start the per-root run: 'asm' = discovery, passive intel, screenshots; 'full' = the scanner run (port scan,
    crawl, vigil DAST, mantis) of the old start-scan wizard, actively testing the real target. Returns (ok, message).
    A full run only starts while the project has no other scan in progress.
    Always LIVE_SCAN: initiate_scan then runs on the ScanHistory written here. SCHEDULED_SCAN would make
    it create a second one and orphan this one in INITIATED."""
    if mode not in ('asm', 'full'):
        return False, 'unknown scan mode'
    if asset.kind != 'root_domain' or not asset.is_active_scan_allowed:
        return False, 'Per-asset rescan is not supported yet (owned root domains only in A2).'
    if mode == 'full' and project_scan_busy(asset.project_id):
        return False, 'a scan is already in progress for this project; wait for it to finish'
    domain = Domain.objects.filter(project=asset.project, name=asset.value).first()
    if not domain:
        return False, 'no Domain record for this root; add it as a target first.'
    # No engine given: reuse the target's last engine, else the first built-in one.
    if engine_id in (None, ''):
        last = ScanHistory.objects.filter(domain=domain, scan_type__isnull=False).order_by('-start_scan_date').first()
        engine = last.scan_type if last else EngineType.objects.filter(default_engine=True).order_by('id').first()
    else:
        try:
            engine = EngineType.objects.filter(id=int(engine_id)).first()
        except (TypeError, ValueError, OverflowError):
            engine = None
    if not engine:
        return False, 'unknown scan engine; pick an engine or set a default one.'
    scan_history_id = create_scan_object(host_id=domain.id, engine_id=engine.id, initiated_by_id=initiated_by_id)
    initiate_scan.apply_async(kwargs={
        'scan_history_id': scan_history_id,
        'domain_id': domain.id,
        'engine_id': engine.id,
        'scan_type': LIVE_SCAN,
        'results_dir': '/usr/src/scan_results',
        'imported_subdomains': [],
        'out_of_scope_subdomains': [],
        'initiated_by_id': initiated_by_id,
        'scan_mode': mode,
    })
    return True, f"{'Full' if mode == 'full' else 'ASM'} scan started for {asset.value}"


def due_roots(now, project=None):
    """Owned roots whose cadence has elapsed and that have no scan in progress, most overdue first
    (never-scanned first), optionally limited to one project. Due-ness counts from the last scan's
    start, whatever its outcome, so a failing root is retried once per interval, never every tick.
    NOTE: loads every candidate root each call; fine for hundreds. Upgrade: one annotated query."""
    due = []
    roots = Asset.objects.filter(kind='root_domain', scope_tier='owned_root', cadence_tier__in=list(CADENCE_INTERVALS))
    if project is not None:
        roots = roots.filter(project=project)
    for asset in roots.order_by('id'):
        domain = Domain.objects.filter(project_id=asset.project_id, name=asset.value).first()
        if not domain:
            continue  # no scan target for this root: nothing to start
        scans = ScanHistory.objects.filter(domain=domain)
        if scans.filter(scan_status__in=IN_PROGRESS).exists():
            continue
        last = scans.order_by('-start_scan_date').values_list('start_scan_date', flat=True).first()
        if last is None or last <= now - CADENCE_INTERVALS[asset.cadence_tier]:
            due.append((last is not None, last, asset.id, asset))
    due.sort(key=lambda d: d[:3])
    return [d[3] for d in due]


@contextmanager
def tick_lock(name):
    """At most one running `name` tick across all workers. Redis (owner token + TTL), not a Postgres session
    advisory lock: behind pgbouncer (POOL_MODE=transaction) lock and unlock can reach different server connections,
    leaking the lock (later ticks starve) or re-entering it (two ticks run). Yields False when another tick holds it
    or Redis is unreachable (fail closed). Release is redis-py's compare-and-delete on the owner token, so a holder
    whose TTL ran out never removes the next holder's lock.
    NOTE: TTL = the task's hard time limit, so a hard-killed worker pauses this tick for at most that long. Upgrade
    path: a shorter TTL renewed with lock.extend() between units of work."""
    lock, got = None, False
    try:
        lock = get_redis_connection('default').lock(f'limes:tick:{name}', timeout=TASK_PLAN[name][1], blocking=False)
        got = bool(lock.acquire())
    except RedisError as e:
        logger.warning('tick lock %s unavailable (%s); skipping this tick', name, type(e).__name__)
    try:
        yield got
    finally:
        if got:
            try:
                lock.release()
            except (LockError, RedisError):
                logger.warning('tick lock %s expired or could not be released', name)


@app.task(name='dispatch_due_scans', bind=False)
def dispatch_due_scans():
    if not settings.CONTINUOUS_SCANS:
        return {'dispatched': 0, 'reason': 'disabled'}
    # Ticks queued while workers were down can run in parallel: only one may pick and start roots. Each started
    # scan's ScanHistory still commits on its own (autocommit) before the next check.
    with tick_lock('dispatch_due_scans') as got:
        if not got:
            return {'dispatched': 0, 'skipped': 0, 'reason': 'locked'}
        return _dispatch()


def _dispatch():
    if ScanHistory.objects.filter(scan_status__in=IN_PROGRESS).count() >= MAX_IN_FLIGHT:
        return {'dispatched': 0, 'skipped': 0}
    dispatched = skipped = 0
    for asset in due_roots(timezone.now())[:MAX_ATTEMPTS_PER_TICK]:
        ok, message = start_asm_scan(asset, initiated_by_id=None)
        if ok:
            dispatched += 1
            if dispatched >= MAX_DISPATCH_PER_TICK:
                break
        else:
            logger.info(f'Continuous scan skipped for {asset.value}: {message}')
            skipped += 1
    return {'dispatched': dispatched, 'skipped': skipped}


STALE_AFTER = timedelta(days=30)
RETIRE_AFTER = timedelta(days=90)
SIGHTING_KEEP = timedelta(days=400)


@app.task(name='age_assets', bind=False)
def age_assets():
    """missing -> stale after STALE_AFTER unseen; stale -> retired after RETIRE_AFTER.
    A sighting brings an asset back to active (Asset.mark_missing_or_seen)."""
    now = timezone.now()
    stale = Asset.objects.filter(state='missing', last_seen__lt=now - STALE_AFTER).update(state='stale')
    retired = Asset.objects.filter(state='stale', last_seen__lt=now - RETIRE_AFTER).update(state='retired')
    CertSighting.objects.filter(first_seen_at__lt=now - SIGHTING_KEEP).delete()
    return {'stale': stale, 'retired': retired}
