"""Continuous monitoring (A5b): cadence-driven rediscovery of owned roots and asset aging."""
import logging
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from limes.celery import app
from limes.common_func import create_scan_object
from limes.definitions import INITIATED_TASK, LIVE_SCAN, RUNNING_TASK, SCHEDULED_SCAN
from limes.tasks.control import initiate_scan
from scanEngine.models import EngineType
from startScan.models import Asset, ScanHistory
from targetApp.models import Domain

logger = logging.getLogger(__name__)

CADENCE_INTERVALS = {'crown_jewel': timedelta(hours=24), 'standard': timedelta(days=7),
                     'inactive': timedelta(days=30)}  # 'off' is never automatic
MAX_IN_FLIGHT = 2  # NOTE: global ceiling: automation waits while this many scans run; upgrade: capacity-aware budget
MAX_DISPATCH_PER_TICK = 1
MAX_ATTEMPTS_PER_TICK = 5
IN_PROGRESS = (INITIATED_TASK, RUNNING_TASK)


def start_asm_scan(asset, engine_id=None, initiated_by_id=None, scan_type=LIVE_SCAN):
    """Start the per-root ASM run (discovery, passive intel, screenshots). Returns (ok, message)."""
    if asset.kind != 'root_domain' or not asset.is_active_scan_allowed:
        return False, 'Per-asset rescan is not supported yet (owned root domains only in A2).'
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
    # Mirrors startScan.views.start_scan_ui, plus scan_mode='asm'.
    initiate_scan.apply_async(kwargs={
        'scan_history_id': scan_history_id,
        'domain_id': domain.id,
        'engine_id': engine.id,
        'scan_type': scan_type,
        'results_dir': '/usr/src/scan_results',
        'imported_subdomains': [],
        'out_of_scope_subdomains': [],
        'initiated_by_id': initiated_by_id,
        'scan_mode': 'asm',
    })
    return True, f'ASM scan started for {asset.value}'


def due_roots(now):
    """Owned roots whose cadence has elapsed and that have no scan in progress, most overdue first
    (never-scanned first). Due-ness counts from the last scan's start, whatever its outcome, so a
    failing root is retried once per interval, never every tick.
    NOTE: loads every candidate root each call; fine for hundreds. Upgrade: one annotated query."""
    due = []
    for asset in Asset.objects.filter(kind='root_domain', scope_tier='owned_root',
                                      cadence_tier__in=list(CADENCE_INTERVALS)).order_by('id'):
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


@app.task(name='dispatch_due_scans', bind=False)
def dispatch_due_scans():
    if not settings.CONTINUOUS_SCANS:
        return {'dispatched': 0, 'reason': 'disabled'}
    if ScanHistory.objects.filter(scan_status__in=IN_PROGRESS).count() >= MAX_IN_FLIGHT:
        return {'dispatched': 0, 'skipped': 0}
    dispatched = skipped = 0
    for asset in due_roots(timezone.now())[:MAX_ATTEMPTS_PER_TICK]:
        ok, message = start_asm_scan(asset, initiated_by_id=None, scan_type=SCHEDULED_SCAN)
        if ok:
            dispatched += 1
            if dispatched >= MAX_DISPATCH_PER_TICK:
                break
        else:
            logger.info(f'Continuous scan skipped for {asset.value}: {message}')
            skipped += 1
    return {'dispatched': dispatched, 'skipped': skipped}
