"""Continuous monitoring (A5b): cadence-driven rediscovery of owned roots and asset aging."""
from limes.common_func import create_scan_object
from limes.definitions import LIVE_SCAN
from limes.tasks.control import initiate_scan
from scanEngine.models import EngineType
from startScan.models import ScanHistory
from targetApp.models import Domain


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
