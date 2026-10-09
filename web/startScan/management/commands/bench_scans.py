import time

from django.core.management.base import BaseCommand
from django.utils import timezone

from dashboard.models import Project
from limes.common_func import create_scan_object
from limes.definitions import LIVE_SCAN
from limes.tasks import initiate_scan
from scanEngine.models import EngineType
from startScan.models import ScanHistory
from targetApp.models import Domain

LAB_HOST = 'lab.limes.test'
ENGINE_YAML = """
port_scan: {'ports': ['80'], 'rate_limit': 50, 'enable_nmap': true}
http_crawl: {}
fetch_url: {'uses_tools': ['katana', 'gau'], 'remove_duplicate_endpoints': true}
"""
STATUS_NAMES = {-1: 'initiated', 0: 'failed', 1: 'running', 2: 'success', 3: 'aborted'}


class Command(BaseCommand):
    help = 'Start N concurrent scans of the lab target and report scans that never finish.'

    def add_arguments(self, parser):
        parser.add_argument('--scans', type=int, default=20)
        parser.add_argument('--budget-min', type=int, default=45)

    def handle(self, *args, **opts):
        now = timezone.now()
        project, _ = Project.objects.get_or_create(slug='bench', defaults={'name': 'bench', 'insert_date': now})
        domain, _ = Domain.objects.get_or_create(name=LAB_HOST, defaults={'project': project, 'insert_date': now})
        engine, _ = EngineType.objects.update_or_create(engine_name='bench-lab', defaults={'yaml_configuration': ENGINE_YAML})
        ids = []
        for _ in range(opts['scans']):
            scan_id = create_scan_object(host_id=domain.id, engine_id=engine.id)
            initiate_scan.apply_async(kwargs={
                'scan_history_id': scan_id, 'domain_id': domain.id, 'engine_id': engine.id,
                'scan_type': LIVE_SCAN, 'results_dir': '/usr/src/scan_results'})
            ids.append(scan_id)
        deadline = time.monotonic() + opts['budget_min'] * 60
        while time.monotonic() < deadline:
            open_count = ScanHistory.objects.filter(id__in=ids, scan_status__in=[-1, 1]).count()
            if open_count == 0:
                break
            time.sleep(30)
        counts = {}
        for status in ScanHistory.objects.filter(id__in=ids).values_list('scan_status', flat=True):
            counts[STATUS_NAMES.get(status, status)] = counts.get(STATUS_NAMES.get(status, status), 0) + 1
        stuck = counts.get('initiated', 0) + counts.get('running', 0)
        self.stdout.write(f'scans={len(ids)} {counts} stuck={stuck}')
