import threading

from django.db import connection
from django.test import TransactionTestCase
from django.utils import timezone

from limes.db_ops import append_celery_id
from scanEngine.models import EngineType
from startScan.models import ScanHistory
from targetApp.models import Domain


class AppendCeleryIdTest(TransactionTestCase):
    def test_concurrent_appends_all_land(self):
        domain = Domain.objects.create(name='a.test', insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='t', yaml_configuration='{}')
        scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=timezone.now())

        def worker(i):
            append_celery_id(ScanHistory, scan.pk, f'id-{i}')
            connection.close()

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        scan.refresh_from_db()
        self.assertEqual(sorted(scan.celery_ids), sorted(f'id-{i}' for i in range(20)))
