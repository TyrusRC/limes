from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from limes.definitions import FAILED_TASK, INITIATED_TASK, RUNNING_TASK
from limes.reaper import STUCK_AFTER, reap_stuck_scans
from scanEngine.models import EngineType
from startScan.models import ScanActivity, ScanHistory
from targetApp.models import Domain


class ReaperTest(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name='r.test', insert_date=timezone.now())
        self.engine = EngineType.objects.create(engine_name='t', yaml_configuration='{}')

    def scan(self, status, started_ago, activity_ago=None):
        now = timezone.now()
        scan = ScanHistory.objects.create(domain=self.domain, scan_type=self.engine,
                                          start_scan_date=now - started_ago, scan_status=status)
        if activity_ago is not None:
            ScanActivity.objects.create(scan_of=scan, title='t', name='t', status=RUNNING_TASK,
                                        time=now - activity_ago)
        return scan

    @mock.patch('limes.reaper.report.delay')
    def test_reaps_silent_running_scan(self, delay):
        old = STUCK_AFTER + timedelta(minutes=5)
        stuck = self.scan(RUNNING_TASK, old, activity_ago=old)
        self.assertEqual(reap_stuck_scans(), [stuck.pk])
        self.assertEqual(ScanActivity.objects.get(scan_of=stuck).status, FAILED_TASK)
        delay.assert_called_once()
        self.assertEqual(delay.call_args.kwargs['ctx']['scan_history_id'], stuck.pk)

    @mock.patch('limes.reaper.report.delay')
    def test_keeps_scan_with_recent_activity(self, delay):
        self.scan(RUNNING_TASK, STUCK_AFTER * 3, activity_ago=timedelta(minutes=1))
        self.assertEqual(reap_stuck_scans(), [])
        delay.assert_not_called()

    @mock.patch('limes.reaper.report.delay')
    def test_reaps_scan_stuck_in_initiated(self, delay):
        stuck = self.scan(INITIATED_TASK, STUCK_AFTER + timedelta(minutes=5))
        self.assertEqual(reap_stuck_scans(), [stuck.pk])

    @mock.patch('limes.reaper.report.delay')
    def test_ignores_finished_scans(self, delay):
        self.scan(2, STUCK_AFTER * 2, activity_ago=STUCK_AFTER * 2)
        self.assertEqual(reap_stuck_scans(), [])
