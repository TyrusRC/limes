from unittest import mock

from django.test import TestCase

from limes.db_ops import notifications_enabled
from scanEngine.models import Notification


class NotifyGateTest(TestCase):
    def test_disabled_without_settings(self):
        self.assertFalse(notifications_enabled())

    def test_enabled_when_status_notifs_on(self):
        Notification.objects.create(send_scan_status_notif=True)
        self.assertTrue(notifications_enabled())

    def test_task_notify_does_not_enqueue_when_disabled(self):
        from limes.tasks import port_scan
        with mock.patch('limes.tasks.send_task_notif.delay') as delay:
            port_scan.task_name = 'port_scan'
            port_scan.status = 1
            port_scan.result = port_scan.traceback = port_scan.output_path = None
            port_scan.scan_id = port_scan.engine_id = port_scan.subscan_id = None
            port_scan.notify(fields={'x': 'y'})
        delay.assert_not_called()
