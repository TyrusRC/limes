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
            port_scan.scan_id = port_scan.engine_id = None
            port_scan.notify(fields={'x': 'y'})
        delay.assert_not_called()


class InAppDescriptionTest(TestCase):
    def test_description_uses_plain_newlines_not_markup(self):
        # The panel renders this as text, so separators must be newlines, never <br>.
        from types import SimpleNamespace as NS
        from limes.tasks import notifications
        scan = NS(id=7, domain=NS(name='x.test', project=NS(slug='acme')))
        with mock.patch.object(notifications, 'create_inappnotification') as create:
            notifications.generate_inapp_notification(scan, 'SUCCESS', NS(engine_name='full'), {'Duration': '5s'})
        self.assertEqual(create.call_args.kwargs['description'],
                         'Scan was successful for x.test\nEngine: full\nCompleted in 5s')


class ScanLinkTest(TestCase):
    def test_scan_url_is_a_page_that_exists(self):
        from types import SimpleNamespace as NS
        from django.urls import resolve
        from limes.common_func import get_scan_url
        url = get_scan_url(NS(id=7, domain=NS(project=NS(slug='acme'))))
        path = url.split('/', 3)[3]
        self.assertEqual(resolve('/' + path).url_name, 'scan_history')
        self.assertIsNone(get_scan_url(None))

    def test_scheme_follows_the_setting_and_defaults_to_plain_http(self):
        from types import SimpleNamespace as NS
        from limes import common_func
        scan = NS(id=7, domain=NS(project=NS(slug='acme')))
        with mock.patch.object(common_func, 'DOMAIN_NAME', 'limes.test'):
            with mock.patch.object(common_func, 'LIMES_PUBLIC_SCHEME', 'http'):
                self.assertEqual(common_func.get_scan_url(scan), 'http://limes.test/scan/acme/history/scan')
            with mock.patch.object(common_func, 'LIMES_PUBLIC_SCHEME', 'https'):
                self.assertEqual(common_func.get_scan_url(scan), 'https://limes.test/scan/acme/history/scan')
        from django.conf import settings
        self.assertEqual(settings.LIMES_PUBLIC_SCHEME, 'http')

    def test_a_bad_scheme_is_refused_at_startup(self):
        import subprocess, sys, os
        env = {**os.environ, 'LIMES_PUBLIC_SCHEME': 'ftp', 'DJANGO_SETTINGS_MODULE': 'limes.settings'}
        res = subprocess.run([sys.executable, '-c', 'import django; django.setup()'], env=env,
                             capture_output=True, text=True, cwd=os.path.join(os.path.dirname(__file__), '..', '..'))
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('LIMES_PUBLIC_SCHEME', res.stderr)
