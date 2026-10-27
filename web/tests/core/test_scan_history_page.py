from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.test import TestCase
from django.utils import timezone
from rolepermissions.roles import assign_role

from dashboard.models import Project
from dashboard.views import on_user_logged_in
from scanEngine.models import EngineType
from startScan.models import ScanHistory
from targetApp.models import Domain


class ScanHistoryPageTest(TestCase):
    """The slim Scan History list that replaced the per-scan result pages."""

    def setUp(self):
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.admin = User.objects.create_user('adm', password='p')
        assign_role(self.admin, 'sys_admin')
        self.auditor = User.objects.create_user('aud', password='p')
        assign_role(self.auditor, 'auditor')
        p = Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())
        other = Project.objects.create(name='p2', slug='p2', insert_date=timezone.now())
        eng = EngineType.objects.create(engine_name='full', yaml_configuration='{}')
        mine = Domain.objects.create(project=p, name='x.com', insert_date=timezone.now())
        theirs = Domain.objects.create(project=other, name='secret.org', insert_date=timezone.now())
        now = timezone.now()
        self.running = ScanHistory.objects.create(domain=mine, scan_type=eng, scan_status=1, start_scan_date=now)
        ScanHistory.objects.create(domain=mine, scan_type=eng, scan_status=0, start_scan_date=now,
                                   error_message='<script>alert(1)</script>')
        ScanHistory.objects.create(domain=theirs, scan_type=eng, scan_status=2, start_scan_date=now)

    def get(self, user):
        self.client.force_login(user)
        self.client.get('/scan/p1/history/scan')  # warm-up (lazy prefs creation)
        return self.client.get('/scan/p1/history/scan')

    def test_lists_only_this_projects_scans_and_escapes_errors(self):
        html = self.get(self.admin).content.decode()
        self.assertIn('x.com', html)
        self.assertNotIn('secret.org', html)
        self.assertNotIn('<script>alert(1)</script>', html)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', html)

    def test_stop_button_only_for_running_scans_and_users_who_may_stop(self):
        self.assertEqual(self.get(self.admin).content.decode().count('class="btn btn-xs btn-soft-danger scan_stop"'), 1)
        self.assertNotIn('scan_stop"', self.get(self.auditor).content.decode().replace('.scan_stop', ''))
