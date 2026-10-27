from datetime import timedelta

from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.test import TestCase
from django.utils import timezone
from rolepermissions.roles import assign_role

from dashboard.models import Project
from dashboard.views import on_user_logged_in
from startScan.models import Asset, IssueNote, IssueWaiver, RiskCheck, TrackedIssue

HOSTILE = '<img src=x onerror=alert(1)>'


class IssueDetailPageTest(TestCase):
    def setUp(self):
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.admin = User.objects.create_user('adm', password='p')
        assign_role(self.admin, 'sys_admin')
        self.auditor = User.objects.create_user('aud', password='p')
        assign_role(self.auditor, 'auditor')
        self.client.force_login(self.admin)
        now = timezone.now()
        self.p = Project.objects.create(name='p1', slug='p1', insert_date=now)
        self.q = Project.objects.create(name='p2', slug='p2', insert_date=now)
        self.a = Asset.objects.create(project=self.p, kind='hostname', value='a.x.com', scope_tier='owned_host')
        self.b = Asset.objects.create(project=self.p, kind='hostname', value='b.x.com', scope_tier='owned_host')
        self.o = Asset.objects.create(project=self.q, kind='hostname', value='o.y.com', scope_tier='owned_host')
        self.i1 = TrackedIssue.objects.create(project=self.p, asset=self.a, key='web.hsts_missing', source='check',
                                              severity=2, first_seen=now - timedelta(days=9))
        self.i2 = TrackedIssue.objects.create(project=self.p, asset=self.b, key='web.hsts_missing', source='check',
                                              severity=2, first_seen=now - timedelta(days=3))
        self.other = TrackedIssue.objects.create(project=self.q, asset=self.o, key='web.hsts_missing', source='check',
                                                 severity=2)
        self.client.get('/scan/p1/issues')  # warm-up (lazy prefs creation)

    def get(self, issue, slug='p1'):
        return self.client.get(f'/scan/{slug}/issues/{issue.id}/')

    def test_sections_and_catalogue_text(self):
        r = self.get(self.i1)
        self.assertEqual(r.status_code, 200)
        html = r.content.decode()
        for needle in ('What was detected', 'Why it matters', 'Recommended action', 'Affected assets',
                       'Strict-Transport-Security', 'Medium', 'Website', 'a.x.com', 'b.x.com', 'Score impact'):
            self.assertIn(needle, html)
        self.assertNotIn('o.y.com', html)  # the other project's asset with the same key stays out

    def test_affected_assets_link_to_their_own_detail(self):
        self.assertIn(f'/scan/p1/issues/{self.i2.id}/', self.get(self.i1).content.decode())

    def test_cross_project_id_is_404(self):
        self.assertEqual(self.get(self.other, slug='p1').status_code, 404)
        self.assertEqual(self.get(self.i1, slug='p2').status_code, 404)
        self.assertEqual(self.client.get('/scan/nope/issues/1/').status_code, 404)

    def test_unknown_finding_falls_back_gracefully(self):
        f = TrackedIssue.objects.create(project=self.p, asset=self.a, key='some-template', source='finding', severity=3)
        r = self.get(f)
        self.assertEqual(r.status_code, 200)
        html = r.content.decode()
        self.assertIn('some-template', html)
        self.assertIn('Recommended action', html)

    def test_finding_text_comes_from_the_scanner_record(self):
        from startScan.models import Vulnerability
        Vulnerability.objects.create(asset=self.a, name='Exposed panel', template_id='panel-1', severity=3, open_status=True,
                                     description='Admin panel reachable', impact='Takeover', remediation='Restrict the panel')
        f = TrackedIssue.objects.create(project=self.p, asset=self.a, key='panel-1', source='finding', severity=3)
        html = self.get(f).content.decode()
        for needle in ('Admin panel reachable', 'Takeover', 'Restrict the panel'):
            self.assertIn(needle, html)

    def test_expected_and_actual_from_evidence(self):
        RiskCheck.objects.create(asset=self.a, check_id='web.hsts_missing', status='fail', severity=2,
                                 evidence={'expected': 'max-age>=31536000', 'actual': 'max-age=0'})
        html = self.get(self.i1).content.decode()
        self.assertIn('Expected', html)
        self.assertIn('max-age&gt;=31536000', html)
        self.assertIn('Actual', html)
        self.assertIn('max-age=0', html)

    def test_hostile_text_is_escaped(self):
        f = TrackedIssue.objects.create(project=self.p, asset=self.a, key=HOSTILE, source='finding', severity=4)
        RiskCheck.objects.create(asset=self.a, check_id='web.csp_missing', status='fail', severity=1, evidence={'actual': HOSTILE})
        csp = TrackedIssue.objects.create(project=self.p, asset=self.a, key='web.csp_missing', source='check', severity=1)
        IssueNote.objects.create(issue=f, author=self.admin, text=HOSTILE)
        IssueWaiver.objects.create(issue=f, kind='accepted_risk', reason=HOSTILE, created_by=self.admin,
                                   expires_at=timezone.now() + timedelta(days=5))
        for issue in (f, csp):
            html = self.get(issue).content.decode()
            self.assertNotIn(HOSTILE, html)
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;', self.get(f).content.decode())

    def test_waiver_history_notes_and_status(self):
        IssueNote.objects.create(issue=self.i1, author=self.admin, text='ticket opened')
        now = timezone.now()
        IssueWaiver.objects.create(issue=self.i1, kind='false_positive', reason='old one', created_by=self.admin,
                                   created_at=now - timedelta(days=20), revoked_at=now - timedelta(days=10), revoked_by=self.admin)
        IssueWaiver.objects.create(issue=self.i1, kind='accepted_risk', reason='vendor fix due', created_by=self.admin,
                                   expires_at=now + timedelta(days=30))
        html = self.get(self.i1).content.decode()
        for needle in ('ticket opened', 'old one', 'vendor fix due', 'Revoked', 'Waived'):
            self.assertIn(needle, html)

    def test_provisional_is_labelled_not_scored(self):
        prov = TrackedIssue.objects.create(project=self.p, asset=self.a, key='rep.dnsbl_listed', source='check', severity=2)
        html = self.get(prov).content.decode()
        self.assertIn('Provisional', html)
        self.assertIn('not scored', html.lower())

    def test_actions_follow_permissions(self):
        self.assertIn('id="rd_waive_form"', self.get(self.i1).content.decode())
        self.client.force_login(self.auditor)
        html = self.get(self.i1).content.decode()
        self.assertNotIn('id="rd_waive_form"', html)
        self.assertNotIn('id="rd_note_form"', html)

    def test_queries_do_not_grow_with_affected_assets(self):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext
        self.get(self.i1)
        with CaptureQueriesContext(connection) as small:
            self.get(self.i1)
        for n in range(15):
            a = Asset.objects.create(project=self.p, kind='hostname', value=f'h{n}.x.com', scope_tier='owned_host')
            t = TrackedIssue.objects.create(project=self.p, asset=a, key='web.hsts_missing', source='check', severity=2)
            IssueNote.objects.create(issue=t, author=self.admin, text='n')
        with CaptureQueriesContext(connection) as big:
            self.get(self.i1)
        self.assertEqual(len(small), len(big))

    def test_finding_shows_evidence_box_and_check_does_not(self):
        f = TrackedIssue.objects.create(project=self.p, asset=self.a, key='panel-1', source='finding', severity=3)
        self.assertIn('id="rd_evidence"', self.get(f).content.decode())
        self.assertNotIn('id="rd_evidence"', self.get(self.i1).content.decode())

    def test_evidence_endpoint_the_page_reads_is_project_scoped(self):
        f = TrackedIssue.objects.create(project=self.p, asset=self.a, key='panel-1', source='finding', severity=3)
        url = '/api/issue/evidence/'
        self.assertEqual(self.client.get(url, {'project': 'p1', 'issue_id': f.id}).status_code, 200)
        self.assertEqual(self.client.get(url, {'project': 'p2', 'issue_id': f.id}).status_code, 404)
