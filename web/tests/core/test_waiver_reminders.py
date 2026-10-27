from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.test import Client, TestCase
from django.utils import timezone
from rolepermissions.roles import assign_role

from dashboard.home import tasks
from dashboard.models import InAppNotification, Project
from dashboard.views import on_user_logged_in
from limes import waivers
from limes.alerts import waiver_tasks
from startScan.models import Asset, IssueWaiver, TrackedIssue

HOSTILE = '<img src=x onerror=alert(1)>'


class Base(TestCase):
    def setUp(self):
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.me = User.objects.create_user('me', password='p')
        self.boss = User.objects.create_user('boss', password='p')
        self.viewer = User.objects.create_user('viewer', password='p')
        for u, role in ((self.me, 'sys_admin'), (self.boss, 'sys_admin'), (self.viewer, 'auditor')):
            assign_role(u, role)
        self.now = timezone.now()
        self.p = Project.objects.create(name='p1', slug='p1', insert_date=self.now)
        self.q = Project.objects.create(name='p2', slug='p2', insert_date=self.now)
        self.a = Asset.objects.create(project=self.p, kind='hostname', value='a.x.com', scope_tier='owned_host')
        self.o = Asset.objects.create(project=self.q, kind='hostname', value='o.y.com', scope_tier='owned_host')
        self.issue = TrackedIssue.objects.create(project=self.p, asset=self.a, key='web.hsts_missing', source='check', severity=2)
        self.other = TrackedIssue.objects.create(project=self.q, asset=self.o, key='web.hsts_missing', source='check', severity=2)

    def waiver(self, days, **kw):
        kw.setdefault('expires_at', self.now + timedelta(days=days))
        return waivers.create_waiver(self.issue, 'accepted_risk', 'r', self.me, now=self.now - timedelta(minutes=1), **kw)

    def remind(self, **kw):
        return waiver_tasks.remind_waivers(now=self.now, **kw)

    def notes(self):
        return InAppNotification.objects.filter(title__startswith='Waiver ends')


class ReminderTest(Base):
    def test_reminded_once_inside_the_lead_time(self):
        self.waiver(5)
        self.assertEqual(self.remind(), {'reminded': 1})
        self.assertEqual(self.remind(), {'reminded': 0})
        self.assertEqual(self.notes().count(), 1)
        self.assertEqual(self.notes()[0].project, self.p)
        self.assertEqual(self.notes()[0].redirect_link, '/remediation/p1/waivers')

    def test_not_before_the_lead_time(self):
        self.waiver(20)
        self.assertEqual(self.remind(), {'reminded': 0})
        self.assertEqual(self.notes().count(), 0)

    def test_lead_time_is_per_waiver(self):
        self.waiver(20, remind_days=30)
        self.assertEqual(self.remind(), {'reminded': 1})

    def test_never_for_revoked_expired_or_pending(self):
        w = self.waiver(5)
        waivers.revoke_waiver(self.issue, self.me, now=self.now)
        self.assertEqual(self.remind(), {'reminded': 0})
        past = IssueWaiver.objects.create(issue=self.issue, kind='accepted_risk', reason='r', expires_at=self.now - timedelta(days=1))
        self.waiver(5, approver=self.boss)
        self.assertEqual(self.remind(), {'reminded': 0})
        self.assertEqual((w.reminded_at, IssueWaiver.objects.get(pk=past.pk).reminded_at), (None, None))

    def test_project_wide_waiver_is_reminded_in_its_own_project(self):
        self.waiver(3, scope='all')
        self.assertEqual(self.remind(), {'reminded': 1})
        self.assertEqual(self.notes()[0].project, self.p)

    def test_hostile_key_is_one_clean_line(self):
        TrackedIssue.objects.filter(pk=self.issue.pk).update(key='k\r\nBcc: x')
        self.issue.refresh_from_db()
        self.waiver(3)
        self.remind()
        self.assertNotIn('\n', self.notes()[0].title)

    def test_a_failure_for_one_waiver_does_not_stop_the_rest(self):
        self.waiver(3)
        with mock.patch('limes.common_func.create_inappnotification', side_effect=RuntimeError('boom')):
            self.assertEqual(self.remind(), {'reminded': 0})
        # the claim rolled back with the failed notification, so the next run tries again
        self.assertEqual(self.remind(), {'reminded': 1})


class TasksTest(Base):
    def cards(self, user, project=None):
        return [c for c in tasks(project or self.p, self.now, set(), user)]

    def test_approver_sees_a_pending_waiver_requester_and_others_do_not(self):
        self.waiver(30, approver=self.boss)
        self.assertEqual([c['key'] for c in self.cards(self.boss) if c['kind'] == 'approval'], [f'task:approve:{IssueWaiver.objects.get().id}'])
        self.assertEqual([c for c in self.cards(self.me) if c['kind'] == 'approval'], [])
        self.assertEqual([c for c in self.cards(self.viewer) if c['kind'] == 'approval'], [])
        self.assertEqual([c for c in self.cards(self.boss, self.q) if c['kind'] == 'approval'], [])

    def test_approved_waiver_leaves_the_approver_tasks(self):
        w = self.waiver(30, approver=self.boss)
        waivers.decide_waiver(self.p, w.id, self.boss, True)
        self.assertEqual([c for c in self.cards(self.boss) if c['kind'] == 'approval'], [])

    def test_ending_soon_uses_the_waivers_own_lead_time(self):
        self.waiver(20, remind_days=30)
        self.assertEqual(len([c for c in self.cards(self.me) if c['kind'] == 'waiver']), 1)

    def test_project_wide_waiver_ending_soon_is_a_task_linking_to_the_waivers_page(self):
        self.waiver(2, scope='all')
        (card,) = [c for c in self.cards(self.me) if c['kind'] == 'waiver']
        self.assertEqual(card['url'], '/remediation/p1/waivers')


class WaiversPageTest(Base):
    def setUp(self):
        super().setUp()
        self.client = Client()
        self.client.force_login(self.me)

    def post(self, url, body, client=None):
        return (client or self.client).post(url, body, content_type='application/json')

    def test_lists_current_and_past_with_hostile_text_escaped(self):
        old = self.waiver(30)
        new = waivers.create_waiver(self.issue, 'false_positive', HOSTILE, self.me)
        old.refresh_from_db()
        html = self.client.get('/remediation/p1/waivers').content.decode()
        self.assertEqual(self.client.get('/remediation/p1/waivers').status_code, 200)
        self.assertNotIn(HOSTILE, html)
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;', html)
        self.assertEqual(IssueWaiver.objects.filter(revoked_at__isnull=False).count(), 1)
        self.assertIn('Past', html)
        self.assertIsNotNone(new.id)

    def test_unknown_project_is_404(self):
        self.assertEqual(self.client.get('/remediation/nope/waivers').status_code, 404)

    def test_revoke_and_cross_project_404(self):
        w = self.waiver(30)
        r = self.post('/api/action/waiver/revoke/', {'project': 'p2', 'waiver_id': w.id})
        self.assertEqual(r.status_code, 404)
        self.assertIsNone(IssueWaiver.objects.get(pk=w.id).revoked_at)
        self.assertEqual(self.post('/api/action/waiver/revoke/', {'project': 'p1', 'waiver_id': w.id}).status_code, 200)
        self.assertIsNotNone(IssueWaiver.objects.get(pk=w.id).revoked_at)
        self.assertEqual(self.post('/api/action/waiver/revoke/', {'project': 'p1', 'waiver_id': w.id}).status_code, 400)

    def test_revoke_project_wide_waiver(self):
        w = self.waiver(30, scope='all')
        self.assertEqual(self.post('/api/action/waiver/revoke/', {'project': 'p1', 'waiver_id': w.id}).status_code, 200)
        self.assertEqual(self.post('/api/action/waiver/revoke/', {'project': 'p2', 'waiver_id': w.id}).status_code, 404)

    def test_approve_over_http_and_self_approval_refused(self):
        w = self.waiver(30, approver=self.boss)
        self.assertEqual(self.post('/api/action/waiver/decide/', {'project': 'p1', 'waiver_id': w.id, 'approve': True}).status_code, 400)
        boss = Client()
        boss.force_login(self.boss)
        self.assertEqual(self.post('/api/action/waiver/decide/', {'project': 'p2', 'waiver_id': w.id, 'approve': True}, boss).status_code, 404)
        self.assertEqual(self.post('/api/action/waiver/decide/', {'project': 'p1', 'waiver_id': w.id, 'approve': 'yes'}, boss).status_code, 400)
        self.assertEqual(self.post('/api/action/waiver/decide/', {'project': 'p1', 'waiver_id': w.id, 'approve': True}, boss).status_code, 200)
        self.assertFalse(IssueWaiver.objects.get(pk=w.id).approval_pending)

    def test_waive_endpoint_takes_scope_approver_and_rejects_a_non_member(self):
        body = {'project': 'p1', 'issue_id': self.issue.id, 'kind': 'accepted_risk', 'reason': 'ok', 'scope': 'all',
                'approver': 'boss', 'shared': True, 'remind_days': 14}
        r = self.post('/api/action/issue/waive/', body)
        self.assertEqual(r.json()['message'], 'waiting for approval')
        w = IssueWaiver.objects.get()
        self.assertEqual((w.issue_id, w.project_id, w.key, w.approver, w.shared, w.remind_days),
                         (None, self.p.id, 'web.hsts_missing', self.boss, True, 14))
        for bad in ('viewer', 'nobody', 'me', 5):
            r = self.post('/api/action/issue/waive/', {**body, 'approver': bad})
            self.assertFalse(r.json()['status'], bad)
        self.assertEqual(IssueWaiver.objects.count(), 1)

    def test_writes_need_the_targets_permission_and_csrf(self):
        w = self.waiver(30)
        viewer = Client()
        viewer.force_login(self.viewer)
        self.assertEqual(self.post('/api/action/waiver/revoke/', {'project': 'p1', 'waiver_id': w.id}, viewer).status_code, 403)
        strict = Client(enforce_csrf_checks=True)
        strict.force_login(self.me)
        self.assertEqual(self.post('/api/action/waiver/revoke/', {'project': 'p1', 'waiver_id': w.id}, strict).status_code, 403)
        self.assertIsNone(IssueWaiver.objects.get(pk=w.id).revoked_at)

    def test_list_endpoint_is_project_scoped(self):
        w = self.waiver(30)
        got = self.client.get('/api/waivers/?project=p1').json()
        self.assertEqual([x['id'] for x in got['current']], [w.id])
        self.assertEqual(self.client.get('/api/waivers/?project=p2').json(), {'current': [], 'past': []})
        self.assertEqual(self.client.get('/api/waivers/?project=nope').status_code, 404)
