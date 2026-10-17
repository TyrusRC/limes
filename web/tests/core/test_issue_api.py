from datetime import timedelta
from django.test import TestCase
from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role
from dashboard.models import Project
from dashboard.views import on_user_logged_in
from startScan.models import Asset, TrackedIssue, IssueWaiver, IssueNote


class IssueApiTest(TestCase):
    def setUp(self):
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.admin = User.objects.create_user('adm', password='p')
        assign_role(self.admin, 'sys_admin')
        self.auditor = User.objects.create_user('aud', password='p')
        assign_role(self.auditor, 'auditor')
        self.p = Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())
        self.q = Project.objects.create(name='p2', slug='p2', insert_date=timezone.now())
        self.a = Asset.objects.create(project=self.p, kind='hostname', value='a.x.com', scope_tier='owned_host')
        self.b = Asset.objects.create(project=self.q, kind='hostname', value='b.y.com', scope_tier='owned_host')
        now = timezone.now()
        self.i1 = TrackedIssue.objects.create(project=self.p, asset=self.a, key='web.hsts_missing', source='check',
                                              severity=2, first_seen=now - timedelta(days=2))
        self.i2 = TrackedIssue.objects.create(project=self.p, asset=self.a, key='<script>x', source='finding',
                                              severity=4, first_seen=now - timedelta(days=1))
        self.i3 = TrackedIssue.objects.create(project=self.p, asset=self.a, key='web.csp_missing', source='check',
                                              severity=1, status='fixed')
        self.other = TrackedIssue.objects.create(project=self.q, asset=self.b, key='web.hsts_missing', source='check',
                                                 severity=2)

    def as_user(self, user):
        c = APIClient()
        c.force_login(user)
        return c

    def post(self, user, url, **body):
        body.setdefault('project', 'p1')
        return self.as_user(user).post(url, body, format='json')

    def list(self, **params):
        params.setdefault('project', 'p1')
        return self.as_user(self.admin).get('/api/issues/', params).json()

    def test_list_filters_and_shape(self):
        rows = self.list()
        self.assertEqual([r['id'] for r in rows], [self.i2.id, self.i1.id])  # severity desc, open only
        r = rows[1]
        self.assertEqual((r['asset'], r['key'], r['source'], r['severity'], r['waiver'], r['note_count']),
                         ('a.x.com', 'web.hsts_missing', 'check', 2, None, 0))
        self.assertIn('HTTPS', r['title'])
        self.assertEqual(rows[0]['title'], '<script>x')
        self.assertIn('first_seen', r)
        self.assertIn('last_seen', r)
        self.assertEqual([r['id'] for r in self.list(severity='4')], [self.i2.id])
        self.assertEqual([r['id'] for r in self.list(source='check')], [self.i1.id])
        self.post(self.admin, '/api/action/issue/waive/', issue_id=self.i1.id, kind='false_positive', reason='fp')
        self.assertEqual([r['id'] for r in self.list(waived='true')], [self.i1.id])
        self.assertEqual([r['id'] for r in self.list(waived='false')], [self.i2.id])

    def test_waive_and_revoke_round_trip(self):
        r = self.post(self.admin, '/api/action/issue/waive/', issue_id=self.i1.id, kind='accepted_risk', reason='ok')
        self.assertTrue(r.json()['status'])
        self.assertEqual(r.json()['waiver']['kind'], 'accepted_risk')
        w = [x for x in self.list() if x['id'] == self.i1.id][0]['waiver']
        self.assertEqual((w['kind'], w['reason'], w['created_by']), ('accepted_risk', 'ok', 'adm'))
        self.assertTrue(w['expires_at'])
        self.assertTrue(self.post(self.admin, '/api/action/issue/revoke/', issue_id=self.i1.id).json()['status'])
        self.assertIsNone([x for x in self.list() if x['id'] == self.i1.id][0]['waiver'])
        self.assertFalse(self.post(self.admin, '/api/action/issue/revoke/', issue_id=self.i1.id).json()['status'])

    def test_waive_validation_errors_are_messages(self):
        big = (timezone.now() + timedelta(days=400)).isoformat()
        cases = [dict(kind='nope', reason='r'), dict(kind='accepted_risk', reason='  '),
                 dict(kind='accepted_risk', reason=5), dict(kind='accepted_risk', reason='r', expires_at=big),
                 dict(kind='accepted_risk', reason='r', expires_at='garbage'),
                 dict(kind='accepted_risk', reason='r', expires_at=12),
                 dict(kind='accepted_risk', reason='r', expires_at=['x'])]
        for c in cases:
            r = self.post(self.admin, '/api/action/issue/waive/', issue_id=self.i1.id, **c)
            self.assertEqual(r.status_code, 200, c)
            self.assertFalse(r.json()['status'], c)
            self.assertTrue(r.json()['message'], c)
        self.assertFalse(IssueWaiver.objects.exists())

    def test_waive_and_revoke_drop_the_cached_dashboard_stats(self):
        from django.core.cache import cache
        from dashboard.stats import _key
        for url, body in (('/api/action/issue/waive/', {'kind': 'false_positive', 'reason': 'fp'}), ('/api/action/issue/revoke/', {})):
            cache.set(_key(self.p.id), {'stale': True})
            self.assertTrue(self.post(self.admin, url, issue_id=self.i1.id, **body).json()['status'])
            self.assertIsNone(cache.get(_key(self.p.id)), url)

    def test_expiry_task_drops_the_cached_dashboard_stats(self):
        from django.core.cache import cache
        from dashboard.stats import _key
        from limes.alerts import waiver_tasks
        from limes import waivers
        w = waivers.create_waiver(self.i1, 'false_positive', 'fp', self.admin)
        IssueWaiver.objects.filter(pk=w.pk).update(expires_at=timezone.now() - timedelta(minutes=1))
        cache.set(_key(self.p.id), {'stale': True})
        self.assertEqual(waiver_tasks.expire_waivers()['expired'], 1)
        self.assertIsNone(cache.get(_key(self.p.id)))

    def test_naive_expiry_accepted(self):
        exp = (timezone.now() + timedelta(days=5)).replace(tzinfo=None).isoformat()
        r = self.post(self.admin, '/api/action/issue/waive/', issue_id=self.i1.id, kind='false_positive',
                      reason='r', expires_at=exp)
        self.assertTrue(r.json()['status'], r.json())

    def test_notes_round_trip(self):
        url = '/api/issue/notes/'
        self.assertTrue(self.post(self.admin, url, issue_id=self.i1.id, text='first').json()['status'])
        self.post(self.admin, url, issue_id=self.i1.id, text='second')
        self.assertFalse(self.post(self.admin, url, issue_id=self.i1.id, text=' ').json()['status'])
        self.assertFalse(self.post(self.admin, url, issue_id=self.i1.id, text=['x']).json()['status'])
        rows = self.as_user(self.auditor).get(url, {'project': 'p1', 'issue_id': self.i1.id}).json()
        self.assertEqual([(r['author'], r['text']) for r in rows], [('adm', 'first'), ('adm', 'second')])
        self.assertIn('created_at', rows[0])
        self.assertEqual([x for x in self.list() if x['id'] == self.i1.id][0]['note_count'], 2)

    def test_forecast_endpoint(self):
        r = self.post(self.auditor, '/api/score_forecast/', issues=[self.i2.id, self.other.id])
        d = r.json()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(set(d), {'status', 'score', 'grade', 'delta'})
        self.assertIs(d['status'], True)
        for bad in ('x', [None], [{'a': 1}], ['abc'], [True], None, 5):
            r = self.post(self.admin, '/api/score_forecast/', issues=bad)
            self.assertEqual(r.status_code, 200, bad)
            self.assertFalse(r.json()['status'], bad)
        self.assertEqual(self.post(self.admin, '/api/score_forecast/', issues=[str(self.i2.id)]).json()['score'], d['score'])

    def test_writes_need_permission_and_project(self):
        w, rv, n = '/api/action/issue/waive/', '/api/action/issue/revoke/', '/api/issue/notes/'
        body = dict(issue_id=self.i1.id, kind='accepted_risk', reason='r')
        self.assertEqual(self.post(self.auditor, w, **body).status_code, 403)
        self.assertEqual(self.post(self.auditor, rv, issue_id=self.i1.id).status_code, 403)
        self.assertEqual(self.post(self.auditor, n, issue_id=self.i1.id, text='t').status_code, 403)
        body['issue_id'] = self.other.id
        self.assertFalse(self.post(self.admin, w, **body).json()['status'])
        foreign = IssueWaiver.objects.create(issue=self.other, kind='false_positive', reason='x')
        self.assertFalse(self.post(self.admin, rv, issue_id=self.other.id).json()['status'])
        foreign.refresh_from_db()
        self.assertIsNone(foreign.revoked_at)
        self.assertFalse(self.post(self.admin, n, issue_id=self.other.id, text='t').json()['status'])
        self.assertFalse(self.post(self.admin, n, issue_id='zz', text='t').json()['status'])
        self.assertEqual(IssueWaiver.objects.count(), 1)  # only the foreign fixture
        self.assertFalse(IssueNote.objects.exists())
        got = self.as_user(self.admin).get(n, {'project': 'p1', 'issue_id': self.other.id})
        self.assertEqual(got.status_code, 404)
        self.assertEqual(self.as_user(self.admin).get('/api/issues/', {'project': 'nope'}).json(), [])
        self.assertNotEqual(APIClient().get('/api/issues/', {'project': 'p1'}).status_code, 200)

    def test_bad_ids_are_messages(self):
        for bad in (1.9, '9' * 30, 10 ** 30, '1.5', '-1', True, None, [1]):
            for url, extra in (('/api/action/issue/waive/', dict(kind='false_positive', reason='r')),
                               ('/api/action/issue/revoke/', {}), ('/api/issue/notes/', dict(text='t'))):
                r = self.post(self.admin, url, issue_id=bad, **extra)
                self.assertEqual(r.status_code, 200, (url, bad))
                self.assertFalse(r.json()['status'], (url, bad))
            g = self.as_user(self.admin).get('/api/issue/notes/', {'project': 'p1', 'issue_id': str(bad)})
            self.assertEqual(g.status_code, 404, bad)
        for bad in ([1.9], ['9' * 30], [10 ** 30], ['-1']):
            r = self.post(self.admin, '/api/score_forecast/', issues=bad)
            self.assertFalse(r.json()['status'], bad)

    def test_list_query_count_is_constant(self):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext
        def count():
            with CaptureQueriesContext(connection) as c:
                self.list()
            return len(c)
        self.post(self.admin, '/api/action/issue/waive/', issue_id=self.i1.id, kind='false_positive', reason='r')
        few = count()
        for n in range(5):
            i = TrackedIssue.objects.create(project=self.p, asset=self.a, key=f'f{n}', source='finding', severity=3)
            self.post(self.admin, '/api/action/issue/waive/', issue_id=i.id, kind='false_positive', reason='r')
            IssueNote.objects.create(issue=i, text='n')
        self.assertEqual(count(), few)
