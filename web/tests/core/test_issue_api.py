import re
from datetime import timedelta
from unittest import mock
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

    def test_category_filter(self):
        ids = lambda **kw: [r['id'] for r in self.list(**kw)]
        self.assertEqual(ids(category='web'), [self.i1.id])
        self.assertEqual(ids(category='vulnerabilities'), [self.i2.id])
        self.assertEqual(ids(category='tls'), [])
        for bad in ('bogus', 'WEB', ''):
            self.assertEqual(ids(category=bad), [self.i2.id, self.i1.id], bad)
        self.assertNotIn(self.other.id, ids(category='web'))

    def test_category_filter_matches_counts(self):
        from limes import scoring
        gone = Asset.objects.create(project=self.p, kind='hostname', value='old.x.com', scope_tier='owned_host', state='retired')
        TrackedIssue.objects.create(project=self.p, asset=gone, key='cve-9', source='finding', severity=3)
        counts = scoring.category_issue_counts(self.p)
        for key in scoring.CATEGORIES:
            self.assertEqual(len(self.list(category=key)), counts[key]['open'], key)
        self.assertEqual(sum(c['open'] for c in counts.values()), len(self.list()))

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

    def test_rows_carry_category_and_kind_for_the_grouped_list(self):
        rows = {r['id']: r for r in self.list()}
        self.assertEqual((rows[self.i1.id]['category'], rows[self.i1.id]['category_label']), ('web', 'Website'))
        self.assertEqual(rows[self.i2.id]['category'], 'vulnerabilities')  # a finding
        self.assertEqual(rows[self.i1.id]['asset_kind'], 'hostname')

    def test_grouped_list(self):
        b = Asset.objects.create(project=self.p, kind='hostname', value='b.x.com', scope_tier='owned_host')
        j = TrackedIssue.objects.create(project=self.p, asset=b, key='web.hsts_missing', source='check', severity=2)
        groups = self.as_user(self.admin).get('/api/issues/', {'project': 'p1', 'group': '1'}).json()
        self.assertEqual([g['key'] for g in groups], ['<script>x', 'web.hsts_missing'])
        g = groups[1]
        self.assertEqual((g['count'], g['status'], sorted(a['asset'] for a in g['assets'])), (2, 'open', ['a.x.com', 'b.x.com']))
        self.assertEqual(g['id'], self.i1.id)  # the oldest row
        self.assertIn(j.id, g['unwaived_ids'])
        other = self.as_user(self.admin).get('/api/issues/', {'project': 'p2', 'group': '1'}).json()
        self.assertEqual([x['count'] for x in other], [1])

    def test_waiver_inactive_exactly_at_expires_at(self):
        exp = timezone.now() + timedelta(days=3)
        IssueWaiver.objects.create(issue=self.i1, kind='accepted_risk', reason='r', created_by=self.admin, expires_at=exp)
        waived = lambda: [r['id'] for r in self.list(waived='true')]
        with mock.patch('api.views.timezone.now', return_value=exp - timedelta(seconds=1)):
            self.assertEqual(waived(), [self.i1.id])
        with mock.patch('api.views.timezone.now', return_value=exp):
            self.assertEqual(waived(), [])
            self.assertIsNone([r for r in self.list() if r['id'] == self.i1.id][0]['waiver'])

    def test_expired_waiver_reported_until_replaced_or_revoked(self):
        now = timezone.now()
        exp = now - timedelta(days=1)
        IssueWaiver.objects.create(issue=self.i1, kind='accepted_risk', reason='r', expires_at=exp,
                                   created_at=now - timedelta(days=30))
        row = lambda: [r for r in self.list() if r['id'] == self.i1.id][0]
        self.assertIsNone(row()['waiver'])
        self.assertEqual(row()['expired_waiver']['kind'], 'accepted_risk')
        self.assertIsNone([r for r in self.list() if r['id'] == self.i2.id][0]['expired_waiver'])
        # a newer active waiver supersedes it
        self.post(self.admin, '/api/action/issue/waive/', issue_id=self.i1.id, kind='false_positive', reason='fp')
        self.assertIsNone(row()['expired_waiver'])
        # revoking the newer one does not bring the old expiry back
        self.post(self.admin, '/api/action/issue/revoke/', issue_id=self.i1.id)
        self.assertIsNone(row()['expired_waiver'])

    def test_forecast_caps_issue_list(self):
        r = self.post(self.admin, '/api/score_forecast/', issues=list(range(1, 502)))
        self.assertFalse(r.json()['status'])
        self.assertIn('500', r.json()['message'])
        self.assertTrue(self.post(self.admin, '/api/score_forecast/', issues=list(range(1, 501))).json()['status'])

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


class IssuePageTest(TestCase):
    """The waive and note forms are rendered only for users who may write; read-only roles get the notice."""

    def setUp(self):
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())

    def page(self, role):
        u = User.objects.create_user(role, password='p')
        assign_role(u, role)
        self.client.force_login(u)
        self.client.get('/scan/p1/issues')  # warm-up (lazy prefs creation)
        r = self.client.get('/scan/p1/issues')
        self.assertEqual(r.status_code, 200)
        return r.content.decode()

    def test_category_chips_rendered(self):
        html = self.page('sys_admin')
        from limes import scoring  # the hand-written chips must not drift from the category model
        chips = re.findall(r'data-k="category" data-v="([^"]*)"[^>]*>([^<]*)</button>', html)
        self.assertEqual(chips, [(k, scoring.CATEGORY_LABELS[k]) for k in scoring.CATEGORIES])

    def test_list_page_has_no_write_forms(self):
        """Waiving and notes live on the risk detail page (tests.core.test_issue_detail checks them per role)."""
        html = self.page('sys_admin')
        for needle in ('id="issue_waive_form"', 'id="issue_note_form"'):
            self.assertNotIn(needle, html)


class IssueEvidenceApiTest(IssueApiTest):
    """The scanner evidence the retired Vulnerabilities pages used to show, now behind the issue."""

    def vuln(self, asset, template, **kw):
        from startScan.models import Vulnerability
        return Vulnerability.objects.create(asset=asset, template_id=template, name=template + ' name', severity=3,
                                            http_url='https://a.x.com/', discovered_date=timezone.now(), **kw)

    def get(self, issue_id, project='p1', user=None):
        return self.as_user(user or self.admin).get('/api/issue/evidence/', {'project': project, 'issue_id': issue_id})

    def test_returns_open_rows_of_that_asset_and_key(self):
        self.vuln(self.a, '<script>x', description='d' * 30000, request='GET /', response='HTTP/1.1 200', open_status=True)
        self.vuln(self.a, '<script>x', description='closed', open_status=False)
        self.vuln(self.a, 'other-template', description='nope', open_status=True)
        self.vuln(self.b, '<script>x', description='other project', open_status=True)
        rows = self.get(self.i2.id).json()
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]['request'], len(rows[0]['description'])), ('GET /', 20000))

    def test_returns_cves_and_references(self):
        from startScan.models import CveId
        v = self.vuln(self.a, '<script>x', reference_urls=['https://r/2', 'https://r/1'])
        v.cve_ids.add(CveId.objects.create(name='CVE-2024-2'), CveId.objects.create(name='CVE-2024-1'))
        row = self.get(self.i2.id).json()[0]
        self.assertEqual((row['cves'], row['references']), (['CVE-2024-1', 'CVE-2024-2'], ['https://r/1', 'https://r/2']))

    def test_check_issue_has_no_evidence(self):
        self.assertEqual(self.get(self.i1.id).json(), [])

    def test_cross_project_and_bad_ids_are_404(self):
        for pid, project in ((self.other.id, 'p1'), (self.i2.id, 'p2'), ('abc', 'p1'), (self.i2.id, '')):
            self.assertEqual(self.get(pid, project).status_code, 404, (pid, project))
