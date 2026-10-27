from startScan.models import Asset, TrackedIssue
from limes import scoring
from tests.core.test_remediation import HOSTILE, Base


class IgnoreTest(Base):
    def setUp(self):
        super().setUp()
        self.f = TrackedIssue.objects.create(project=self.p, asset=self.a, key='cve-x', source='finding', severity=3)
        self.of = TrackedIssue.objects.create(project=self.q, asset=self.o, key='cve-x', source='finding', severity=3)

    def act(self, what, issue, project='p1', **kw):
        return self.post(f'/api/action/issue/{what}/', {'project': project, 'issue_id': issue.id, **kw})

    def rows(self, **q):
        return self.client.get('/api/issues/', {'project': 'p1', **q}).json()

    def test_ignore_hides_from_list_shows_in_ignored_tab_and_reverses(self):
        self.assertIn(self.f.id, [r['id'] for r in self.rows()])
        self.assertEqual(self.act('ignore', self.f, reason='noise').status_code, 200)
        self.assertNotIn(self.f.id, [r['id'] for r in self.rows()])
        ign = [r for r in self.rows(ignored='true') if r['id'] == self.f.id]
        self.assertEqual(ign[0]['ignored_reason'], 'noise')
        self.assertEqual(self.act('unignore', self.f).status_code, 200)
        self.assertIn(self.f.id, [r['id'] for r in self.rows()])
        self.assertEqual(self.rows(ignored='true'), [])

    def test_ignoring_does_not_change_the_score(self):
        before = scoring.project_score(self.p)
        self.act('ignore', self.f, reason='noise')
        self.assertEqual(scoring.project_score(self.p), before)

    def test_validation_and_scoping(self):
        self.assertEqual(self.act('ignore', self.f, reason='').status_code, 400)
        self.assertEqual(self.act('ignore', self.f, reason='x' * 301).status_code, 400)
        self.assertEqual(self.act('ignore', self.i1, reason='r').status_code, 400)  # a check is waived, not ignored
        self.assertEqual(self.act('ignore', self.of, reason='r').status_code, 404)  # another project's issue
        self.assertEqual(self.act('ignore', self.f, project='nope', reason='r').status_code, 404)
        self.assertFalse(TrackedIssue.objects.exclude(ignored_at=None).exists())

    def test_viewer_cannot_ignore(self):
        c = self.client_class()
        c.force_login(self.viewer)
        self.assertEqual(self.post('/api/action/issue/ignore/', {'project': 'p1', 'issue_id': self.f.id, 'reason': 'r'}, c).status_code, 403)

    def test_reason_is_escaped_on_the_detail_page(self):
        self.act('ignore', self.f, reason=HOSTILE)
        html = self.client.get(f'/scan/p1/issues/{self.f.id}/').content.decode()
        self.assertNotIn('<img src=x', html)
        self.assertIn('&lt;img src=x', html)
