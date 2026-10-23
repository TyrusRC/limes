from django.db import connection
from django.test.utils import CaptureQueriesContext

from limes import scoring
from limes.alerts.issues import sync_issues
from limes.waivers import create_waiver
from startScan.models import Asset, Tag, Vulnerability
from tests.core.test_dashboard_stats import Base


class TagScoresTest(Base):
    def setUp(self):
        super().setUp()
        self.s = self.scan()  # the owned root's baseline: every *.x.com host is assessed
        self.n = 0

    def host(self, tags, sev=None, project=None, name=None, **kw):
        self.n += 1
        a = self.asset(name or f'h{self.n}.x.com', project=project, **kw)
        if sev:
            Vulnerability.objects.create(scan_history=self.s, asset=a, name=f'v{self.n}', template_id=f't{self.n}',
                                         severity=sev, open_status=True)
        for t in tags:
            tag, _ = Tag.objects.get_or_create(project=a.project, name=t)
            a.tags.add(tag)
        return a

    def by_name(self, project=None):
        return {r['name']: r for r in scoring.tag_scores(project or self.p, self.now)}

    def test_hand_computed_scores_with_p10_roll_up(self):
        # prod: 11 hosts -> p10 is the 2nd lowest (nearest rank ceil(1.1) = 2).
        # critical: 950-200=750 capped at 599; high: 950-80=870 capped at 799; nine clean hosts: 950.
        self.host(['prod'], 4)
        self.host(['prod'], 3)
        for _ in range(9):
            self.host(['prod'])
        # eu: medium (950-25=925) and clean (950): p10 of two is the lower one.
        self.host(['eu'], 2)
        self.host(['eu'])
        rows = self.by_name()
        self.assertEqual((rows['prod']['score'], rows['prod']['grade'], rows['prod']['assets'], rows['prod']['assessed']),
                         (799, 'B', 11, 11))
        self.assertEqual((rows['eu']['score'], rows['eu']['grade'], rows['eu']['assets']), (925, 'A', 2))

    def test_reconciles_with_the_headline_model(self):
        self.host(['all'], 3)
        self.host(['all'], 2)
        self.host(['all'])
        Asset.objects.get(pk=self.root.pk).tags.add(Tag.objects.get_or_create(project=self.p, name='all')[0])
        head = scoring.project_score(self.p, self.now)
        row = self.by_name()['all']
        self.assertEqual((row['score'], row['raw_score'], row['grade']), (head['score'], head['raw_score'], head['grade']))
        a = self.host(['lone'], 3)  # one asset: its own score, same as asset_breakdown
        self.assertEqual(self.by_name()['lone']['score'], scoring.asset_breakdown(a)['score'])

    def test_waivers_leave_the_score_but_raw_keeps_them_and_open_counts_live_issues(self):
        a = self.host(['t'], 3)
        self.host(['t'], 2)
        sync_issues(self.p, now=self.now)
        self.assertEqual(self.by_name()['t']['open'], 2)
        issue = a.tracked_issues.get()
        create_waiver(issue, 'accepted_risk', 'ok', None, now=self.now)
        row = self.by_name()['t']
        self.assertEqual((row['open'], row['score'], row['raw_score']), (1, 925, 799))

    def test_not_assessed_when_no_tagged_asset_is_scored(self):
        self.asset('far.net', tier='owned_host')  # no owned root over it, no checks: unassessed
        far = Asset.objects.get(value='far.net')
        far.tags.add(Tag.objects.create(project=self.p, name='far'))
        cand = self.host(['far'], tier='candidate', name='cand.x.com')  # candidates never score
        row = self.by_name()['far']
        self.assertEqual((row['score'], row['grade'], row['assessed'], row['assets']), (None, 'N/A', 0, 2))

    def test_top_ten_by_asset_count_then_name_and_project_scoped(self):
        for i in range(12):
            for _ in range(12 - i):
                self.host([f'tag{i:02d}'])
        self.host(['zzz-other'], project=self.other, name='o.y.com')
        rows = scoring.tag_scores(self.p, self.now)
        self.assertEqual([r['name'] for r in rows], [f'tag{i:02d}' for i in range(10)])
        self.assertEqual(scoring.tag_scores(self.other, self.now)[0]['name'], 'zzz-other')
        self.assertEqual(scoring.tag_scores(self.other, self.now)[0]['assets'], 1)

    def test_query_count_does_not_grow_with_tags_or_assets(self):
        def count():
            with CaptureQueriesContext(connection) as ctx:
                scoring.tag_scores(self.p, self.now)
            return len(ctx)
        self.host(['a'], 3)
        small = count()
        for i in range(10):
            for _ in range(5):
                self.host([f'g{i}'], 2)
        self.assertEqual(count(), small)

    def test_endpoint_matches_the_function(self):
        from django.contrib.auth.models import User
        from django.contrib.auth.signals import user_logged_in
        from dashboard.views import on_user_logged_in
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.client.force_login(User.objects.create_user('u', password='p'))
        self.host(['prod'], 3)
        r = self.client.get('/api/tag_scores/', {'project': 'p'})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()[0]['name'], 'prod')
        self.assertEqual(r.json()[0]['score'], 799)
        self.assertEqual(self.client.get('/api/tag_scores/', {'project': 'nope'}).status_code, 404)
        self.assertEqual(self.client.get('/api/tag_scores/', {'project': 'o'}).json(), [])
