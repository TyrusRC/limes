from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes import scoring
from limes.definitions import FAILED_TASK, NOTHING_ASSESSED, SUCCESS_TASK
from scanEngine.models import EngineType
from startScan.models import Asset, ScanActivity, ScanHistory, ScoreSnapshot, Vulnerability
from targetApp.models import Domain


class Base(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.eng = EngineType.objects.create(engine_name='e', yaml_configuration='{}')
        self.root = self.owned_root('x.com')
        self.now = timezone.now()

    def owned_root(self, value, project=None):
        project = project or self.p
        Domain.objects.create(project=project, name=value, insert_date=timezone.now())
        return Asset.objects.create(project=project, kind='root_domain', value=value, scope_tier='owned_root')

    def host(self, value, tier='owned_host', state='active', project=None):
        return Asset.objects.create(project=project or self.p, kind='hostname', value=value, scope_tier=tier, state=state)

    def scan(self, domain='x.com', ago=timedelta(hours=1), vuln_stage=SUCCESS_TASK):
        s = ScanHistory.objects.create(domain=Domain.objects.get(name=domain), scan_type=self.eng,
                                       start_scan_date=self.now - ago)
        if vuln_stage is not None:
            ScanActivity.objects.create(scan_of=s, name='vulnerability_scan', title='v', time=self.now, status=vuln_stage)
        return s

    def vuln(self, scan, asset, severity, template='t1', url='https://h/', open_status=True):
        return Vulnerability.objects.create(scan_history=scan, asset=asset, name=f'{template} name', template_id=template,
                                            severity=severity, http_url=url, open_status=open_status)

    def score(self, asset):
        return scoring.asset_breakdown(asset)['score']


class AssetScoreTest(Base):
    def test_clean_asset_scores_max(self):
        self.scan()
        self.assertEqual(scoring.asset_breakdown(self.host('a.x.com')), {'score': 950, 'grade': 'A', 'penalties': [], 'assessed': True})

    def test_penalties_and_ceilings(self):
        s = self.scan()
        med, high, crit = self.host('m.x.com'), self.host('h.x.com'), self.host('c.x.com')
        self.vuln(s, med, 2)
        self.vuln(s, high, 3)
        self.vuln(s, crit, 4)
        self.assertEqual((self.score(med), self.score(high), self.score(crit)), (925, 799, 599))
        self.assertEqual((scoring.grade(925), scoring.grade(799), scoring.grade(599)), ('A', 'B', 'C'))

    def test_same_issue_counts_once_at_its_worst(self):
        s = self.scan()
        a = self.host('a.x.com')
        for url in ('https://a/1', 'https://a/2', 'https://a/3'):
            self.vuln(s, a, 2, url=url)
        self.vuln(s, a, 3, url='https://a/4')  # same template, worse severity
        self.vuln(s, a, 1, template='t2')
        b = scoring.asset_breakdown(a)
        self.assertEqual(b['score'], min(950 - 80 - 5, 799))
        self.assertEqual([(r['issue'], r['severity'], r['points']) for r in b['penalties']],
                         [('t1', 'high', 80), ('t2', 'low', 5)])

    def test_floor_at_zero(self):
        s = self.scan()
        a = self.host('a.x.com')
        for i in range(6):
            self.vuln(s, a, 4, template=f't{i}')
        self.assertEqual(self.score(a), 0)

    def test_excluded_findings(self):
        s = self.scan()
        a = self.host('a.x.com')
        self.vuln(s, a, 0, template='info')
        self.vuln(s, a, -1, template='unknown')
        self.vuln(s, a, 4, template='closed', open_status=False)
        self.assertEqual(self.score(a), 950)

    def test_monotonic(self):
        s = self.scan()
        a = self.host('a.x.com')
        before = self.score(a), scoring.project_score(self.p)['score']
        for sev, t in ((1, 'l'), (2, 'm'), (3, 'h'), (4, 'c')):
            self.vuln(s, a, sev, template=t)
            after = self.score(a), scoring.project_score(self.p)['score']
            self.assertLessEqual(after[0], before[0])
            self.assertLessEqual(after[1], before[1])
            before = after


class BaselineTest(Base):
    def test_newer_scan_without_the_finding_recovers(self):
        a = self.host('a.x.com')
        old = self.scan(ago=timedelta(days=2))
        self.vuln(old, a, 4)
        self.assertEqual(self.score(a), 599)
        self.scan(ago=timedelta(hours=1))  # verified fix: the stage ran and found nothing
        self.assertEqual(self.score(a), 950)

    def test_scan_without_a_successful_vuln_stage_is_never_baseline(self):
        a = self.host('a.x.com')
        self.vuln(self.scan(ago=timedelta(days=2)), a, 4)
        self.scan(ago=timedelta(hours=2), vuln_stage=None)  # asm-only run
        self.scan(ago=timedelta(hours=1), vuln_stage=FAILED_TASK)
        self.assertEqual(self.score(a), 599)

    def test_stage_that_assessed_nothing_is_never_a_baseline(self):
        a = self.host('a.x.com')
        self.vuln(self.scan(ago=timedelta(days=2)), a, 4)
        empty = self.scan(ago=timedelta(hours=1), vuln_stage=None)
        ScanActivity.objects.create(scan_of=empty, name='vulnerability_scan', title='v', time=self.now,
                                    status=SUCCESS_TASK, error_message=f'{NOTHING_ASSESSED}: no alive HTTP URLs')
        self.assertEqual(self.score(a), 599)

    def test_refound_finding_counts_once(self):
        a = self.host('a.x.com')
        self.vuln(self.scan(ago=timedelta(days=2)), a, 3)
        self.vuln(self.scan(ago=timedelta(hours=1)), a, 3)
        self.assertEqual(scoring.asset_breakdown(a)['penalties'], [{'asset': 'a.x.com', 'issue': 't1', 'severity': 'high', 'points': 80, 'kind': 'finding', 'provisional': False, 'waived': False}])

    def test_only_owned_unretired_assets_count(self):
        s = self.scan()
        for tier, state in (('candidate', 'active'), ('co_brand', 'active'), ('owned_host', 'retired')):
            a = self.host(f'{tier}-{state}.x.com', tier=tier, state=state)
            self.vuln(s, a, 4)
        self.assertEqual(scoring.project_score(self.p)['score'], 950)
        self.assertEqual(scoring.project_score(self.p)['top_penalties'], [])


class ProjectScoreTest(Base):
    def test_p10_nearest_rank(self):
        cases = {1: [5], 2: [5, 9], 9: list(range(9)), 10: list(range(10)), 11: list(range(11))}
        expected = {1: 5, 2: 5, 9: 0, 10: 0, 11: 1}
        for n, scores in cases.items():
            self.assertEqual(scoring.p10(list(reversed(scores))), expected[n], n)
        self.assertIsNone(scoring.p10([]))

    def test_merger_invariance(self):
        scores = [950, 925, 799, 599, 0, 870, 950, 950, 940, 600, 300, 950]
        self.assertEqual(scoring.p10(scores), scoring.p10(scores + scores))

    def test_no_assets_is_not_applicable(self):
        empty = Project.objects.create(name='e', slug='e', insert_date=timezone.now())
        s = scoring.project_score(empty)
        self.assertEqual((s['score'], s['grade'], s['coverage'], s['asset_count']), (None, 'N/A', None, 0))

    def test_project_score_and_top_penalties(self):
        s = self.scan()
        a, b = self.host('a.x.com'), self.host('b.x.com')
        self.vuln(s, a, 3)
        self.vuln(s, b, 2, template='t2')
        out = scoring.project_score(self.p)
        self.assertEqual((out['version'], out['asset_count'], out['score'], out['grade']), ('limes-score-v3', 3, 799, 'B'))
        self.assertEqual([r['asset'] for r in out['top_penalties']], ['a.x.com', 'b.x.com'])

    def test_coverage_window(self):
        self.owned_root('y.com')
        self.scan('x.com', ago=timedelta(days=29))
        self.scan('y.com', ago=timedelta(days=31))
        self.assertEqual(scoring.coverage(self.p, now=self.now), 0.5)

    def test_other_projects_never_leak_in(self):
        other = Project.objects.create(name='o', slug='o', insert_date=timezone.now())
        self.owned_root('z.com', project=other)
        a = self.host('a.z.com', project=other)
        self.vuln(self.scan('z.com'), a, 4)
        self.scan('x.com')
        self.assertEqual(scoring.project_score(self.p)['score'], 950)


class AssessmentTest(Base):
    def test_never_vulnerability_scanned_is_not_clean(self):
        a = self.host('a.x.com')
        self.scan(vuln_stage=None)  # asm-only
        self.assertEqual(scoring.asset_breakdown(a), {'score': None, 'grade': 'N/A', 'penalties': [], 'assessed': False})
        s = scoring.project_score(self.p)
        self.assertEqual((s['score'], s['grade'], s['asset_count'], s['unassessed']), (None, 'N/A', 0, 2))

    def test_only_assessed_roots_drive_the_project(self):
        self.owned_root('y.com')
        self.vuln(self.scan('x.com'), self.host('a.x.com'), 2)
        bad = self.host('b.y.com')  # y.com never vulnerability-scanned: not counted as clean
        s = scoring.project_score(self.p)
        self.assertEqual((s['score'], s['asset_count'], s['unassessed']), (925, 2, 2))
        self.assertFalse(scoring.asset_breakdown(bad)['assessed'])


class SnapshotTest(Base):
    def test_one_row_per_project_per_day(self):
        self.vuln(self.scan(), self.host('a.x.com'), 3)
        scoring.snapshot_scores()
        self.vuln(self.scan(ago=timedelta(minutes=5)), self.host('b.x.com'), 4)
        scoring.snapshot_scores()
        snaps = ScoreSnapshot.objects.filter(project=self.p)
        self.assertEqual(snaps.count(), 1)
        self.assertEqual((snaps[0].score, snaps[0].grade, snaps[0].version), (599, 'C', 'limes-score-v3'))

