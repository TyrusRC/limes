from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from dashboard.models import Project
from dashboard.stats import asm_stats, invalidate, project_stats
from limes.definitions import RUNNING_TASK, SUCCESS_TASK
from scanEngine.models import EngineType
from startScan.models import Asset, ScanActivity, ScanHistory, ScoreSnapshot, Vulnerability
from targetApp.models import Domain


class Base(TestCase):
    def setUp(self):
        cache.clear()
        self.now = timezone.now()
        self.eng = EngineType.objects.create(engine_name='e', yaml_configuration='{}')
        self.p = Project.objects.create(name='p', slug='p', insert_date=self.now)
        self.other = Project.objects.create(name='o', slug='o', insert_date=self.now)
        self.root = self.owned_root(self.p, 'x.com')
        self.owned_root(self.other, 'y.com')

    def owned_root(self, project, value):
        Domain.objects.create(project=project, name=value, insert_date=self.now)
        return Asset.objects.create(project=project, kind='root_domain', value=value, scope_tier='owned_root')

    def asset(self, value, tier='owned_host', kind='hostname', project=None, **kw):
        return Asset.objects.create(project=project or self.p, kind=kind, value=value, scope_tier=tier, **kw)

    def scan(self, domain='x.com', ago=timedelta(hours=1), vuln=True, user=None, status=SUCCESS_TASK):
        s = ScanHistory.objects.create(domain=Domain.objects.get(name=domain), scan_type=self.eng, scan_status=status,
                                       start_scan_date=self.now - ago, initiated_by=user)
        if vuln:
            ScanActivity.objects.create(scan_of=s, name='vulnerability_scan', title='v', time=self.now, status=SUCCESS_TASK)
        return s


class InventoryTest(Base):
    def test_counts_are_per_project_and_owned(self):
        self.asset('a.x.com')
        self.asset('b.x.com', state='missing')
        self.asset('203.0.113.9', kind='ip')
        self.asset('cdn.net', tier='dependency', kind='root_domain')
        self.asset('cand.x.com', tier='candidate', state='missing')
        self.asset('o.y.com', project=self.other)
        inv = asm_stats(self.p)['inventory']
        self.assertEqual((inv['owned_root'], inv['owned_host'], inv['ip'], inv['dependency']), (1, 2, 1, 1))
        self.assertEqual(inv['states'], {'active': 3, 'missing': 1, 'stale': 0, 'retired': 0})

    def test_review_queue(self):
        self.asset('low.net', tier='candidate', kind='root_domain', confidence=0.2)
        self.asset('mid.net', tier='candidate', kind='root_domain', confidence=0.6)
        self.asset('new.net', tier='candidate', kind='root_domain')
        self.asset('would.net', tier='candidate', kind='root_domain', confidence=0.95,
                   confidence_detail={'would_auto_confirm': True})
        self.asset('o.net', tier='candidate', kind='root_domain', project=self.other)
        self.assertEqual(asm_stats(self.p)['review'], {'candidates': 3, 'would_auto_confirm': 1})


class ChangesTest(Base):
    def test_new_owned_counts_the_last_seven_days(self):
        recent, old = self.asset('recent.x.com'), self.asset('old.x.com')
        self.asset('cand.x.com', tier='candidate')
        Asset.objects.filter(pk=recent.pk).update(first_seen=self.now - timedelta(days=6))
        Asset.objects.filter(pk=old.pk).update(first_seen=self.now - timedelta(days=8))
        Asset.objects.filter(pk=self.root.pk).update(first_seen=self.now - timedelta(days=30))
        self.assertEqual(asm_stats(self.p)['changes'], {'new_owned': 1})


class FindingsTest(Base):
    def test_provisional_checks_are_not_counted_as_findings(self):
        from limes.checks.catalogue import CHECKS
        from startScan.models import RiskCheck
        a = self.asset('a.x.com')
        self.scan()
        before = asm_stats(self.p)['findings']
        RiskCheck.objects.create(asset=a, check_id='leak.supabase_secret_key', status='fail',
                                 severity=CHECKS['leak.supabase_secret_key'].severity, last_checked=self.now)
        invalidate(self.p.id)
        self.assertEqual(asm_stats(self.p)['findings'], before)  # it scores nothing, so the tile must not count it

    def test_counts_only_baseline_findings_on_assessed_assets(self):
        a = self.asset('a.x.com')
        old = self.scan(ago=timedelta(days=3))
        Vulnerability.objects.create(scan_history=old, asset=a, name='gone', severity=4, open_status=True)
        new = self.scan()
        for sev in (4, 3, 3, 1, 0):
            Vulnerability.objects.create(scan_history=new, asset=a, name=f'v{sev}', severity=sev, open_status=True)
        Vulnerability.objects.create(scan_history=new, asset=a, name='closed', severity=4, open_status=False)
        # issues, not rows: the two 'v3' rows are one issue, as in the score
        self.assertEqual(asm_stats(self.p)['findings'], {'critical': 1, 'high': 1, 'medium': 0, 'low': 1})

    def test_waived_issue_leaves_its_tile_and_failed_checks_count(self):
        from startScan.models import IssueWaiver, RiskCheck, TrackedIssue
        a = self.asset('a.x.com')
        s = self.scan()
        for name, sev in (('crit', 4), ('high', 3)):
            Vulnerability.objects.create(scan_history=s, asset=a, name=name, template_id=name, severity=sev, open_status=True)
        RiskCheck.objects.create(asset=a, check_id='web.hsts_missing', status='fail', severity=2, evidence={})
        issue = TrackedIssue.objects.create(project=self.p, asset=a, key='crit', source='finding', severity=4)
        IssueWaiver.objects.create(issue=issue, kind='accepted_risk', reason='r')
        self.assertEqual(asm_stats(self.p)['findings'], {'critical': 0, 'high': 1, 'medium': 1, 'low': 0})

    def test_other_project_findings_never_counted(self):
        o = self.asset('o.y.com', project=self.other)
        Vulnerability.objects.create(scan_history=self.scan('y.com'), asset=o, name='v', severity=4, open_status=True)
        self.assertEqual(asm_stats(self.p)['findings']['critical'], 0)


class RiskTest(Base):
    def test_trend_oldest_first_capped_and_scoped(self):
        for i in range(35):
            ScoreSnapshot.objects.create(project=self.p, date=(self.now - timedelta(days=i)).date(), version='v',
                                         score=900 - i, grade='A')
        ScoreSnapshot.objects.create(project=self.other, date=(self.now + timedelta(days=1)).date(), version='v',
                                     score=1, grade='F')
        trend = asm_stats(self.p)['risk']['trend']
        self.assertEqual(len(trend), 30)
        self.assertEqual((trend[0]['score'], trend[-1]['score']), (871, 900))
        self.assertTrue(trend[0]['date'] < trend[-1]['date'])


class MonitoringTest(Base):
    def test_due_roots_scoped_and_last_auto_ignores_users(self):
        from django.contrib.auth.models import User
        user = User.objects.create_user('u', password='p')
        self.scan(ago=timedelta(days=1), vuln=False)  # automatic (no user)
        self.scan(ago=timedelta(hours=1), vuln=False, user=user)  # manual, newer
        self.scan('y.com', ago=timedelta(minutes=1), vuln=False)  # other project's automatic scan
        mon = asm_stats(self.p)['monitoring']
        self.assertEqual(mon['last_auto'], self.now - timedelta(days=1))
        self.assertEqual(mon['next_due'], [])  # x.com was scanned within its 7-day cadence
        Asset.objects.filter(pk=self.root.pk).update(cadence_tier='crown_jewel')
        Asset.objects.filter(project=self.other).update(cadence_tier='crown_jewel')
        ScanHistory.objects.all().update(start_scan_date=self.now - timedelta(days=2))
        self.assertEqual(asm_stats(self.p)['monitoring']['next_due'], [{'value': 'x.com', 'cadence_tier': 'crown_jewel'}])

    @override_settings(CONTINUOUS_SCANS=False)
    def test_running_and_disabled(self):
        self.scan(vuln=False, status=RUNNING_TASK)
        self.scan('y.com', vuln=False, status=RUNNING_TASK)
        mon = asm_stats(self.p)['monitoring']
        self.assertEqual((mon['enabled'], mon['running']), (False, 1))


class EmptyAndCacheTest(Base):
    def test_empty_project_renders_defaults(self):
        empty = Project.objects.create(name='e', slug='e', insert_date=self.now)
        s = asm_stats(empty)
        self.assertEqual((s['risk']['score'], s['risk']['grade'], s['risk']['trend']), (None, 'N/A', []))
        self.assertEqual(s['inventory']['owned_root'], 0)
        self.assertEqual(s['changes'], {'new_owned': 0})
        self.assertEqual(s['findings'], {'critical': 0, 'high': 0, 'medium': 0, 'low': 0})

    def test_cached_until_invalidated(self):
        with mock.patch('dashboard.stats.asm_stats', wraps=asm_stats) as compute:
            project_stats(self.p)
            project_stats(self.p)
            self.assertEqual(compute.call_count, 1)
            invalidate(self.p.id)
            project_stats(self.p)
            self.assertEqual(compute.call_count, 2)


class TrendVersionTest(Base):
    def test_trend_carries_version(self):
        for i, v in ((1, 'v1'), (0, 'v2')):
            ScoreSnapshot.objects.create(project=self.p, date=(self.now - timedelta(days=i)).date(), version=v,
                                         score=800, grade='B')
        trend = asm_stats(self.p)['risk']['trend']
        self.assertEqual([t['version'] for t in trend], ['v1', 'v2'])


class RecentChangesTest(Base):
    def test_recent_changes_newest_first_and_scoped(self):
        from startScan.models import ChangeEvent
        a = self.asset('a.x.com')
        for i in range(12):
            ev = ChangeEvent.objects.create(project=self.p, kind='issue_new', severity=3, title=f't{i}', asset=a if i == 11 else None)
            ChangeEvent.objects.filter(id=ev.id).update(created_at=self.now - timedelta(minutes=12 - i))
        ChangeEvent.objects.create(project=self.other, kind='issue_new', title='other')
        rows = asm_stats(self.p)['recent_changes']
        self.assertEqual([r['title'] for r in rows], [f't{i}' for i in range(11, 1, -1)])
        self.assertEqual(rows[0]['asset'], 'a.x.com')
        self.assertIsNone(rows[1]['asset'])
        self.assertEqual(set(rows[0]), {'id', 'kind', 'label', 'title', 'severity', 'created_at', 'asset'})
        self.assertEqual(rows[0]['label'], 'New issue')

    def test_every_change_kind_has_a_label(self):
        from dashboard.stats import CHANGE_LABELS
        from limes.alerts.events import KINDS
        self.assertEqual(set(CHANGE_LABELS), set(KINDS))


class OverviewDataTest(Base):
    def test_riskiest_assets_follow_the_waived_score(self):
        from startScan.models import IssueWaiver, TrackedIssue
        a, b, clean = self.asset('a.x.com'), self.asset('b.x.com'), self.asset('c.x.com')
        s = self.scan()
        for asset, name, sev in ((a, 'crit', 4), (a, 'high', 3), (a, 'low', 1), (b, 'med', 2)):
            Vulnerability.objects.create(scan_history=s, asset=asset, name=name, template_id=name, severity=sev,
                                         open_status=True)
        issue = TrackedIssue.objects.create(project=self.p, asset=a, key='crit', source='finding', severity=4)
        IssueWaiver.objects.create(issue=issue, kind='accepted_risk', reason='r')
        rows = asm_stats(self.p)['risky_assets']
        self.assertEqual([r['value'] for r in rows], ['a.x.com', 'b.x.com'])  # clean (950) assets left out
        self.assertEqual((rows[0]['score'], rows[0]['grade'], rows[0]['kind']), (799, 'B', 'hostname'))
        self.assertEqual(rows[0]['counts'], {'critical': 0, 'high': 1, 'medium': 0, 'low': 1})

    def test_grade_band_comes_from_scoring(self):
        from dashboard.stats import grade_band
        self.assertEqual(grade_band(749), {'floor': 600, 'top': 799, 'next': 'A', 'to_next': 51})
        self.assertEqual(grade_band(950), {'floor': 800, 'top': 950, 'next': None, 'to_next': None})
        self.assertIsNone(grade_band(None))

    def test_last_scan_and_empty_project(self):
        self.scan(ago=timedelta(days=2), vuln=False)
        self.scan('y.com', ago=timedelta(minutes=1), vuln=False)
        s = asm_stats(self.p)
        self.assertEqual(s['monitoring']['last_scan'], self.now - timedelta(days=2))
        empty = asm_stats(Project.objects.create(name='e', slug='e', insert_date=self.now))
        self.assertEqual((empty['risky_assets'], empty['monitoring']['last_scan'], empty['risk']['band']), ([], None, None))


class OverviewPageTest(Base):
    XSS = '<img src=x onerror=alert(1)>'

    def setUp(self):
        super().setUp()
        from django.contrib.auth.models import User
        from django.contrib.auth.signals import user_logged_in
        from dashboard.views import on_user_logged_in
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.client.force_login(User.objects.create_user('u', password='p'))

    def page(self, slug):
        self.client.get(f'/{slug}/dashboard/')  # warm-up (lazy prefs creation)
        r = self.client.get(f'/{slug}/dashboard/')
        self.assertEqual(r.status_code, 200)
        return r.content.decode()

    def test_attacker_text_is_escaped_and_raw_shown_only_when_waived(self):
        from startScan.models import ChangeEvent, IssueWaiver, TrackedIssue
        a = self.asset(self.XSS + '.x.com')
        s = self.scan()
        Vulnerability.objects.create(scan_history=s, asset=a, name='n', template_id='t', severity=3, open_status=True)
        ChangeEvent.objects.create(project=self.p, kind='issue_new', severity=3, title='New: ' + self.XSS, asset=a)
        html = self.page('p')
        self.assertNotIn(self.XSS, html)
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;.x.com', html)  # riskiest assets and feed
        self.assertIn('New: &lt;img', html)
        self.assertIn('New issue · &lt;img', html)  # human label, asset still escaped
        self.assertIn('id="dash_monitoring"', html)
        self.assertIn('Last automatic scan: <time', html)  # the test scan has no user
        self.assertNotIn('id="dash_raw"', html)
        IssueWaiver.objects.create(kind='accepted_risk', reason='r', issue=TrackedIssue.objects.create(
            project=self.p, asset=a, key='t', source='finding', severity=3))
        invalidate(self.p.id)
        self.assertIn('id="dash_raw"', self.page('p'))

    def test_empty_project_shows_not_assessed(self):
        Project.objects.create(name='e', slug='e', insert_date=self.now)
        html = self.page('e')
        self.assertIn('No owned assets yet.', html)
        self.assertIn('No changes recorded yet.', html)
        self.assertNotIn('ov-gauge-value', html)


class LiveTrendTest(Base):
    def test_last_point_is_the_live_headline(self):
        from startScan.models import IssueWaiver, TrackedIssue
        a = self.asset('a.x.com')
        Vulnerability.objects.create(scan_history=self.scan(), asset=a, name='crit', template_id='crit', severity=4,
                                     open_status=True)
        today = timezone.localdate()
        for i in (2, 0):  # yesterday-but-one and today's (now stale) snapshot
            ScoreSnapshot.objects.create(project=self.p, date=today - timedelta(days=i), version='limes-score-v3',
                                         score=599, grade='C')
        IssueWaiver.objects.create(issue=TrackedIssue.objects.create(project=self.p, asset=a, key='crit',
                                                                     source='finding', severity=4),
                                   kind='accepted_risk', reason='r')
        risk = asm_stats(self.p)['risk']
        self.assertEqual(risk['score'], 950)
        self.assertEqual([(t['date'], t['score']) for t in risk['trend']],
                         [((today - timedelta(days=2)).isoformat(), 599), (today.isoformat(), 950)])
        ScoreSnapshot.objects.filter(date=today).delete()  # no snapshot yet today: the live point is appended
        self.assertEqual(asm_stats(self.p)['risk']['trend'][-1], {'date': today.isoformat(), 'score': 950,
                                                                   'version': 'limes-score-v3'})
