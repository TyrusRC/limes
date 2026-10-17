from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from dashboard.models import Project
from limes import scoring
from limes.alerts import events, issues
from limes.tasks import attribution, inventory
from startScan.models import Asset, ChangeEvent, RiskCheck, ScanRun, ScoreSnapshot, TrackedIssue
from tests.core.test_attribution_decisions import DecisionBase
from tests.core.test_scoring import Base


class ImmediacyTest(SimpleTestCase):
    def test_rules(self):
        self.assertFalse(events.is_immediate('issue_new', 'web.csp_missing', 1))
        self.assertFalse(events.is_immediate('issue_new', 't1', 2))
        self.assertTrue(events.is_immediate('issue_regressed', 't1', 3))
        self.assertTrue(events.is_immediate('issue_new', 't1', 3))
        self.assertTrue(events.is_immediate('issue_regressed', 'tls.cert_expiring', 2))
        self.assertTrue(events.is_immediate('issue_new', 'net.exposed_ftp', 2))
        self.assertFalse(events.is_immediate('issue_fixed', 't1', 4))
        self.assertTrue(events.is_immediate('score_dropped', None, None))
        self.assertTrue(events.is_immediate('asset_auto_confirmed', None, None))
        self.assertFalse(events.is_immediate('score_changed', None, None))
        self.assertFalse(events.is_immediate('asset_missing', None, None))


class SyncTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.a = Asset.objects.create(project=self.p, kind='hostname', value='a.x.com', scope_tier='owned_host')

    def sync(self, issues_, assessed=None, project=None):
        assessed = {self.a.id} if assessed is None else assessed
        with mock.patch('limes.scoring.current_issues', return_value=(issues_, assessed)):
            return issues.sync_issues(project or self.p)

    def test_first_sync_is_silent(self):
        self.assertEqual(self.sync({self.a.id: {'t1': 1, 't2': 2, 'web.csp_missing': 1}}), [])
        self.assertEqual(TrackedIssue.objects.filter(status='open').count(), 3)
        self.assertEqual(ChangeEvent.objects.count(), 0)
        self.assertEqual(TrackedIssue.objects.get(key='web.csp_missing').source, 'check')
        self.assertEqual(TrackedIssue.objects.get(key='t1').source, 'finding')

    def test_second_sync_emits_nothing(self):
        data = {self.a.id: {'t1': 1}}
        self.sync(data)
        self.assertEqual(self.sync(data), [])

    def test_new_fixed_regressed(self):
        self.sync({self.a.id: {'t1': 1}})
        (new,) = self.sync({self.a.id: {'t1': 1, 't2': 3}})
        self.assertEqual((new.kind, new.immediate, new.title), ('issue_new', True, 'New high issue t2 on a.x.com'))
        (fixed,) = self.sync({self.a.id: {'t1': 1}})
        self.assertEqual((fixed.kind, fixed.immediate), ('issue_fixed', False))
        self.assertEqual(TrackedIssue.objects.get(key='t2').status, 'fixed')
        (back,) = self.sync({self.a.id: {'t1': 1, 't2': 3}})
        self.assertEqual((back.kind, back.immediate), ('issue_regressed', True))
        self.assertEqual(TrackedIssue.objects.get(key='t2').reopened, 1)

    def test_severity_rise_is_new(self):
        self.sync({self.a.id: {'t1': 1}})
        (e,) = self.sync({self.a.id: {'t1': 3}})
        self.assertEqual((e.kind, e.severity), ('issue_new', 3))

    def test_unassessed_asset_is_not_fixed(self):
        self.sync({self.a.id: {'t1': 1}})
        got = self.sync({self.a.id: {'t2': 1}}, assessed=set())
        self.assertNotIn('issue_fixed', [e.kind for e in got])
        self.assertEqual(TrackedIssue.objects.get(key='t1').status, 'open')

    def test_events_are_per_project(self):
        self.sync({self.a.id: {'t1': 1}})
        other = Project.objects.create(name='q', slug='q', insert_date=timezone.now())
        b = Asset.objects.create(project=other, kind='hostname', value='b.y.com', scope_tier='owned_host')
        self.assertEqual(self.sync({b.id: {'t9': 3}}, assessed={b.id}, project=other), [])
        self.assertEqual(self.sync({b.id: {'t9': 3, 't8': 3}}, assessed={b.id}, project=other)[0].project, other)
        self.assertEqual(list(TrackedIssue.objects.filter(project=self.p).values_list('key', flat=True)), ['t1'])
        self.assertEqual(set(TrackedIssue.objects.filter(project=other).values_list('key', flat=True)), {'t8', 't9'})
        self.assertEqual(ChangeEvent.objects.filter(project=self.p).count(), 0)

    def test_first_sync_with_no_issues_still_counts(self):
        self.assertEqual(self.sync({}), [])
        (e,) = self.sync({self.a.id: {'t1': 3}})
        self.assertEqual((e.kind, e.immediate), ('issue_new', True))

    def test_failed_sync_leaves_no_partial_change(self):
        self.sync({self.a.id: {'t1': 1}})
        with mock.patch('limes.alerts.events.record', side_effect=RuntimeError('boom')):
            with self.assertRaises(RuntimeError):
                self.sync({self.a.id: {'t1': 3}})
        self.assertEqual(TrackedIssue.objects.get(key='t1').severity, 1)
        (e,) = self.sync({self.a.id: {'t1': 3}})
        self.assertEqual(e.kind, 'issue_new')


class CurrentIssuesTest(Base):
    def test_matches_score_inputs(self):
        s = self.scan()
        host = self.host('a.x.com')
        self.vuln(s, host, 3)
        RiskCheck.objects.create(asset=host, check_id='web.csp_missing', status='fail', severity=1)
        got, assessed = scoring.current_issues(self.p)
        self.assertEqual(got, {host.id: {'t1': 3, 'web.csp_missing': 1}})
        self.assertIn(host.id, assessed)


class OtherEventsTest(Base):
    def snap(self, score, grade, date=None):
        return ScoreSnapshot(project=self.p, date=date or timezone.localdate(), version='v', score=score, grade=grade)

    def test_score_event_rules(self):
        f = scoring.score_event
        self.assertEqual(f(self.snap(850, 'A'), self.snap(790, 'B'))[0], 'score_dropped')
        self.assertEqual(f(self.snap(800, 'A'), self.snap(750, 'B'))[0], 'score_dropped')
        self.assertEqual(f(self.snap(940, 'A'), self.snap(880, 'A'))[0], 'score_dropped')
        self.assertEqual(f(self.snap(900, 'A'), self.snap(880, 'A'))[0], 'score_changed')
        self.assertEqual(f(self.snap(880, 'A'), self.snap(900, 'A'))[0], 'score_changed')
        self.assertIsNone(f(None, self.snap(900, 'A')))
        self.assertIsNone(f(self.snap(None, 'A'), self.snap(900, 'A')))
        self.assertIsNone(f(self.snap(900, 'A'), self.snap(None, 'A')))
        self.assertIsNone(f(self.snap(900, 'A'), self.snap(900, 'A')))
        self.assertIn('850 (A)', f(self.snap(850, 'A'), self.snap(790, 'B'))[1])

    def test_snapshot_records_score_event(self):
        a = self.host('a.x.com')
        self.vuln(self.scan(), a, 4)
        ScoreSnapshot.objects.create(project=self.p, date=timezone.localdate() - timedelta(days=1), version='v',
                                     score=950, grade='A')
        scoring.snapshot_scores()
        (e,) = ChangeEvent.objects.filter(kind='score_dropped')
        self.assertTrue(e.immediate)
        scoring.snapshot_scores()
        self.assertEqual(ChangeEvent.objects.count(), 1)

    def test_missing_transition_records_event(self):
        root = Asset.objects.get(value='x.com')
        run = ScanRun.objects.create(project=self.p, root_asset=root, start_scan_date=timezone.now())
        a = inventory.upsert_hostname_asset(self.p, 'a.x.com', parent=root)
        Asset.objects.filter(id=a.id).update(last_seen=run.start_scan_date - timedelta(minutes=1))
        inventory.finalize_lifecycle(run)
        self.assertEqual(ChangeEvent.objects.count(), 0)  # still active, miss count only went up
        inventory.finalize_lifecycle(run)
        inventory.finalize_lifecycle(run)
        (e,) = ChangeEvent.objects.filter(kind='asset_missing')
        self.assertEqual((e.asset_id, e.immediate), (a.id, False))
        inventory.finalize_lifecycle(run)  # no longer active, so not scanned again
        self.assertEqual(ChangeEvent.objects.count(), 1)

    def test_failing_event_loses_neither_snapshot_nor_other_projects(self):
        a = self.host('a.x.com')
        self.vuln(self.scan(), a, 4)
        other = Project.objects.create(name='q', slug='q', insert_date=timezone.now())
        yesterday = timezone.localdate() - timedelta(days=1)
        for proj in (self.p, other):
            ScoreSnapshot.objects.create(project=proj, date=yesterday, version='v', score=950, grade='A')
        real = events.record

        def flaky(project, *args, **kw):
            if project == self.p:
                raise RuntimeError('boom')
            return real(project, *args, **kw)
        # score_event is stubbed so both projects reach record()
        with mock.patch('limes.alerts.events.record', side_effect=flaky), \
                mock.patch('limes.scoring.score_event', return_value=('score_changed', 't')):
            scoring.snapshot_scores()
        today = timezone.localdate()
        self.assertFalse(ScoreSnapshot.objects.filter(project=self.p, date=today).exists())
        self.assertTrue(ScoreSnapshot.objects.filter(project=other, date=today).exists())
        self.assertEqual(list(ChangeEvent.objects.values_list('project_id', flat=True)), [other.id])
        scoring.snapshot_scores()  # next run recovers the lost alert
        self.assertEqual(ChangeEvent.objects.filter(project=self.p, kind='score_dropped').count(), 1)

    def test_failing_event_does_not_stop_lifecycle(self):
        root = Asset.objects.get(value='x.com')
        run = ScanRun.objects.create(project=self.p, root_asset=root, start_scan_date=timezone.now())
        hosts = [inventory.upsert_hostname_asset(self.p, f'{n}.x.com', parent=root) for n in 'ab']
        Asset.objects.filter(id__in=[h.id for h in hosts]).update(
            last_seen=run.start_scan_date - timedelta(minutes=1), missed_count=2)
        with mock.patch('limes.alerts.events.record', side_effect=RuntimeError('boom')):
            inventory.finalize_lifecycle(run)
        self.assertEqual(Asset.objects.filter(id__in=[h.id for h in hosts], state='missing').count(), 2)


class AutoConfirmEventTest(DecisionBase):
    def qualifying(self):
        a = self.cand('ours.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        self.delegate(a)
        return a

    @override_settings(ATTRIBUTION_AUTO_CONFIRM=True)
    def test_auto_confirm_records_event(self):
        a = self.qualifying()
        self.run_all()
        (e,) = ChangeEvent.objects.filter(kind='asset_auto_confirmed')
        self.assertEqual((e.asset_id, e.immediate), (a.id, True))
        self.run_all()
        self.assertEqual(ChangeEvent.objects.count(), 1)

    @override_settings(ATTRIBUTION_AUTO_CONFIRM=False)
    def test_flag_off_records_nothing(self):
        self.qualifying()
        self.run_all()
        self.assertEqual(ChangeEvent.objects.count(), 0)

    @override_settings(ATTRIBUTION_AUTO_CONFIRM=True)
    def test_failing_event_does_not_undo_confirmation(self):
        a = self.qualifying()
        with mock.patch('limes.alerts.events.record', side_effect=RuntimeError('boom')):
            self.assertEqual(self.run_all()['auto_confirmed'], 1)
        self.assertEqual(self.tier(a), 'owned_root')

    @override_settings(ATTRIBUTION_AUTO_CONFIRM=True)
    def test_lost_race_records_nothing(self):
        a = self.qualifying()
        attribution.score_project(self.p)
        real = attribution._qualifying_control

        def reject_after_select(asset, fresh_after):
            Asset.objects.filter(pk=asset.pk).update(scope_tier='rejected')  # a human decided first
            return real(asset, fresh_after)
        with mock.patch.object(attribution, '_qualifying_control', side_effect=reject_after_select):
            self.assertEqual(attribution.apply_decisions(self.p)['auto_confirmed'], 0)
        self.assertEqual(self.tier(a), 'rejected')
        self.assertEqual(ChangeEvent.objects.count(), 0)
