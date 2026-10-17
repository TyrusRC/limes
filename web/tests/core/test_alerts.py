from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from dashboard.models import Project
from limes import scoring
from limes.alerts import events, issues
from startScan.models import Asset, ChangeEvent, RiskCheck, TrackedIssue
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
