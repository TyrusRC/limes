import hmac
import json
import tempfile
from datetime import timedelta
from unittest import mock

import requests
from django.conf import settings
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from dashboard.models import InAppNotification, Project
from limes import celery_routing, scoring
from limes.alerts import deliver, digest, events, issues
from limes.checks import network
from limes.definitions import FAILED_TASK, SUCCESS_TASK
from limes.tasks import attribution, control, inventory
from scanEngine.models import EngineType
from targetApp.models import Domain
from startScan.models import (Asset, ChangeEvent, RiskCheck, ScanActivity, ScanHistory, ScanRun, ScoreSnapshot, TrackedIssue,
                              Vulnerability)
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
        self.assertTrue(events.is_immediate('asset_new', 'net.exposed_rdp', None))
        self.assertFalse(events.is_immediate('asset_new', None, None))


class RiskyCheckTest(SimpleTestCase):
    def test_worst_port_then_lowest(self):
        self.assertEqual(network.risky_check([80, 3389, 21]), 'net.exposed_rdp')
        self.assertEqual(network.risky_check([21, 23]), 'net.exposed_telnet')
        self.assertEqual(network.risky_check([445, 3389]), 'net.exposed_smb')  # tie on severity: lowest port
        self.assertIsNone(network.risky_check([80]))


class AssetNewTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.parent = Asset.objects.create(project=self.p, kind='cidr', value='198.51.100.0/24', scope_tier='owned_host')
        self.a = Asset.objects.create(project=self.p, kind='ip', value='198.51.100.7', scope_tier='owned_host',
                                      parent=self.parent)

    def test_plain_and_risky(self):
        ev = events.record_asset_new(self.p, self.a, ports=[80])
        self.assertEqual(ev.kind, 'asset_new')
        self.assertEqual(ev.title, 'New ip 198.51.100.7')
        self.assertFalse(ev.immediate)
        self.assertEqual(ev.detail, {'ports': [80], 'parent': '198.51.100.0/24'})
        ev = events.record_asset_new(self.p, self.a, ports=[80, 3389])
        self.assertEqual(ev.title, 'New ip 198.51.100.7 exposes rdp')
        self.assertTrue(ev.immediate)

    def test_no_parent_and_failure_never_raises(self):
        self.parent.delete()
        self.a.refresh_from_db()
        self.assertEqual(events.record_asset_new(self.p, self.a).detail, {'ports': [], 'parent': None})
        with mock.patch('limes.alerts.events.record', side_effect=RuntimeError('boom')):
            self.assertIsNone(events.record_asset_new(self.p, self.a))


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

    def test_first_sync_of_a_new_root_is_silent(self):
        Asset.objects.create(project=self.p, kind='root_domain', value='x.com', scope_tier='owned_root')
        ip = Asset.objects.create(project=self.p, kind='ip', value='192.0.2.1', scope_tier='owned_host')
        self.sync({self.a.id: {'t1': 1}, ip.id: {'t1': 1}}, assessed={self.a.id, ip.id})
        Asset.objects.create(project=self.p, kind='root_domain', value='y.com', scope_tier='owned_root')
        b = Asset.objects.create(project=self.p, kind='hostname', value='b.y.com', scope_tier='owned_host')
        ip2 = Asset.objects.create(project=self.p, kind='ip', value='192.0.2.2', scope_tier='owned_host')
        old = {self.a.id: {'t1': 1}, ip.id: {'t1': 1}, b.id: {'h1': 3, 'h2': 3, 'h3': 3}}
        everyone = {self.a.id, ip.id, b.id, ip2.id}
        self.assertEqual(self.sync(old, assessed=everyone), [])
        got = self.sync({**old, b.id: {'h1': 3, 'h2': 3, 'h3': 3, 'h4': 3}, ip2.id: {'t2': 3}}, assessed=everyone)
        self.assertEqual(sorted((e.kind, e.asset_id, e.detail['key']) for e in got),
                         sorted([('issue_new', b.id, 'h4'), ('issue_new', ip2.id, 't2')]))

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


class CheckFixedTest(Base):
    """A check-sourced issue is fixed only by its own fresh pass; error, stale or missing leave it open."""
    def setUp(self):
        super().setUp()
        self.h = self.host('a.x.com')
        self.tls = RiskCheck.objects.create(asset=self.h, check_id='tls.cert_expired', status='fail', severity=3)
        RiskCheck.objects.create(asset=self.h, check_id='web.csp_missing', status='pass', severity=1)
        issues.sync_issues(self.p)

    def set_tls(self, status, ago=timedelta(0)):
        RiskCheck.objects.filter(pk=self.tls.pk).update(status=status, last_checked=timezone.now() - ago)

    def test_error_flap_is_neither_fixed_nor_regressed(self):
        self.set_tls('error')
        self.assertEqual(issues.sync_issues(self.p), [])
        self.set_tls('fail')
        self.assertEqual(issues.sync_issues(self.p), [])
        self.assertEqual(TrackedIssue.objects.get(key='tls.cert_expired').status, 'open')

    def test_stale_check_is_not_fixed(self):
        self.scan()  # the root's baseline makes the host assessed regardless of checks
        self.set_tls('fail', ago=timedelta(days=31))
        self.assertEqual(issues.sync_issues(self.p), [])
        self.assertEqual(TrackedIssue.objects.get(key='tls.cert_expired').status, 'open')

    def test_fresh_pass_is_fixed(self):
        self.set_tls('pass')
        (e,) = issues.sync_issues(self.p)
        self.assertEqual((e.kind, e.detail['key']), ('issue_fixed', 'tls.cert_expired'))


class LongKeyTest(Base):
    def test_long_finding_name_syncs_stably(self):
        s = self.scan()
        h = self.host('a.x.com')
        issues.sync_issues(self.p)
        name = 'vulners ' + 'x' * 392
        Vulnerability.objects.create(scan_history=s, asset=h, name=name, template_id=None, severity=3,
                                     http_url='https://h/', open_status=True)
        (e,) = issues.sync_issues(self.p)
        self.assertEqual(e.kind, 'issue_new')
        self.assertLessEqual(len(e.title), 300)
        self.assertEqual(issues.sync_issues(self.p), [])
        (row,) = TrackedIssue.objects.all()
        self.assertLessEqual(len(row.key), 255)
        self.assertEqual(row.key, issues.issue_key(name))
        self.assertNotEqual(issues.issue_key(name), issues.issue_key(name[:-1] + 'y'))
        self.assertEqual(issues.issue_key('t1'), 't1')


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


class DeliverTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.chat = mock.Mock()
        self.post = mock.Mock()

    def ev(self, immediate=True, kind='issue_new', **kw):
        kw.setdefault('title', 't')
        kw.setdefault('created_at', timezone.now())
        return ChangeEvent.objects.create(project=self.p, kind=kind, severity=3, detail={},
                                          immediate=immediate, **kw)

    def run_(self, **kw):
        return deliver.deliver_immediate(self.p, chat=self.chat, post=self.post, **kw)

    def test_sends_immediate_only_oldest_first(self):
        now = timezone.now()
        b = self.ev(title='second', created_at=now)
        a = self.ev(title='first', created_at=now - timedelta(minutes=5))
        d = self.ev(immediate=False)
        self.assertEqual(self.run_(), 2)
        self.assertEqual([c.kwargs['title'] for c in self.chat.call_args_list], ['first', 'second'])
        for e in (a, b, d):
            e.refresh_from_db()
        self.assertIsNotNone(a.notified_at)
        self.assertIsNotNone(b.notified_at)
        self.assertIsNone(d.notified_at)
        self.assertEqual(InAppNotification.objects.count(), 2)

    def test_chat_failure_does_not_log_url(self):
        self.ev()
        self.chat.side_effect = requests.exceptions.ConnectionError('https://hooks.slack.com/services/T0K3N')
        with self.assertLogs('limes.alerts.deliver', level='DEBUG') as cm:
            self.run_()
        self.assertNotIn('T0K3N', '\n'.join(cm.output))

    def test_delivered_events_are_not_resent(self):
        self.ev()
        self.assertEqual(self.run_(), 1)
        self.assertEqual(self.run_(), 0)
        self.assertEqual(self.chat.call_count, 1)

    def test_digested_events_are_not_sent(self):
        e = self.ev()
        e.digested_at = timezone.now()
        e.save()
        self.assertEqual(self.run_(), 0)

    def test_hourly_cap(self):
        for _ in range(12):
            self.ev()
        self.assertEqual(self.run_(), 10)
        self.assertEqual(ChangeEvent.objects.filter(notified_at__isnull=True).count(), 2)
        ChangeEvent.objects.exclude(notified_at__isnull=True).update(notified_at=timezone.now() - timedelta(minutes=30))
        self.assertEqual(self.run_(), 0)
        ChangeEvent.objects.exclude(notified_at__isnull=True).update(
            notified_at=timezone.now() - timedelta(minutes=61))
        self.assertEqual(self.run_(), 2)

    def test_over_cap_events_older_than_window_go_to_digest(self):
        for _ in range(12):
            self.ev()
        self.assertEqual(self.run_(), 10)
        self.assertEqual(self.run_(now=timezone.now() + timedelta(hours=2)), 0)
        self.assertEqual(len(digest._pending(self.p)), 2)

    def test_default_chat_is_queued_not_sent_inline(self):
        self.ev()
        with mock.patch('limes.tasks.notifications.send_notif') as notif:
            deliver.deliver_immediate(self.p, post=self.post)
        notif.delay.assert_called_once_with('t', title='t')
        notif.assert_not_called()

    @override_settings(ALERT_WEBHOOK_URL='https://hook.test/x', ALERT_WEBHOOK_SECRET='s3cr3t')
    def test_webhook_signature_verifies(self):
        self.ev()
        self.run_()
        (call,) = self.post.call_args_list
        data, headers = call.kwargs['data'], call.kwargs['headers']
        self.assertEqual(call.args[0], 'https://hook.test/x')
        self.assertEqual(call.kwargs['timeout'], 5)
        self.assertTrue(hmac.compare_digest(headers['X-Limes-Signature'], deliver.sign(data, 's3cr3t')))
        self.assertEqual(headers['Content-Type'], 'application/json')
        self.assertEqual(json.loads(data)['event'], 'issue_new')
        self.assertNotIn('s3cr3t', data.decode())

    @override_settings(ALERT_WEBHOOK_URL='http://hook.test/x', ALERT_WEBHOOK_SECRET='s')
    def test_http_webhook_refused_by_default(self):
        self.ev()
        self.run_()
        self.post.assert_not_called()
        self.chat.assert_called_once()
        self.ev()
        with override_settings(ALERT_WEBHOOK_ALLOW_HTTP=True):
            self.run_()
        self.post.assert_called_once()

    @override_settings(ALERT_WEBHOOK_URL='https://hook.test/x', ALERT_WEBHOOK_SECRET='s')
    def test_webhook_failure_does_not_block_other_channels(self):
        self.post.side_effect = requests.exceptions.ConnectTimeout()
        e = self.ev()
        self.assertEqual(self.run_(), 1)
        self.chat.assert_called_once()
        self.assertEqual(InAppNotification.objects.count(), 1)
        e.refresh_from_db()
        self.assertIsNotNone(e.notified_at)

    def test_no_webhook_configured(self):
        self.ev()
        with override_settings(ALERT_WEBHOOK_URL='https://hook.test/x', ALERT_WEBHOOK_SECRET=''):
            self.run_()
        with override_settings(ALERT_WEBHOOK_URL='', ALERT_WEBHOOK_SECRET='s'):
            self.ev()
            self.run_()
        self.post.assert_not_called()

    def test_event_claimed_by_another_run_is_not_resent(self):
        t0 = timezone.now() - timedelta(minutes=2)
        self.ev(title='e1', created_at=t0)
        self.ev(title='e2', created_at=t0 + timedelta(seconds=1))
        calls = []

        def chat(msg, title=None):
            calls.append(title)
            if title == 'e1':  # a second worker runs while the first is mid-batch
                deliver.deliver_immediate(self.p, chat=chat, post=self.post)
        self.assertEqual(deliver.deliver_immediate(self.p, chat=chat, post=self.post), 1)
        self.assertEqual(sorted(calls), ['e1', 'e2'])

    def test_event_digested_after_read_is_skipped(self):
        t0 = timezone.now() - timedelta(minutes=2)
        self.ev(title='e1', created_at=t0)
        e2 = self.ev(title='e2', created_at=t0 + timedelta(seconds=1))

        def chat(msg, title=None):
            ChangeEvent.objects.filter(pk=e2.pk).update(digested_at=timezone.now())
        self.chat.side_effect = chat
        self.assertEqual(self.run_(), 1)
        self.assertEqual(self.chat.call_count, 1)
        e2.refresh_from_db()
        self.assertIsNone(e2.notified_at)

    @override_settings(ALERT_WEBHOOK_URL='https://hook.test/x', ALERT_WEBHOOK_SECRET='s')
    def test_webhook_does_not_follow_redirects(self):
        self.ev()
        self.run_()
        self.assertIs(self.post.call_args.kwargs['allow_redirects'], False)

    @override_settings(ALERT_WEBHOOK_URL='https://hook.test/T0K3N', ALERT_WEBHOOK_SECRET='s')
    def test_webhook_failure_log_hides_url(self):
        self.post.side_effect = requests.exceptions.ConnectionError('boom https://hook.test/T0K3N')
        self.ev()
        with self.assertLogs('limes.alerts.deliver', level='WARNING') as cm:
            self.run_()
        out = '\n'.join(cm.output)
        self.assertNotIn('T0K3N', out)
        self.assertIn('ConnectionError', out)

    @override_settings(ALERT_WEBHOOK_URL='https://hook.test/T0K3N', ALERT_WEBHOOK_SECRET='s')
    def test_webhook_error_status_is_logged_without_retry(self):
        self.post.return_value = mock.Mock(status_code=500)
        self.ev()
        with self.assertLogs('limes.alerts.deliver', level='WARNING') as cm:
            self.run_()
        self.assertIn('500', '\n'.join(cm.output))
        self.assertNotIn('T0K3N', '\n'.join(cm.output))
        self.assertEqual(self.post.call_count, 1)

    @override_settings(ALERT_WEBHOOK_URL='https://hook.test/x', ALERT_WEBHOOK_SECRET='s')
    def test_dead_webhook_is_tried_once_per_run(self):
        self.post.side_effect = requests.exceptions.ConnectTimeout()
        for _ in range(3):
            self.ev()
        self.assertEqual(self.run_(), 3)
        self.assertEqual(self.post.call_count, 1)
        self.assertEqual(self.chat.call_count, 3)

    @override_settings(ALERT_WEBHOOK_URL='https://hook.test/x', ALERT_WEBHOOK_SECRET='s')
    def test_chat_failure_does_not_block_webhook(self):
        self.chat.side_effect = RuntimeError('down')
        e = self.ev()
        self.assertEqual(self.run_(), 1)
        self.post.assert_called_once()
        e.refresh_from_db()
        self.assertIsNotNone(e.notified_at)


class DigestTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.chat = mock.Mock()

    def ev(self, project=None, immediate=False, **kw):
        kw.setdefault('title', 't')
        return ChangeEvent.objects.create(project=project or self.p, kind='issue_fixed', severity=2, detail={},
                                          immediate=immediate, created_at=timezone.now(), **kw)

    def asset(self, value, tier, age_hours=1):
        return Asset.objects.create(project=self.p, kind='subdomain', value=value, scope_tier=tier,
                                    first_seen=timezone.now() - timedelta(hours=age_hours))

    def test_digest_includes_undigested_events_and_counts(self):
        fixed = self.ev(title='fixed one')
        capped = self.ev(title='capped one', immediate=True)
        done = self.ev(title='already sent', immediate=True, notified_at=timezone.now())
        self.asset('a.example.com', 'owned_host')
        self.asset('b.example.com', 'owned_root')
        self.asset('old.example.com', 'owned_host', age_hours=48)
        self.asset('c.example.net', 'candidate')
        msg = digest.build_digest(self.p)
        for text in ('fixed one', 'capped one', '2 new owned assets', '1 new candidate'):
            self.assertIn(text, msg)
        self.assertNotIn('already sent', msg)
        self.assertEqual(digest.send_digest(chat=self.chat), {'projects': 1, 'sent': 1})
        self.assertEqual(self.chat.call_count, 1)
        self.assertEqual(InAppNotification.objects.count(), 1)
        for e in (fixed, capped, done):
            e.refresh_from_db()
        self.assertIsNotNone(fixed.digested_at)
        self.assertIsNotNone(capped.digested_at)
        self.assertIsNone(done.digested_at)
        self.assertEqual(deliver.deliver_immediate(self.p, chat=self.chat, post=mock.Mock()), 0)

    def test_second_run_resends_nothing(self):
        self.ev()
        self.assertEqual(digest.send_digest(chat=self.chat)['sent'], 1)
        self.assertEqual(digest.send_digest(chat=self.chat)['sent'], 0)
        self.assertEqual(self.chat.call_count, 1)

    def test_event_notified_between_read_and_claim_is_skipped(self):
        e = self.ev(immediate=True)
        real = digest._pending

        def stale(project):
            rows = list(real(project))
            ChangeEvent.objects.filter(pk=e.pk).update(notified_at=timezone.now())
            return rows
        with mock.patch.object(digest, '_pending', stale):
            self.assertEqual(digest.send_digest(chat=self.chat)['sent'], 0)
        e.refresh_from_db()
        self.assertIsNone(e.digested_at)

    def test_long_digest_is_bounded_and_fully_claimed(self):
        for i in range(40):
            self.ev(title='change number %d %s' % (i, 'x' * 20))
        self.asset('a.example.com', 'owned_host')
        digest.send_digest(chat=self.chat)
        self.assertEqual(self.chat.call_count, 1)
        msg = self.chat.call_args.args[0]
        self.assertLessEqual(len(msg), 1900)
        self.assertIn('and 15 more', msg)
        self.assertIn('1 new owned asset', msg)
        self.assertEqual(ChangeEvent.objects.filter(digested_at__isnull=False).count(), 40)

    def test_chat_failure_does_not_log_url(self):
        self.ev()
        boom = mock.Mock(side_effect=requests.exceptions.ConnectionError('https://hooks.slack.com/services/T0K3N'))
        with self.assertLogs('limes.alerts.digest', level='DEBUG') as cm:
            digest.send_digest(chat=boom)
        self.assertNotIn('T0K3N', '\n'.join(cm.output))

    def test_empty_project_sends_nothing(self):
        self.assertIsNone(digest.build_digest(self.p))
        self.assertEqual(digest.send_digest(chat=self.chat), {'projects': 1, 'sent': 0})
        self.chat.assert_not_called()

    def test_digest_is_per_project(self):
        q = Project.objects.create(name='q', slug='q', insert_date=timezone.now())
        self.ev(title='mine')
        self.ev(project=q, title='theirs')
        self.assertEqual(digest.send_digest(chat=self.chat), {'projects': 2, 'sent': 2})
        msgs = [c.args[0] for c in self.chat.call_args_list]
        self.assertEqual(len(msgs), 2)
        for m in msgs:
            self.assertNotEqual('mine' in m, 'theirs' in m)


class WiringTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.domain = Domain.objects.create(name='example.com', project=self.p, insert_date=timezone.now())
        eng = EngineType.objects.create(engine_name='e', yaml_configuration='')
        self.scan = ScanHistory.objects.create(
            scan_type=eng, domain=self.domain, start_scan_date=timezone.now(), results_dir=tempfile.mkdtemp())

    def report(self, failed=False, sync=None):
        ctx = {'scan_history_id': self.scan.id}
        control.start_scan_run(self.domain, self.scan, 'full', ctx)
        if failed:
            ScanActivity.objects.create(name='x', title='x', time=timezone.now(),
                                        status=FAILED_TASK, scan_of=self.scan)
        with mock.patch.object(control, 'send_scan_notif'), \
                mock.patch('limes.alerts.issues.sync_issues', new=sync or mock.Mock()) as s, \
                mock.patch('limes.alerts.deliver.deliver_immediate') as d:
            control.report.run(ctx=ctx)
        return s, d

    def test_successful_report_syncs_and_delivers(self):
        s, d = self.report()
        s.assert_called_once_with(self.p)
        d.assert_called_once_with(self.p)

    def test_time_limit_in_alerts_keeps_notification_and_cache(self):
        from celery.exceptions import SoftTimeLimitExceeded
        with mock.patch('dashboard.stats.invalidate') as inv, \
                mock.patch.object(control, 'send_scan_notif') as notif, \
                mock.patch('limes.alerts.issues.sync_issues'), \
                mock.patch('limes.alerts.deliver.deliver_immediate', side_effect=SoftTimeLimitExceeded):
            ctx = {'scan_history_id': self.scan.id}
            control.start_scan_run(self.domain, self.scan, 'full', ctx)
            with self.assertLogs('limes.tasks', level='WARNING'):
                control.report.run(ctx=ctx)  # must not raise: a re-raise re-runs report via link_error
        inv.assert_called_once()
        notif.delay.assert_called_once()

    def test_sync_error_still_delivers(self):
        s, d = self.report(sync=mock.Mock(side_effect=RuntimeError('x')))
        d.assert_called_once_with(self.p)

    def test_failed_scan_neither(self):
        s, d = self.report(failed=True)
        s.assert_not_called()
        d.assert_not_called()

    def test_sync_error_does_not_break_report(self):
        s, d = self.report(sync=mock.Mock(side_effect=RuntimeError('x')))
        run = ScanRun.objects.get()
        self.assertEqual(run.status, SUCCESS_TASK)

    def test_snapshot_scores_delivers(self):
        with mock.patch('limes.alerts.deliver.deliver_immediate') as d:
            scoring.snapshot_scores()
        d.assert_called_once_with(self.p)

    def test_beat_and_routing(self):
        self.assertEqual(settings.CELERY_BEAT_SCHEDULE['send-digest']['task'], 'send_digest')
        self.assertEqual(settings.CELERY_BEAT_SCHEDULE['send-digest']['schedule'], 86400.0)
        self.assertEqual(celery_routing.TASK_PLAN['send_digest'], (celery_routing.ORCHESTRATE, 15 * celery_routing.MIN))
        self.assertIn('limes.alerts.digest', settings.CELERY_IMPORTS)


class TelegramTest(TestCase):
    def test_markdown_specials_are_escaped_and_text_is_a_param(self):
        from limes import common_func
        from scanEngine.models import Notification
        Notification.objects.create(send_to_telegram=True, telegram_bot_token='tok', telegram_bot_chat_id='42')
        with mock.patch.object(common_func.requests, 'get') as get:
            common_func.send_telegram_message('New issue net.exposed_redis on *a* `b` [c]&d=1')
        (call,) = get.call_args_list
        self.assertEqual(call.kwargs['params']['text'], r'New issue net.exposed\_redis on \*a\* \`b\` \[c]&d=1')
        self.assertEqual(call.kwargs['params']['parse_mode'], 'Markdown')
        self.assertNotIn('net.exposed', call.args[0])
