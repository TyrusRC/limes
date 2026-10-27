from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from dashboard.models import InAppNotification, Project
from limes.alerts import deliver, events, rule_tasks, rules
from startScan.models import AlertRule, Asset, ChangeEvent, ScoreSnapshot, Tag


class Base(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.q = Project.objects.create(name='q', slug='q', insert_date=timezone.now())
        self.a = Asset.objects.create(project=self.p, kind='hostname', value='a.x.com', scope_tier='owned_host')
        self.now = timezone.now()

    def rule(self, project=None, **kw):
        data = {'name': 'r%d' % AlertRule.objects.count(), 'kinds': ['issue_new'], 'channels': ['in_app']}
        data.update(kw)
        fields = rules.clean_rule(data)
        return AlertRule.objects.create(project=project or self.p, created_at=self.now - timedelta(minutes=5), **fields)

    def event(self, kind='issue_new', severity=3, asset=True, title='New high issue t on a.x.com', key=None, project=None, **kw):
        return events.record(project or self.p, kind, title, severity=severity, asset=self.a if asset else None, key=key, **kw)

    def dispatch(self, project=None):
        sent = []
        n = rules.dispatch(project or self.p, enqueue=lambda *a: sent.append(a))
        return n, sent


class CleanRuleTest(SimpleTestCase):
    def bad(self, **kw):
        data = {'name': 'n', 'kinds': ['issue_new'], 'channels': ['in_app']}
        data.update(kw)
        with self.assertRaises(rules.RuleError, msg=str(kw)):
            rules.clean_rule(data)

    def test_rejects(self):
        self.bad(name='')
        self.bad(name='x' * 101)
        self.bad(kinds=[])
        self.bad(kinds=['nope'])
        self.bad(kinds='issue_new')
        self.bad(channels=[])
        self.bad(channels=['sms'])
        self.bad(min_severity=0)
        self.bad(min_severity=5)
        self.bad(min_severity=True)
        self.bad(tags=['Bad Tag!'])
        self.bad(tags=['t'] * 21)
        self.bad(channels=['email'])
        self.bad(channels=['email'], email_to=['not-an-email'])
        self.bad(channels=['email'], email_to=['a@b.com\nbcc: x@y.com'])
        self.bad(channels=['jira'], kinds=['asset_new'])
        self.bad(score_drop_points=0)
        self.bad(score_window_days=91)
        self.bad(enabled='yes')

    def test_normalises(self):
        out = rules.clean_rule({'name': ' n ', 'kinds': ['issue_new', 'asset_new', 'issue_new'], 'channels': ['jira', 'in_app'],
                                'tags': ['Prod', 'prod'], 'score_drop_points': 10})
        self.assertEqual((out['name'], out['kinds'], out['tags'], out['score_window_days']),
                         ('n', ['asset_new', 'issue_new'], ['prod'], 7))


class MatchTest(Base):
    def test_table(self):
        tag = Tag.objects.create(project=self.p, name='prod')
        self.a.tags.add(tag)
        cases = [
            # (rule kwargs, event kwargs, expected)
            ({}, {}, True),
            ({'kinds': ['issue_fixed']}, {}, False),
            ({'min_severity': 3}, {'severity': 3}, True),
            ({'min_severity': 3}, {'severity': 2}, False),
            ({'min_severity': 4}, {'severity': 3}, False),
            ({'min_severity': 3, 'kinds': ['asset_new']}, {'kind': 'asset_new', 'severity': None}, True),  # no severity: not filtered
            ({'tags': ['prod']}, {}, True),
            ({'tags': ['staging', 'prod']}, {}, True),
            ({'tags': ['staging']}, {}, False),
            ({'tags': ['prod'], 'kinds': ['score_dropped']}, {'kind': 'score_dropped', 'severity': None, 'asset': False}, False),
            ({'enabled': False}, {}, False),
        ]
        for rk, ek, want in cases:
            rule = self.rule(**rk)
            ev = self.event(**ek)
            tags = set(ev.asset.tags.values_list('name', flat=True)) if ev.asset_id else set()
            self.assertEqual(rules.matches(rule, ev, tags), want, (rk, ek))

    def test_rule_ignores_history_before_it_existed(self):
        rule = self.rule()
        rule.created_at = timezone.now() + timedelta(minutes=1)
        self.assertFalse(rules.matches(rule, self.event(), set()))

    def test_score_drop_threshold_and_window(self):
        today = timezone.localdate()
        ScoreSnapshot.objects.create(project=self.p, date=today - timedelta(days=5), score=800, grade='B')
        ScoreSnapshot.objects.create(project=self.p, date=today - timedelta(days=20), score=950, grade='A')
        ScoreSnapshot.objects.create(project=self.p, date=today, score=780, grade='B')
        ev = self.event('score_dropped', severity=None, asset=False, detail={'from': 800, 'to': 780})
        for points, window, want in ((20, 7, True), (21, 7, False), (150, 7, False), (150, 30, True), (10, 1, False)):
            rule = self.rule(kinds=['score_dropped'], score_drop_points=points, score_window_days=window)
            self.assertEqual(rules.matches(rule, ev, set()), want, (points, window))
        # without a threshold any score event matches
        self.assertTrue(rules.matches(self.rule(kinds=['score_dropped']), ev, set()))


class DispatchTest(Base):
    def test_dedupes_per_channel_across_rules(self):
        r1 = self.rule(channels=['in_app', 'webhook'])
        r2 = self.rule(channels=['webhook', 'slack'])
        self.rule(channels=['slack'], enabled=False)
        self.rule(kinds=['issue_fixed'], channels=['in_app'])
        ev = self.event(severity=2)  # not immediate: only rules can send it
        n, sent = self.dispatch()
        self.assertEqual(n, 3)
        self.assertEqual(sorted((c, tuple(ids)) for _, c, ids in sent),
                         [('in_app', (r1.id,)), ('slack', (r2.id,)), ('webhook', (r1.id, r2.id))])
        self.assertTrue(all(e == ev.id for e, _, _ in sent))

    def test_claims_once(self):
        self.rule()
        self.event(severity=2)
        self.assertEqual(self.dispatch()[0], 1)
        self.assertEqual(self.dispatch()[0], 0)

    def test_other_projects_rules_and_events_are_apart(self):
        self.rule(project=self.q)
        self.event(severity=2)
        self.assertEqual(self.dispatch()[0], 0)
        self.assertEqual(self.dispatch(self.q)[0], 0)

    def test_no_rules_leaves_events_unclaimed(self):
        ev = self.event(severity=2)
        self.assertEqual(self.dispatch()[0], 0)
        ev.refresh_from_db()
        self.assertIsNone(ev.rules_dispatched_at)

    def test_old_events_are_not_replayed(self):
        self.rule()
        ev = self.event(severity=2)
        ChangeEvent.objects.filter(pk=ev.pk).update(created_at=self.now - deliver.ALERT_WINDOW - timedelta(minutes=1))
        self.assertEqual(self.dispatch()[0], 0)

    def test_enqueue_failure_never_raises(self):
        self.rule()
        self.event(severity=2)

        def boom(*a):
            raise RuntimeError('broker down http://secret')
        self.assertEqual(rules.dispatch(self.p, enqueue=boom), 0)

    def test_always_immediate_event_is_still_delivered_by_default_and_not_twice_in_app(self):
        self.rule(kinds=['score_dropped'], channels=['in_app', 'webhook'])
        ev = self.event('score_dropped', severity=None, asset=False, detail={'to': 1})
        self.assertTrue(ev.immediate)
        chat = mock.Mock()
        with mock.patch('limes.alerts.rule_tasks.send_rule_alert.delay') as delay:
            self.assertEqual(deliver.deliver_immediate(self.p, chat=chat, post=mock.Mock()), 1)
        chat.assert_called_once()
        self.assertEqual(InAppNotification.objects.count(), 1)  # the default one
        self.assertEqual([c.args[1] for c in delay.call_args_list], ['webhook'])  # the rule adds only what was not sent

    def test_no_rules_default_unchanged(self):
        ev = self.event(severity=3)
        chat = mock.Mock()
        with mock.patch('limes.alerts.rule_tasks.send_rule_alert.delay') as delay:
            self.assertEqual(deliver.deliver_immediate(self.p, chat=chat, post=mock.Mock()), 1)
        delay.assert_not_called()
        chat.assert_called_once()
        quiet = self.event(severity=1)
        self.assertFalse(quiet.immediate)
        with mock.patch('limes.alerts.rule_tasks.send_rule_alert.delay'):
            deliver.deliver_immediate(self.p, chat=chat, post=mock.Mock())
        quiet.refresh_from_db()
        self.assertIsNone(quiet.notified_at)  # still left for the digest

    def test_a_rule_sends_a_non_immediate_event_now_without_stealing_the_digest(self):
        self.rule()
        ev = self.event(severity=2)
        with mock.patch('limes.alerts.rule_tasks.send_rule_alert.delay') as delay:
            deliver.deliver_immediate(self.p, chat=mock.Mock(), post=mock.Mock())
        self.assertEqual(delay.call_count, 1)
        ev.refresh_from_db()
        self.assertIsNone(ev.notified_at)
        self.assertIsNone(ev.digested_at)


class TaskResultTest(Base):
    def test_records_success_and_failure_on_the_rule(self):
        r = self.rule(channels=['email'], email_to=['a@b.com'])
        ev = self.event(severity=2)
        with self.settings(EMAIL_HOST=''):
            self.assertIn('not configured', rule_tasks.send_rule_alert.apply(args=(ev.id, 'email', [r.id])).get())
        r.refresh_from_db()
        self.assertTrue(r.last_error.startswith('email: not configured'))
        self.assertIsNone(r.last_sent)
        with self.settings(EMAIL_HOST='smtp.invalid'):
            self.assertIsNone(rule_tasks.send_rule_alert.apply(args=(ev.id, 'email', [r.id])).get())
        r.refresh_from_db()
        self.assertEqual(r.last_error, '')
        self.assertIsNotNone(r.last_sent)
