import logging
from unittest import mock

from django.contrib.auth.models import User
from django.core import mail
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from dashboard.models import Project
from limes import identity
from limes.alerts import channels, events, outbound, rule_tasks, rules
from limes.intel import ratelimit
from scanEngine.models import Notification
from startScan.models import AlertIntegration, AlertRule, Asset
from tests.core.test_alert_api import Base as ApiBase, INTEG, RULES
from tests.core.test_alert_channels import Base as ChBase, Resp


class CapTest(ChBase):
    def setUp(self):
        super().setUp()
        cache.clear()

    def flood(self, n, now=None, channels_=('slack',), **kw):
        self.rule(name='r%d' % AlertRule.objects.count(), kinds=['asset_new'], channels=list(channels_))
        for i in range(n):
            events.record(self.p, 'asset_new', 'host %d' % i, asset=self.a)
        sent = []
        for _ in range(3):  # several dispatch runs in one hour, like the pipeline
            rules.dispatch(self.p, now=now, enqueue=lambda *a: sent.append(a))
        return sent

    @override_settings(ALERT_RULE_PER_HOUR={'in_app': 60, 'email': 30, 'slack': 5, 'webhook': 120, 'jira': 20})
    def test_hourly_cap_per_project_and_channel(self):
        sent = self.flood(40)
        self.assertEqual(len(sent), 5)
        rule = AlertRule.objects.get()
        self.assertEqual(rule.suppressed, 35)
        self.assertIsNotNone(rule.last_suppressed_at)

    @override_settings(ALERT_RULE_PER_HOUR={'in_app': 60, 'email': 30, 'slack': 5, 'webhook': 120, 'jira': 20})
    def test_other_project_and_channel_have_their_own_budget(self):
        self.flood(10)
        q = Project.objects.create(name='q', slug='q', insert_date=timezone.now())
        qa = Asset.objects.create(project=q, kind='hostname', value='b.y.com', scope_tier='owned_host')
        AlertRule.objects.create(project=q, **rules.clean_rule({'name': 'r', 'kinds': ['asset_new'], 'channels': ['slack', 'webhook']}))
        events.record(q, 'asset_new', 'h', asset=qa)
        sent = []
        rules.dispatch(q, enqueue=lambda *a: sent.append(a))
        self.assertEqual(sorted(c for _, c, *_ in sent), ['slack', 'webhook'])

    @override_settings(ALERT_RULE_PER_HOUR={'in_app': 60, 'email': 30, 'slack': 2, 'webhook': 120, 'jira': 20})
    def test_one_summary_in_the_next_window_only(self):
        self.flood(6)
        from datetime import timedelta
        later = timezone.now() + timedelta(hours=1, minutes=1)
        out = []
        rules.dispatch(self.p, now=later, enqueue=lambda *a: out.append(a))
        rules.dispatch(self.p, now=later, enqueue=lambda *a: out.append(a))
        self.assertEqual([(a[0], a[1], a[3]) for a in out], [(None, 'slack', 4)])

    @override_settings(ALERT_RULE_PER_HOUR={'in_app': 60, 'email': 30, 'slack': 5, 'webhook': 120, 'jira': 20})
    def test_summary_message_is_delivered_to_the_channel(self):
        r = self.rule(channels=['webhook'], kinds=['asset_new'])
        with mock.patch.object(outbound, 'request', return_value=Resp(status=200)) as req:
            self.assertIsNone(rule_tasks.send_rule_alert.apply(args=(None, 'webhook', [r.id], 7)).get())
        self.assertIn(b'7 more alert events', req.call_args.kwargs['data'])

    def test_cache_down_fails_closed(self):
        self.rule(kinds=['asset_new'], channels=['slack'])
        events.record(self.p, 'asset_new', 'h', asset=self.a)
        sent = []
        orig = ratelimit.take_hourly

        class Down:
            def add(self, *a, **k):
                raise ConnectionError('redis down')
            incr = get = add
        with mock.patch.object(rules.ratelimit, 'take_hourly', side_effect=lambda *a, **k: orig(*a, cache=Down(), **k)), \
                mock.patch('limes.alerts.rules.cache', Down()):
            rules.dispatch(self.p, enqueue=lambda *a: sent.append(a))
        self.assertEqual(sent, [])


class SlackFallbackTest(ChBase):
    def setUp(self):
        super().setUp()
        Notification.objects.create(send_to_slack=True, slack_hook_url='https://hooks.slack.com/services/GLOBAL/HOOK/1234')
        self.ev = events.record(self.p, 'asset_new', 't', asset=self.a)

    def test_empty_project_column_falls_back_through_outbound(self):
        AlertIntegration.objects.filter(pk=self.integ.pk).update(slack_url_enc='')
        with mock.patch.object(outbound, 'request', return_value=Resp(status=200)) as req:
            channels.send_slack(self.p, [], channels.message(self.ev))
        self.assertEqual(req.call_args.args[1], 'https://hooks.slack.com/services/GLOBAL/HOOK/1234')

    def test_failed_fallback_is_a_failure(self):
        AlertIntegration.objects.filter(pk=self.integ.pk).update(slack_url_enc='')
        r = self.rule(channels=['slack'], kinds=['asset_new'])
        with mock.patch.object(outbound, 'request', side_effect=outbound.OutboundError('down')):
            res = rule_tasks.send_rule_alert.apply(args=(self.ev.id, 'slack', [r.id])).get()
        self.assertEqual(res, 'down')
        r.refresh_from_db()
        self.assertEqual(r.last_error, 'slack: down')
        self.assertIsNone(r.last_sent)

    def test_unreadable_project_secret_never_reroutes(self):
        AlertIntegration.objects.filter(pk=self.integ.pk).update(slack_url_enc='gAAAAA-garbage')
        r = self.rule(channels=['slack'], kinds=['asset_new'])
        with mock.patch.object(outbound, 'request') as req:
            res = rule_tasks.send_rule_alert.apply(args=(self.ev.id, 'slack', [r.id])).get()
        req.assert_not_called()
        self.assertEqual(res, 'secret unreadable — re-enter')
        r.refresh_from_db()
        self.assertEqual(r.last_error, 'slack: secret unreadable — re-enter')

    def test_unreadable_webhook_and_jira_secrets_are_errors_too(self):
        AlertIntegration.objects.filter(pk=self.integ.pk).update(webhook_secret_enc='garbage', jira_token_enc='garbage')
        r = self.rule(channels=['webhook'], kinds=['asset_new'])
        self.assertEqual(rule_tasks.run_channel(self.p, 'webhook', [r], channels.message(self.ev)), channels.UNREADABLE)
        with self.assertRaises(channels.SecretUnreadable):
            channels.create_jira_issue(AlertIntegration.objects.get(pk=self.integ.pk), 's', ['l'])


class ParseAndMaskTest(ChBase):
    def test_non_object_jira_answers_are_an_error_not_a_crash(self):
        for body in ([], 'x', None, 5):
            with mock.patch.object(outbound, 'request', return_value=Resp(body)):
                with self.assertRaises(outbound.OutboundError):
                    channels.create_jira_issue(self.integ, 's', ['l'])

    def test_mask_shows_nothing_of_short_secrets(self):
        for plain in ('abcdefgh', 'x' * 19):
            self.assertEqual(channels.mask(identity.encrypt(plain)), {'set': True, 'last4': None})
        self.assertEqual(channels.mask(identity.encrypt('x' * 16 + 'wxyz')), {'set': True, 'last4': '••••wxyz'})
        self.assertEqual(channels.mask(''), {'set': False, 'last4': None})


class EmailPrivacyTest(ChBase):
    @override_settings(EMAIL_HOST='smtp.example.com')
    def test_one_message_per_recipient(self):
        r1 = self.rule(name='a', kinds=['asset_new'], channels=['email'], email_to=['a@b.com'])
        r2 = self.rule(name='b', kinds=['asset_new'], channels=['email'], email_to=['c@d.com', 'a@b.com'])
        ev = events.record(self.p, 'asset_new', 'h', asset=self.a)
        self.assertIsNone(rule_tasks.run_channel(self.p, 'email', [r1, r2], channels.message(ev)))
        self.assertEqual(sorted(tuple(m.to) for m in mail.outbox), [('a@b.com',), ('c@d.com',)])
        self.assertTrue(all(not m.cc and not m.bcc for m in mail.outbox))


class ApiHardeningTest(ApiBase):
    def test_non_object_put_is_400(self):
        for body in ([1], 'x', 5):
            self.assertEqual(self.c.put(INTEG + '?project=p1', body, format='json').status_code, 400)

    def test_field_caps_match_the_columns(self):
        cases = [('jira_base_url', 'https://' + 'a' * 288 + '.com', 300), ('jira_email', 'a' * 191 + '@acme.com', 200),
                 ('jira_project_key', 'A' * 20, 20), ('jira_issue_type', 'T' * 60, 60)]
        for field, ok, cap in cases:
            self.assertEqual(len(ok), cap, field)
            r = self.c.put(INTEG, {'project': 'p1', field: ok}, format='json')
            self.assertEqual(r.status_code, 200, (field, r.content))
        over = [('jira_base_url', 'https://' + 'a' * 289 + '.com'), ('jira_email', 'a' * 192 + '@acme.com'),
                ('jira_project_key', 'A' * 21), ('jira_issue_type', 'T' * 61)]
        for field, bad in over:
            self.assertEqual(self.c.put(INTEG, {'project': 'p1', field: bad}, format='json').status_code, 400, field)
        self.assertEqual(self.create(name='n' * 100).status_code, 201)
        self.assertEqual(self.create(name='m' * 101).status_code, 400)

    def test_jira_test_survives_garbage_answers_and_leaks_nothing(self):
        self.save_integ()
        with mock.patch.object(outbound, 'request', return_value=Resp([])):
            r = self.c.post(INTEG + 'jira_test/', {'project': 'p1'}, format='json')
        self.assertEqual(r.status_code, 400)
        with mock.patch.object(outbound, 'request', side_effect=RuntimeError('Basic abc jira-token-ZZZZ-8888')):
            r = self.c.post(INTEG + 'jira_test/', {'project': 'p1'}, format='json')
        self.assertEqual((r.status_code, r.json()['message']), (400, 'unexpected error (RuntimeError)'))

    def test_test_sends_are_throttled_per_user(self):
        cache.clear()
        rid = self.create().json()['id']
        codes = [self.c.post(f'{RULES}{rid}/test/', {'project': 'p1'}, format='json').status_code for _ in range(11)]
        self.assertEqual(codes[:10], [200] * 10)
        self.assertEqual(codes[10], 429)
        self.save_integ()
        with mock.patch.object(outbound, 'request', return_value=Resp({'key': 'SEC-1'})):
            codes = [self.c.post(INTEG + 'jira_test/', {'project': 'p1'}, format='json').status_code for _ in range(11)]
        self.assertEqual((codes[9], codes[10]), (200, 429))
        other = APIClient()
        other.force_login(User.objects.create_user('adm2', password='p'))
        assign_role(User.objects.get(username='adm2'), 'sys_admin')
        self.assertEqual(other.post(f'{RULES}{rid}/test/', {'project': 'p1'}, format='json').status_code, 200)
