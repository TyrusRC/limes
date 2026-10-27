import json
import logging
from unittest import mock

from django.core import mail
from django.test import TestCase, override_settings
from django.utils import timezone

from dashboard.models import InAppNotification, Project
from limes import identity
from limes.alerts import channels, events, outbound, rule_tasks, rules
from startScan.models import AlertIntegration, AlertRule, Asset, TrackedIssue


class Resp:
    def __init__(self, body=None, status=201):
        self.status_code, self._b = status, body or {}

    def json(self):
        return self._b


class Base(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.a = Asset.objects.create(project=self.p, kind='hostname', value='a.x.com', scope_tier='owned_host')
        self.integ = AlertIntegration.objects.create(
            project=self.p, jira_base_url='https://acme.atlassian.net', jira_email='bot@acme.com', jira_project_key='SEC',
            jira_issue_type='Task', jira_labels=['limes', 'bad label!'], jira_token_enc=identity.encrypt('tok-SECRET-1234'),
            webhook_url_enc=identity.encrypt('https://hooks.example.com/T0K3N'), webhook_secret_enc=identity.encrypt('whsec-abcdef12'),
            slack_url_enc=identity.encrypt('https://hooks.slack.com/services/AAA/BBB/CCC'))

    def rule(self, **kw):
        data = {'name': 'r', 'kinds': ['issue_new'], 'channels': ['jira']}
        data.update(kw)
        return AlertRule.objects.create(project=self.p, **rules.clean_rule(data))

    def issue_event(self, title='New high issue t on a.x.com', key='t1'):
        ti = TrackedIssue.objects.create(project=self.p, asset=self.a, key=key, source='check', severity=3)
        ev = events.record(self.p, 'issue_new', title, severity=3, asset=self.a, key=key, detail={'key': key})
        return ti, ev


class JiraTest(Base):
    def test_one_issue_per_tracked_issue_even_if_refired_or_matched_by_two_rules(self):
        ti, ev = self.issue_event()
        r1, r2 = self.rule(name='a'), self.rule(name='b')
        with mock.patch.object(outbound, 'request', return_value=Resp({'key': 'SEC-7'})) as req:
            for _ in range(3):
                self.assertIsNone(rule_tasks.run_channel(self.p, 'jira', [r1, r2], channels.message(ev)))
        self.assertEqual(req.call_count, 1)
        ti.refresh_from_db()
        self.assertEqual(ti.jira_key, 'SEC-7')

    def test_failure_releases_the_claim_so_a_retry_can_create_it(self):
        ti, ev = self.issue_event()
        r = self.rule()
        with mock.patch.object(outbound, 'request', side_effect=outbound.OutboundError('down', transient=True)):
            with self.assertRaises(outbound.OutboundError):
                rule_tasks.run_channel(self.p, 'jira', [r], channels.message(ev))
        ti.refresh_from_db()
        self.assertEqual(ti.jira_key, '')
        with mock.patch.object(outbound, 'request', return_value=Resp({'key': 'SEC-8'})):
            rule_tasks.run_channel(self.p, 'jira', [r], channels.message(ev))
        ti.refresh_from_db()
        self.assertEqual(ti.jira_key, 'SEC-8')

    def test_only_new_issue_events_create_issues(self):
        ti, _ = self.issue_event()
        ev = events.record(self.p, 'issue_fixed', 'Fixed', severity=3, asset=self.a, key='t1', detail={'key': 't1'})
        with mock.patch.object(outbound, 'request') as req:
            channels.send_jira(self.p, [], channels.message(ev))
        req.assert_not_called()

    def test_payload_is_plain_text_capped_and_authenticated(self):
        hostile = '<script>alert(1)</script>\r\nSummary: [x](http://evil) ' + 'A' * 5000
        ti, ev = self.issue_event(title=hostile[:300])
        with mock.patch.object(outbound, 'request', return_value=Resp({'key': 'SEC-9'})) as req:
            channels.send_jira(self.p, [], channels.message(ev))
        args, kw = req.call_args
        self.assertEqual(args[:2], ('post', 'https://acme.atlassian.net/rest/api/3/issue'))
        fields = json.loads(kw['data'])['fields']
        self.assertLessEqual(len(fields['summary']), channels.SUMMARY_MAX)
        self.assertNotIn('\n', fields['summary'])
        self.assertNotIn('\r', fields['summary'])
        for para in fields['description']['content']:  # ADF text nodes: Jira never parses them as markup
            self.assertEqual([n['type'] for n in para['content']], ['text'])
            self.assertLessEqual(len(para['content'][0]['text']), channels.LINE_MAX)
            self.assertNotIn('\n', para['content'][0]['text'])
        self.assertEqual(fields['labels'], ['limes', 'bad-label-'])
        self.assertEqual(fields['project'], {'key': 'SEC'})
        self.assertTrue(kw['headers']['Authorization'].startswith('Basic '))

    def test_answer_without_a_valid_key_is_an_error(self):
        for body in ({}, {'key': '../../etc'}, {'key': 'sec-1'}):
            with mock.patch.object(outbound, 'request', return_value=Resp(body)):
                with self.assertRaises(outbound.OutboundError):
                    channels.create_jira_issue(self.integ, 's', ['l'])

    def test_not_configured(self):
        AlertIntegration.objects.filter(pk=self.integ.pk).update(jira_token_enc='')
        ti, ev = self.issue_event()
        with self.assertRaises(channels.NotConfigured):
            channels.send_jira(self.p, [], channels.message(ev))
        ti.refresh_from_db()
        self.assertEqual(ti.jira_key, '')

    def test_jira_url_is_ssrf_checked_on_send(self):
        AlertIntegration.objects.filter(pk=self.integ.pk).update(jira_base_url='https://127.0.0.1')
        self.integ.refresh_from_db()
        with self.assertRaises(outbound.OutboundError):
            channels.create_jira_issue(self.integ, 's', ['l'])


class EmailTest(Base):
    @override_settings(EMAIL_HOST='')
    def test_not_configured_is_reported_not_raised(self):
        r = self.rule(channels=['email'], email_to=['a@b.com'], kinds=['asset_new'])
        ev = events.record(self.p, 'asset_new', 'New host', asset=self.a)
        err = rule_tasks.run_channel(self.p, 'email', [r], channels.message(ev))
        self.assertIn('not configured', err)
        self.assertEqual(mail.outbox, [])

    @override_settings(EMAIL_HOST='smtp.example.com')
    def test_sends_one_mail_per_recipient_with_a_flat_subject(self):
        r1 = self.rule(name='a', kinds=['asset_new'], channels=['email'], email_to=['a@b.com'])
        r2 = self.rule(name='b', kinds=['asset_new'], channels=['email'], email_to=['c@d.com', 'a@b.com'])
        ev = events.record(self.p, 'asset_new', 'New host\r\nBcc: evil@evil.com', asset=self.a)
        self.assertIsNone(rule_tasks.run_channel(self.p, 'email', [r1, r2], channels.message(ev)))
        self.assertEqual(sorted(tuple(m.to) for m in mail.outbox), [('a@b.com',), ('c@d.com',)])
        for m in mail.outbox:
            self.assertNotIn('\n', m.subject)
            self.assertEqual(m.bcc, [])


class SlackAndInAppTest(Base):
    def test_slack_text_is_escaped_and_capped(self):
        ev = events.record(self.p, 'asset_new', '<!channel> <http://evil|click> & ' + 'x' * 1000, asset=self.a)
        with mock.patch.object(outbound, 'request', return_value=Resp(status=200)) as req:
            channels.send_slack(self.p, [], channels.message(ev))
        text = json.loads(req.call_args.kwargs['data'])['text']
        self.assertNotIn('<', text)
        self.assertNotIn('>', text)
        self.assertIn('&lt;!channel&gt;', text)
        self.assertLessEqual(len(text), 1000)

    def test_slack_without_any_hook_is_not_configured(self):
        AlertIntegration.objects.filter(pk=self.integ.pk).update(slack_url_enc='')
        ev = events.record(self.p, 'asset_new', 't', asset=self.a)
        with self.assertRaises(channels.NotConfigured):
            channels.send_slack(self.p, [], channels.message(ev))

    def test_webhook_is_signed_with_the_project_secret(self):
        ev = events.record(self.p, 'asset_new', 't', asset=self.a)
        with mock.patch.object(outbound, 'request', return_value=Resp(status=200)) as req:
            channels.send_webhook(self.p, [], channels.message(ev))
        kw = req.call_args.kwargs
        from limes.alerts import deliver
        self.assertEqual(kw['headers']['X-Limes-Signature'], deliver.sign(kw['data'], 'whsec-abcdef12'))

    def test_in_app_gets_plain_text(self):
        r = self.rule(channels=['in_app'], name='<b>rule</b>')
        ev = events.record(self.p, 'asset_new', '<img src=x onerror=alert(1)>', asset=self.a)
        channels.send_in_app(self.p, [r], channels.message(ev))
        n = InAppNotification.objects.get()
        self.assertEqual(n.title, '<img src=x onerror=alert(1)>')  # stored as text; the panel renders text only


class NoSecretLeakTest(Base):
    def test_failure_text_and_logs_carry_no_secret(self):
        r = self.rule(channels=['webhook'], kinds=['asset_new'])
        ev = events.record(self.p, 'asset_new', 't', asset=self.a)
        boom = outbound.OutboundError('the request failed (ConnectionError)', transient=False)
        with self.assertLogs(level=logging.DEBUG) as cm, mock.patch.object(outbound, 'request', side_effect=boom):
            logging.getLogger('x').debug('start')
            err = rule_tasks.send_rule_alert.apply(args=(ev.id, 'webhook', [r.id])).get()
        r.refresh_from_db()
        blob = err + r.last_error + ' '.join(cm.output)
        for secret in ('T0K3N', 'whsec-abcdef12', 'tok-SECRET-1234'):
            self.assertNotIn(secret, blob)

    def test_transient_failures_retry_then_record(self):
        r = self.rule(channels=['webhook'], kinds=['asset_new'])
        ev = events.record(self.p, 'asset_new', 't', asset=self.a)
        with mock.patch.object(outbound, 'request', side_effect=outbound.OutboundError('down', transient=True)):
            res = rule_tasks.send_rule_alert.apply(args=(ev.id, 'webhook', [r.id]), retries=rule_tasks.MAX_RETRIES)
        self.assertIn('gave up', res.get())
        r.refresh_from_db()
        self.assertTrue(r.last_error.startswith('webhook: down'))
        with mock.patch.object(outbound, 'request', return_value=Resp(status=200)):
            rule_tasks.send_rule_alert.apply(args=(ev.id, 'webhook', [r.id]))
        r.refresh_from_db()
        self.assertEqual(r.last_error, '')
        self.assertIsNotNone(r.last_sent)
