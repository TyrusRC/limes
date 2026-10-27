import logging
from unittest import mock

from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from dashboard.models import Project
from dashboard.views import on_user_logged_in
from limes.alerts import outbound
from startScan.models import AlertIntegration, AlertRule

RULES = '/api/alert_rules/'
INTEG = '/api/alert_integration/'
SECRETS = ('https://hooks.example.com/T0K3N-abc', 'whsec-longsecret99', 'jira-token-ZZZZ-8888', 'https://hooks.slack.com/services/A/B/CCCC')


class Base(TestCase):
    def setUp(self):
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.admin = User.objects.create_user('adm', password='p')
        assign_role(self.admin, 'sys_admin')
        self.auditor = User.objects.create_user('aud', password='p')
        assign_role(self.auditor, 'auditor')
        self.p = Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())
        self.q = Project.objects.create(name='p2', slug='p2', insert_date=timezone.now())
        self.c = APIClient()
        self.c.force_login(self.admin)

    def create(self, project='p1', **kw):
        body = {'project': project, 'name': 'r', 'kinds': ['issue_new'], 'channels': ['in_app']}
        body.update(kw)
        return self.c.post(RULES, body, format='json')

    def save_integ(self, project='p1', **kw):
        body = {'project': project, 'webhook_url': SECRETS[0], 'webhook_secret': SECRETS[1], 'jira_token': SECRETS[2],
                'slack_url': SECRETS[3], 'jira_base_url': 'https://acme.atlassian.net', 'jira_email': 'b@acme.com',
                'jira_project_key': 'sec', 'jira_issue_type': 'Task', 'jira_labels': ['limes']}
        body.update(kw)
        return self.c.put(INTEG, body, format='json')


class RuleApiTest(Base):
    def test_crud(self):
        r = self.create(min_severity=3, tags=['Prod'])
        self.assertEqual(r.status_code, 201, r.content)
        rid = r.json()['id']
        self.assertEqual(r.json()['tags'], ['prod'])
        self.assertEqual(AlertRule.objects.get().created_by, self.admin)
        self.assertEqual(self.c.get(RULES + '?project=p1').json()['results'][0]['id'], rid)
        p = self.c.patch(f'{RULES}{rid}/?project=p1', {'enabled': False, 'channels': ['in_app', 'slack']}, format='json')
        self.assertEqual((p.status_code, p.json()['enabled'], p.json()['kinds']), (200, False, ['issue_new']))
        self.assertEqual(self.c.delete(f'{RULES}{rid}/?project=p1').status_code, 204)
        self.assertFalse(AlertRule.objects.exists())

    def test_validation_errors_are_400_and_duplicate_name_too(self):
        self.assertEqual(self.create(kinds=['bogus']).status_code, 400)
        self.assertEqual(self.create().status_code, 201)
        self.assertEqual(self.create().status_code, 400)
        self.assertEqual(self.c.post(RULES, [1], format='json').status_code, 404)

    def test_cross_project_ids_are_404(self):
        rid = self.create().json()['id']
        other = self.create(project='p2', name='x').json()['id']
        for method, url, body in (('get', f'{RULES}{rid}/?project=p2', None), ('patch', f'{RULES}{rid}/?project=p2', {'enabled': False}),
                                  ('delete', f'{RULES}{rid}/?project=p2', None), ('post', f'{RULES}{rid}/test/?project=p2', {}),
                                  ('get', f'{RULES}{other}/?project=p1', None), ('get', f'{RULES}{rid}/?project=nope', None)):
            r = getattr(self.c, method)(url, body, format='json') if body is not None else getattr(self.c, method)(url)
            self.assertEqual(r.status_code, 404, (method, url))
        self.assertTrue(AlertRule.objects.get(pk=rid).enabled)
        self.assertEqual(AlertRule.objects.count(), 2)
        self.assertEqual([x['id'] for x in self.c.get(RULES + '?project=p2').json()['results']], [other])

    def test_needs_permission(self):
        a = APIClient()
        a.force_login(self.auditor)
        self.assertEqual(a.get(RULES + '?project=p1').status_code, 403)
        self.assertEqual(a.post(RULES, {'project': 'p1'}, format='json').status_code, 403)
        self.assertEqual(a.put(INTEG, {'project': 'p1'}, format='json').status_code, 403)
        self.assertIn(APIClient().get(RULES + '?project=p1').status_code, (301, 302, 401, 403))

    def test_test_send_runs_the_channels_and_reports_per_channel(self):
        rid = self.create(channels=['in_app', 'webhook', 'jira'], kinds=['issue_new']).json()['id']
        AlertIntegration.objects.create(project=self.p)
        r = self.c.post(f'{RULES}{rid}/test/', {'project': 'p1'}, format='json')
        res = r.json()['results']
        self.assertEqual(res['in_app'], 'ok')
        self.assertIn('not configured', res['webhook'])
        self.assertTrue(res['jira'].startswith('skipped'))
        self.assertIn('webhook: not configured', AlertRule.objects.get().last_error)


class IntegrationApiTest(Base):
    def test_secrets_never_come_back(self):
        r = self.save_integ()
        self.assertEqual(r.status_code, 200, r.content)
        for resp in (r, self.c.get(INTEG + '?project=p1')):
            body = resp.content.decode()
            for s in SECRETS:
                self.assertNotIn(s, body)
            self.assertNotIn('T0K3N', body)
            j = resp.json()
            self.assertEqual(j['webhook_secret'], {'set': True, 'last4': '••••et99'})
            self.assertEqual(j['jira_token'], {'set': True, 'last4': '••••8888'})
            self.assertEqual(j['jira_project_key'], 'SEC')
        row = AlertIntegration.objects.get()
        for col in (row.webhook_url_enc, row.webhook_secret_enc, row.jira_token_enc, row.slack_url_enc):
            for s in SECRETS:
                self.assertNotIn(s, col)  # encrypted at rest

    def test_omitted_secret_is_kept_and_empty_clears(self):
        self.save_integ()
        j = self.c.put(INTEG, {'project': 'p1', 'jira_email': 'new@acme.com'}, format='json').json()
        self.assertTrue(j['jira_token']['set'])
        j = self.c.put(INTEG, {'project': 'p1', 'jira_token': ''}, format='json').json()
        self.assertEqual(j['jira_token'], {'set': False, 'last4': None})

    def test_urls_must_be_public_https(self):
        for field in ('webhook_url', 'slack_url', 'jira_base_url'):
            for bad in ('http://hooks.example.com/x', 'https://127.0.0.1/x', 'https://169.254.169.254/', 'https://localhost/x',
                        'https://u:p@hooks.example.com/x', 'file:///etc/passwd'):
                r = self.c.put(INTEG, {'project': 'p1', field: bad}, format='json')
                self.assertEqual(r.status_code, 400, (field, bad))
                self.assertNotIn(bad, r.content.decode() if bad.startswith('https://u') else '')
        self.assertFalse(AlertIntegration.objects.exists())

    def test_bad_fields(self):
        for body in ({'jira_project_key': 'a b'}, {'jira_email': 'nope'}, {'webhook_secret': 'short'}, {'jira_labels': ['x'] * 11},
                     {'jira_issue_type': 'a\nb'}, {'jira_token': 5}):
            self.assertEqual(self.c.put(INTEG, {'project': 'p1', **body}, format='json').status_code, 400, body)

    def test_integrations_are_per_project(self):
        self.save_integ()
        j = self.c.get(INTEG + '?project=p2').json()
        self.assertFalse(j['jira_token']['set'])
        self.assertEqual(j['jira_base_url'], '')
        self.assertEqual(self.c.get(INTEG + '?project=nope').status_code, 404)

    def test_jira_test_creates_one_issue_and_reports_the_key(self):
        self.save_integ()
        with mock.patch.object(outbound, 'request') as req:
            req.return_value.json.return_value = {'key': 'SEC-1'}
            r = self.c.post(INTEG + 'jira_test/', {'project': 'p1'}, format='json')
        self.assertEqual(r.json(), {'status': True, 'key': 'SEC-1'})
        self.assertEqual(req.call_count, 1)
        with mock.patch.object(outbound, 'request', side_effect=outbound.OutboundError('the endpoint answered HTTP 401')):
            r = self.c.post(INTEG + 'jira_test/', {'project': 'p1'}, format='json')
        self.assertEqual((r.status_code, r.json()['message']), (400, 'the endpoint answered HTTP 401'))
        self.assertEqual(self.c.post(INTEG + 'jira_test/', {'project': 'p2'}, format='json').status_code, 400)  # not set up there

    def test_nothing_secret_in_logs_while_saving(self):
        with self.assertLogs(level=logging.DEBUG) as cm:
            logging.getLogger('x').debug('start')
            self.save_integ()
            self.c.get(INTEG + '?project=p1')
        for s in SECRETS:
            self.assertNotIn(s, ' '.join(cm.output))


class PageTest(Base):
    def test_page_renders_without_any_secret_and_is_gated(self):
        self.save_integ()
        AlertRule.objects.create(project=self.p, name='<script>alert(1)</script>', kinds=['issue_new'], channels=['in_app'])
        from django.urls import reverse
        self.client.force_login(self.admin)
        r = self.client.get(reverse('alert_rules_page', args=['p1']))
        self.assertEqual(r.status_code, 200)
        body = r.content.decode()
        for s in SECRETS:
            self.assertNotIn(s, body)
        self.assertNotIn('<script>alert(1)</script>', body)  # rules are drawn from JSON by textContent, not rendered here
        self.client.force_login(self.auditor)
        self.assertEqual(self.client.get(reverse('alert_rules_page', args=['p1'])).status_code, 302)
