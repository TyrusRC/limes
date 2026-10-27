import smtplib
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.core import mail
from django.db import connection
from django.test import Client, TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rolepermissions.roles import assign_role

from dashboard.home import tasks
from dashboard.models import InAppNotification, Project
from dashboard.views import on_user_logged_in
from limes import scoring
from limes.alerts import issues as issue_sync
from remediation import service
from remediation.models import RemediationEvent, RemediationItem, RemediationMessage, RemediationRequest
from startScan.models import Asset, TrackedIssue
from tests.core.test_scoring import Base as ScoringBase

HOSTILE = '<img src=x onerror=alert(1)>'


class Base(TestCase):
    def setUp(self):
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.me = User.objects.create_user('me', password='p')
        self.mate = User.objects.create_user('mate', password='p')
        self.viewer = User.objects.create_user('viewer', password='p')
        for u, role in ((self.me, 'sys_admin'), (self.mate, 'sys_admin'), (self.viewer, 'auditor')):
            assign_role(u, role)
        self.outsider = User.objects.create_user('outsider')
        now = timezone.now()
        self.p = Project.objects.create(name='p1', slug='p1', insert_date=now)
        self.q = Project.objects.create(name='p2', slug='p2', insert_date=now)
        self.a = Asset.objects.create(project=self.p, kind='hostname', value='a.x.com', scope_tier='owned_host')
        self.b = Asset.objects.create(project=self.p, kind='hostname', value='b.x.com', scope_tier='owned_host')
        self.o = Asset.objects.create(project=self.q, kind='hostname', value='o.y.com', scope_tier='owned_host')
        self.i1 = self.issue(self.a, 'web.hsts_missing')
        self.i2 = self.issue(self.b, 'web.hsts_missing')
        self.other = self.issue(self.o, 'web.hsts_missing', self.q)
        self.client = Client()
        self.client.force_login(self.me)

    def issue(self, asset, key, project=None, status='open'):
        return TrackedIssue.objects.create(project=project or self.p, asset=asset, key=key, source='check', severity=2, status=status)

    def make(self, ids=0, **kw):
        kw.setdefault('title', 'Fix HSTS')
        return service.create_request(self.p, self.me, kw.pop('title'), kw.pop('message', 'please'), kw.pop('due_date', None),
                                      [self.i1.id] if ids == 0 else ids, **kw)

    def post(self, url, body, client=None):
        return (client or self.client).post(url, body, content_type='application/json')


class CreateTest(Base):
    def test_creates_items_and_a_timeline_entry(self):
        req = self.make([self.i1.id, self.i2.id], assignee=self.mate)
        self.assertEqual(set(req.items.values_list('issue_id', flat=True)), {self.i1.id, self.i2.id})
        self.assertEqual(req.assignee, self.mate)
        self.assertEqual(list(req.events.values_list('kind', flat=True)), ['created'])

    def test_an_issue_of_another_project_refuses_the_whole_request(self):
        with self.assertRaises(service.RemediationError):
            self.make([self.i1.id, self.other.id])
        self.assertEqual(RemediationRequest.objects.count(), 0)

    def test_only_open_issues_can_be_requested(self):
        fixed = self.issue(self.a, 'web.csp_missing', status='fixed')
        with self.assertRaises(service.RemediationError):
            self.make([fixed.id])

    def test_issue_cap(self):
        ids = list(range(1, service.MAX_ISSUES + 2))
        with self.assertRaisesMessage(service.RemediationError, 'at most 200'):
            self.make(ids)
        for bad in ([], None, 'x', [True], ['1']):
            with self.subTest(bad=bad), self.assertRaises(service.RemediationError):
                self.make(bad)

    def test_text_validation(self):
        for kw in ({'title': ''}, {'title': '   '}, {'title': 'x' * 201}, {'title': 5}, {'message': 'x' * 5001}, {'message': 5},
                   {'due_date': timezone.localdate() - timedelta(days=1)}, {'due_date': '2030-01-01'}):
            with self.subTest(kw=kw), self.assertRaises(service.RemediationError):
                self.make(**kw)

    def test_title_is_one_line(self):
        self.assertEqual(self.make(title='a\r\n b\tc').title, 'a b c')

    def test_assignee_must_be_a_member(self):
        for who in (self.outsider, self.viewer):
            with self.subTest(who=who), self.assertRaises(service.RemediationError):
                self.make(assignee=who)

    def test_external_recipients_are_validated_deduplicated_and_capped(self):
        self.assertEqual(self.make(external=['A@Example.com ', 'a@example.com', ' a@example.com\n', '']).external_emails, ['a@example.com'])
        ok = [f'u{n}@example.com' for n in range(10)]
        self.assertEqual(len(self.make(external=ok).external_emails), 10)
        with self.assertRaisesMessage(service.RemediationError, 'at most 10'):
            self.make(external=ok + ['x@example.com'])
        for bad in ('nope', 'a@b', 'a@example.com\r\nBcc: evil@example.com', 'a@example.com, b@example.com', 'Eve <e@example.com>',
                    '"x y"@example.com', 'a b@example.com', 'a@' + 'x' * 300 + '.com', 5, None and 1):
            with self.subTest(bad=bad), self.assertRaises(service.RemediationError):
                service.emails([bad] if bad is not None else 'str')
        self.assertEqual(RemediationRequest.objects.filter(external_emails__contains=['nope']).count(), 0)


class EmailTest(Base):
    def test_records_email_not_configured_and_sends_nothing(self):
        with override_settings(EMAIL_HOST=''):
            req = self.make(external=['a@example.com'])
        self.assertEqual(req.email_status, 'email not configured')
        self.assertEqual(mail.outbox, [])
        self.assertIn('email not configured', req.events.get(kind='email').text)

    @override_settings(EMAIL_HOST='smtp.invalid', DEFAULT_FROM_EMAIL='limes@example.com')
    def test_sends_one_message_per_recipient_with_a_one_line_subject(self):
        req = self.make(title='Fix\r\nBcc: evil@example.com <script>', message=f'line1\r\nBcc: evil@example.com\n{HOSTILE}\x07',
                        external=['a@example.com', 'b@example.com'])
        self.assertEqual(req.email_status, 'sent')
        self.assertEqual(sorted(m.to[0] for m in mail.outbox), ['a@example.com', 'b@example.com'])
        for m in mail.outbox:
            self.assertEqual(len(m.to), 1)
            self.assertEqual((m.cc, m.bcc, m.extra_headers), ([], [], {}))
            self.assertNotRegex(m.subject, r'[\r\n]')
            self.assertTrue(m.subject.startswith('[Limes] Remediation request: Fix Bcc: evil@example.com'))
            self.assertNotIn('\x07', m.body)

    @override_settings(EMAIL_HOST='smtp.invalid')
    def test_a_mail_failure_keeps_the_request(self):
        with mock.patch('remediation.service.send_mass_mail', side_effect=smtplib.SMTPException('down')):
            req = self.make(external=['a@example.com'])
        self.assertEqual(req.email_status, 'failed')
        self.assertTrue(RemediationRequest.objects.filter(pk=req.pk).exists())

    @override_settings(EMAIL_HOST='smtp.invalid')
    def test_no_recipients_no_mail(self):
        self.make()
        self.assertEqual(mail.outbox, [])


class LifecycleTest(Base):
    def test_status_transitions(self):
        req = self.make()
        with self.assertRaises(service.RemediationError):
            service.set_status(req, self.me, 'active')
        with self.assertRaises(service.RemediationError):
            service.set_status(req, self.me, 'bogus')
        self.assertEqual(service.set_status(req, self.me, 'completed').completed_at is not None, True)
        self.assertIsNone(service.set_status(req, self.me, 'active').completed_at)
        service.set_status(req, self.me, 'archived')
        self.assertEqual(list(req.events.values_list('kind', flat=True)), ['created', 'completed', 'reopened', 'archived'])

    def test_messages_are_capped_and_required(self):
        req = self.make()
        for bad in ('', '  ', 'x' * 5001, None, 5):
            with self.subTest(bad=bad), self.assertRaises(service.RemediationError):
                service.add_message(req, self.me, bad)
        service.add_message(req, self.me, HOSTILE)
        self.assertEqual(RemediationMessage.objects.get().text, HOSTILE)

    def test_overdue_notifies_once_and_only_while_active(self):
        req = self.make(due_date=timezone.localdate())
        later = timezone.now() + timedelta(days=2)
        self.assertEqual(service.notify_overdue(later), 1)
        self.assertEqual(service.notify_overdue(later), 0)
        note = InAppNotification.objects.get()
        self.assertEqual((note.project, note.redirect_link), (self.p, f'/remediation/p1/{req.id}/'))
        done = self.make(due_date=timezone.localdate())
        service.set_status(done, self.me, 'completed')
        self.assertEqual(service.notify_overdue(later), 0)
        self.assertEqual(self.make().due_date, None)
        self.assertEqual(service.notify_overdue(later), 0)

    def test_not_overdue_before_the_due_date(self):
        self.make(due_date=timezone.localdate() + timedelta(days=3))
        self.assertEqual(service.notify_overdue(), 0)

    def test_overdue_request_is_a_task(self):
        req = self.make(due_date=timezone.localdate())
        now = timezone.now() + timedelta(days=2)
        (card,) = [c for c in tasks(self.p, now, set(), self.me) if c['kind'] == 'remediation']
        self.assertEqual(card['url'], f'/remediation/p1/{req.id}/')
        self.assertEqual([c for c in tasks(self.q, now, set(), self.me) if c['kind'] == 'remediation'], [])
        self.assertEqual([c for c in tasks(self.p, timezone.now(), set(), self.me) if c['kind'] == 'remediation'], [])


class AutoCompleteTest(Base):
    def setUp(self):
        super().setUp()
        TrackedIssue.objects.filter(project=self.p).update(source='finding', key='t1')  # a finding is fixed when its asset is assessed without it
        self.i1.refresh_from_db()
    def sync(self, present, project=None):
        data = {self.a.id: dict(present.get('a', {})), self.b.id: dict(present.get('b', {}))}
        with mock.patch('limes.scoring.current_issues', return_value=(data, {self.a.id, self.b.id})):
            return issue_sync.sync_issues(project or self.p)

    def test_completes_when_every_issue_is_fixed(self):
        self.sync({'a': {'t1': 2}, 'b': {'t1': 2}})
        req = self.make([self.i1.id, self.i2.id])
        self.sync({'b': {'t1': 2}})  # a is fixed, b is not
        req.refresh_from_db()
        self.assertEqual(req.status, 'active')
        self.sync({})
        req.refresh_from_db()
        self.assertEqual((req.status, req.completed_at is not None), ('completed', True))
        self.assertEqual(req.events.last().kind, 'completed')

    def test_archived_and_other_projects_requests_are_left_alone(self):
        self.sync({'a': {'t1': 2}, 'b': {'t1': 2}})
        archived = self.make([self.i1.id])
        service.set_status(archived, self.me, 'archived')
        foreign = service.create_request(self.q, self.me, 't', '', None, [self.other.id])
        TrackedIssue.objects.filter(pk=self.other.pk).update(status='fixed')
        self.sync({})
        for r in (archived, foreign):
            r.refresh_from_db()
        self.assertEqual((archived.status, foreign.status), ('archived', 'active'))

    def test_a_sync_failure_in_the_hook_does_not_fail_the_sync(self):
        self.sync({'a': {'t1': 2}})
        with mock.patch('remediation.service.complete_finished', side_effect=RuntimeError('boom')):
            self.sync({})
        self.assertEqual(TrackedIssue.objects.get(pk=self.i1.pk).status, 'fixed')

    def test_a_request_without_items_never_completes(self):
        req = RemediationRequest.objects.create(project=self.p, title='empty')
        self.assertEqual(service.complete_finished(self.p), 0)
        req.refresh_from_db()
        self.assertEqual(req.status, 'active')


class ImpactTest(ScoringBase):
    """The panel is the existing forecast: same function, same numbers, for the same selection."""

    def setUp(self):
        super().setUp()
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.me = User.objects.create_user('me', password='p')
        assign_role(self.me, 'sys_admin')
        self.client = Client()
        self.client.force_login(self.me)
        s = self.scan()
        self.h1, self.h2 = self.host('a.x.com'), self.host('b.x.com')
        self.vuln(s, self.h1, 4, 't1')
        self.vuln(s, self.h2, 3, 't2')
        self.t1 = TrackedIssue.objects.create(project=self.p, asset=self.h1, key='t1', source='finding', severity=4)
        self.t2 = TrackedIssue.objects.create(project=self.p, asset=self.h2, key='t2', source='finding', severity=3)

    def test_detail_and_forecast_endpoint_equal_the_forecast_function(self):
        req = service.create_request(self.p, self.me, 'Fix both', '', None, [self.t1.id, self.t2.id])
        want = scoring.forecast(self.p, [self.t1.id, self.t2.id])
        self.assertNotEqual(want['delta'], 0)
        self.assertEqual(service.impact(req), want)
        got = self.client.get(f'/api/remediation/detail/?project=p&id={req.id}').json()['impact']
        self.assertEqual(got, want)
        api = self.client.post('/api/score_forecast/', {'project': 'p', 'issues': [self.t1.id, self.t2.id]}, content_type='application/json').json()
        self.assertEqual({k: api[k] for k in ('score', 'grade', 'delta')}, want)
        page = self.client.get(f'/remediation/p/{req.id}/').content.decode()
        self.assertIn(f'moves the score to {want["score"]}', page)

    def test_impact_covers_only_the_issues_still_open(self):
        req = service.create_request(self.p, self.me, 'Fix both', '', None, [self.t1.id, self.t2.id])
        TrackedIssue.objects.filter(pk=self.t1.pk).update(status='fixed')
        self.assertEqual(service.impact(req), scoring.forecast(self.p, [self.t2.id]))
        TrackedIssue.objects.filter(pk=self.t2.pk).update(status='fixed')
        self.assertIsNone(service.impact(req))


class PagesTest(Base):
    def test_hostile_text_is_escaped_on_every_page(self):
        req = self.make(title=HOSTILE, message=HOSTILE)
        service.add_message(req, self.me, HOSTILE)
        TrackedIssue.objects.filter(pk=self.i1.pk).update(key=HOSTILE)
        for url in ('/remediation/p1/', f'/remediation/p1/{req.id}/'):
            html = self.client.get(url).content.decode()
            self.assertNotIn(HOSTILE, html, url)
            self.assertIn('&lt;img src=x onerror=alert(1)&gt;', html, url)

    def test_tabs_filter_by_status(self):
        active, done = self.make(title='live one'), self.make(title='done one')
        service.set_status(done, self.me, 'completed')
        html = self.client.get('/remediation/p1/').content.decode()
        self.assertIn('live one', html)
        self.assertNotIn('done one', html)
        self.assertIn('done one', self.client.get('/remediation/p1/?status=completed').content.decode())
        self.assertIn('live one', self.client.get('/remediation/p1/?status=bogus').content.decode())
        self.assertIsNotNone(active)

    def test_list_columns(self):
        self.make([self.i1.id, self.i2.id], title='Cols')
        html = self.client.get('/remediation/p1/').content.decode()
        for needle in ('Title', 'Categories', 'Open issues', 'Impacted assets', 'Last updated', 'Status', '2 of 2', 'Website'):
            self.assertIn(needle, html)

    def test_list_query_count_does_not_grow_with_requests(self):
        def count():
            with CaptureQueriesContext(connection) as c:
                self.assertEqual(self.client.get('/remediation/p1/').status_code, 200)
            return len(c)
        self.make()
        base = count()
        for n in range(12):
            self.make([self.i1.id, self.i2.id], title=f'r{n}')
        self.assertEqual(count(), base)

    def test_api_list_query_count_is_bounded(self):
        def count():
            with CaptureQueriesContext(connection) as c:
                self.assertEqual(self.client.get('/api/remediation/?project=p1').status_code, 200)
            return len(c)
        self.make()
        base = count()
        for n in range(12):
            self.make([self.i1.id, self.i2.id], title=f'r{n}')
        self.assertEqual(count(), base)

    def test_cross_project_ids_are_404_everywhere(self):
        req = self.make()
        for url in (f'/remediation/p2/{req.id}/', '/remediation/nope/', '/remediation/nope/new', '/remediation/nope/waivers'):
            self.assertEqual(self.client.get(url).status_code, 404, url)
        self.assertEqual(self.client.get(f'/api/remediation/detail/?project=p2&id={req.id}').status_code, 404)
        self.assertEqual(self.client.get(f'/api/remediation/detail/?project=p1&id={req.id + 99}').status_code, 404)
        self.assertEqual(self.client.get('/api/remediation/detail/?project=p1&id=abc').status_code, 404)
        self.assertEqual(self.client.get('/api/remediation/?project=nope').status_code, 404)
        for url, body in (('status', {'status': 'completed'}), ('message', {'text': 'hi'})):
            r = self.post(f'/api/remediation/{url}/', {'project': 'p2', 'id': req.id, **body})
            self.assertEqual(r.status_code, 404, url)
        self.assertEqual(RemediationMessage.objects.count(), 0)
        req.refresh_from_db()
        self.assertEqual(req.status, 'active')
        r = self.post('/api/remediation/create/', {'project': 'p2', 'title': 't', 'issues': [self.i1.id]})
        self.assertEqual(r.status_code, 400)  # p1's issue id used under p2
        self.assertEqual(RemediationRequest.objects.count(), 1)
        self.assertEqual(self.post('/api/remediation/create/', {'project': 'nope', 'title': 't', 'issues': [1]}).status_code, 404)

    def test_create_over_http(self):
        r = self.post('/api/remediation/create/', {'project': 'p1', 'title': 'T', 'message': 'm', 'issues': [self.i1.id, self.i2.id],
                                                   'due_date': str(timezone.localdate()), 'assignee': 'mate', 'emails': ['x@example.com']})
        self.assertEqual(r.status_code, 200, r.content)
        req = RemediationRequest.objects.get()
        self.assertEqual((req.assignee, req.external_emails, req.created_by), (self.mate, ['x@example.com'], self.me))
        for bad in ({'assignee': 'viewer'}, {'assignee': 'nobody'}, {'due_date': 'tomorrow'}, {'emails': ['bad']}, {'title': ''}):
            r = self.post('/api/remediation/create/', {'project': 'p1', 'title': 'T', 'issues': [self.i1.id], **bad})
            self.assertEqual(r.status_code, 400, bad)
        self.assertEqual(RemediationRequest.objects.count(), 1)

    def test_status_and_message_over_http_and_detail_payload(self):
        req = self.make()
        self.assertEqual(self.post('/api/remediation/message/', {'project': 'p1', 'id': req.id, 'text': HOSTILE}).status_code, 200)
        self.assertEqual(self.post('/api/remediation/message/', {'project': 'p1', 'id': req.id, 'text': ''}).status_code, 400)
        self.assertEqual(self.post('/api/remediation/status/', {'project': 'p1', 'id': req.id, 'status': 'archived'}).status_code, 200)
        self.assertEqual(self.post('/api/remediation/status/', {'project': 'p1', 'id': req.id, 'status': 'completed'}).status_code, 400)
        d = self.client.get(f'/api/remediation/detail/?project=p1&id={req.id}').json()
        self.assertEqual((d['status'], d['messages'][0]['text'], [i['issue_id'] for i in d['items']]), ('archived', HOSTILE, [self.i1.id]))
        self.assertEqual([e['kind'] for e in d['events']], ['created', 'archived'])

    def test_writes_need_permission_and_csrf_reads_do_not(self):
        req = self.make()
        viewer = Client()
        viewer.force_login(self.viewer)
        self.assertEqual(self.post('/api/remediation/message/', {'project': 'p1', 'id': req.id, 'text': 'x'}, viewer).status_code, 403)
        self.assertEqual(self.post('/api/remediation/create/', {'project': 'p1', 'title': 't', 'issues': [self.i1.id]}, viewer).status_code, 403)
        self.assertEqual(viewer.get(f'/api/remediation/detail/?project=p1&id={req.id}').status_code, 200)
        strict = Client(enforce_csrf_checks=True)
        strict.force_login(self.me)
        for url in ('create', 'status', 'message'):
            self.assertEqual(self.post(f'/api/remediation/{url}/', {'project': 'p1', 'id': req.id}, strict).status_code, 403, url)
        self.assertEqual(Client().get('/api/remediation/?project=p1').status_code, 302)  # login required

    def test_members_lists_only_people_who_can_be_named(self):
        self.assertEqual(self.client.get('/api/members/?project=p1').json(), ['me', 'mate'][::-1] if False else ['mate', 'me'])
        self.assertEqual(self.client.get('/api/members/?project=nope').status_code, 404)

    def test_wizard_and_entry_points_render(self):
        self.assertEqual(self.client.get('/remediation/p1/new').status_code, 200)
        detail = self.client.get(f'/scan/p1/issues/{self.i1.id}/').content.decode()
        self.assertIn(f'/remediation/p1/new?issues={self.i1.id},{self.i2.id}', detail)
        self.assertIn('fc_remediate', self.client.get('/scan/p1/issues').content.decode())
        viewer = Client()
        viewer.force_login(self.viewer)
        self.assertNotIn('Request remediation', viewer.get(f'/scan/p1/issues/{self.i1.id}/').content.decode())

    def test_models_cascade_with_the_issue(self):
        req = self.make()
        self.i1.delete()
        self.assertEqual(RemediationItem.objects.count(), 0)
        self.assertEqual(RemediationEvent.objects.filter(request=req).count(), 1)
