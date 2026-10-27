from unittest import mock

from django.core.cache import cache
from django.contrib.auth.models import User
from django.utils import timezone
from rolepermissions.roles import assign_role

from dashboard.models import InAppNotification
from limes import waivers
from limes.mcp import registry
from remediation import notes
from remediation.models import Note, RemediationMessage
from startScan.models import IssueNote
from tests.core.mcp_base import McpBase
from tests.core.test_remediation import HOSTILE, Base


class NotesBase(Base):
    def setUp(self):
        super().setUp()
        cache.delete_pattern('limes:hourly:note:*')  # the fake Redis outlives tests
        self.req = self.make(assignee=self.mate)
        self.waiver = waivers.create_waiver(self.i1, 'accepted_risk', 'ok', self.mate)

    def create(self, body='hello', kind='request', pk=None, project='p1', client=None):
        pk = pk or {'request': self.req.id, 'issue': self.i1.id, 'waiver': self.waiver.id}[kind]
        return self.post('/api/notes/create/', {'project': project, 'type': kind, 'id': pk, 'body': body}, client)


class NoteApiTest(NotesBase):
    def test_all_three_targets_list_in_order(self):
        for kind in ('request', 'issue', 'waiver'):
            self.assertEqual(self.create(f'one {kind}', kind).status_code, 200)
            self.create(f'two {kind}', kind)
            pk = {'request': self.req.id, 'issue': self.i1.id, 'waiver': self.waiver.id}[kind]
            rows = self.client.get('/api/notes/', {'project': 'p1', 'type': kind, 'id': pk}).json()
            self.assertEqual([r['body'] for r in rows], [f'one {kind}', f'two {kind}'])

    def test_other_project_and_unknown_are_404(self):
        # every target of project p1 asked for through p2, and p2's own ids through p1
        for kind, pk in (('request', self.req.id), ('issue', self.i1.id), ('waiver', self.waiver.id)):
            self.assertEqual(self.create(kind=kind, pk=pk, project='p2').status_code, 404)
            self.assertEqual(self.client.get('/api/notes/', {'project': 'p2', 'type': kind, 'id': pk}).status_code, 404)
        self.assertEqual(self.create(kind='issue', pk=self.other.id).status_code, 404)
        self.assertEqual(self.post('/api/notes/create/', {'project': 'p1', 'type': 'bogus', 'id': 1, 'body': 'x'}).status_code, 404)
        self.assertEqual(self.create(project='nope').status_code, 404)
        self.assertFalse(Note.objects.exists())

    def test_a_viewer_can_read_but_not_write(self):
        self.create('seen')
        c = self.client_class()
        c.force_login(self.viewer)
        self.assertEqual(self.create(client=c).status_code, 403)
        self.assertEqual(len(c.get('/api/notes/', {'project': 'p1', 'type': 'request', 'id': self.req.id}).json()), 1)

    def test_length_cap_and_empty(self):
        self.assertEqual(self.create('x' * notes.MAX_BODY).status_code, 200)
        self.assertEqual(self.create('x' * (notes.MAX_BODY + 1)).status_code, 400)
        self.assertEqual(self.create('   ').status_code, 400)
        self.assertEqual(self.create(['x']).status_code, 400)
        self.assertEqual(Note.objects.count(), 1)

    def test_rate_limit_per_user_and_fails_closed(self):
        with mock.patch.object(notes, 'HOURLY_LIMIT', 2):
            self.assertEqual([self.create().status_code for _ in range(3)], [200, 200, 429])
            mate = self.client_class()
            mate.force_login(self.mate)
            self.assertEqual(self.create(client=mate).status_code, 200)  # another user has their own budget
        cache.delete_pattern('limes:hourly:note:*')
        with mock.patch('limes.intel.ratelimit.take_hourly', return_value=False):  # what a down cache returns
            self.assertEqual(self.create().status_code, 429)
        self.assertEqual(Note.objects.count(), 3)

    def test_delete_only_by_author_inside_the_project(self):
        self.create('mine')
        n = Note.objects.get()
        mate = self.client_class()
        mate.force_login(self.mate)
        self.assertEqual(self.post('/api/notes/delete/', {'project': 'p1', 'note_id': n.id}, mate).status_code, 403)
        self.assertEqual(self.post('/api/notes/delete/', {'project': 'p2', 'note_id': n.id}).status_code, 404)
        self.assertTrue(Note.objects.exists())
        self.assertEqual(self.post('/api/notes/delete/', {'project': 'p1', 'note_id': n.id}).status_code, 200)
        self.assertFalse(Note.objects.exists())
        self.assertEqual(self.post('/api/notes/delete/', {'project': 'p1', 'note_id': n.id}).status_code, 404)

    def test_no_edit_endpoint(self):
        self.create('x')
        n = Note.objects.get()
        self.assertEqual(self.post('/api/notes/', {'project': 'p1', 'note_id': n.id, 'body': 'y'}).status_code, 405)

    def test_older_issue_notes_and_messages_join_the_timeline(self):
        IssueNote.objects.create(issue=self.i1, author=self.me, text='old issue note')
        RemediationMessage.objects.create(request=self.req, author=self.me, text='old message')
        self.create('new', 'issue')
        rows = self.client.get('/api/notes/', {'project': 'p1', 'type': 'issue', 'id': self.i1.id}).json()
        self.assertEqual([(r['body'], r['id'] is None) for r in rows], [('old issue note', True), ('new', False)])
        rows = self.client.get('/api/notes/', {'project': 'p1', 'type': 'request', 'id': self.req.id}).json()
        self.assertEqual([r['body'] for r in rows], ['old message'])


class NoteNotifyAndPagesTest(NotesBase):
    def test_notifies_assignee_without_the_text_and_not_the_author(self):
        self.create('secret body')
        n = InAppNotification.objects.get()
        self.assertIn('mate', n.description)
        self.assertNotIn('secret', n.title + n.description)
        InAppNotification.objects.all().delete()
        mate = self.client_class()
        mate.force_login(self.mate)
        self.create('reply', client=mate)  # the requester (me) is told, the author (mate) is not
        self.assertEqual(InAppNotification.objects.count(), 1)
        self.assertNotIn('mate', InAppNotification.objects.get().description)

    def test_waiver_owner_is_told(self):
        self.create('ping', 'waiver')
        self.assertIn('mate', InAppNotification.objects.get().description)

    def test_pages_escape_note_text_and_show_delete_only_on_own(self):
        self.create(HOSTILE, 'request')
        self.create(HOSTILE, 'issue')
        self.create(HOSTILE, 'waiver')
        mate = self.client_class()
        mate.force_login(self.mate)
        for url in (f'/remediation/p1/{self.req.id}/', f'/scan/p1/issues/{self.i1.id}/', f'/remediation/p1/waivers/{self.waiver.id}/'):
            for c, own in ((self.client, True), (mate, False)):
                r = c.get(url)
                self.assertEqual(r.status_code, 200, url)
                html = r.content.decode()
                self.assertNotIn('<img src=x', html)
                self.assertIn('&lt;img src=x', html)
                self.assertEqual('data-note-delete' in html, own, url)

    def test_waiver_page_of_another_project_is_404(self):
        self.assertEqual(self.client.get(f'/remediation/p2/waivers/{self.waiver.id}/').status_code, 404)


class NoteMcpTest(McpBase):
    def test_list_notes_wraps_text_and_is_scoped(self):
        from remediation import service
        from startScan.models import Asset, TrackedIssue
        a = Asset.objects.create(project=self.p1, kind='hostname', value='a.x.com', scope_tier='owned_host')
        i = TrackedIssue.objects.create(project=self.p1, asset=a, key='web.hsts_missing', source='check', severity=2)
        o = TrackedIssue.objects.create(project=self.p2, asset=Asset.objects.create(project=self.p2, kind='hostname', value='o.y.com', scope_tier='owned_host'),
                                        key='web.hsts_missing', source='check', severity=2)
        Note.objects.create(project=self.p1, target_type='issue', target_id=i.id, author=self.admin, body=HOSTILE)
        spec = registry.load_tools()['list_notes']
        self.assertTrue(registry.annotations(spec)['readOnlyHint'])
        env = self.call('list_notes', project='p1', target_type='issue', target_id=i.id)
        rows = self.data(env)['items']
        self.assertEqual(len(rows), 1)
        self.assertEqual(self.outside_untrusted(env['data']).count(HOSTILE), 0)
        self.assertIn('untrusted_text', rows[0]['text'])
        self.assertEqual(self.err(self.call('list_notes', project='p1', target_type='issue', target_id=o.id)), 'not_found')
