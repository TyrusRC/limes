"""An MCP token acts as its user, with that user's role in each project."""
from unittest import mock

from django.test import override_settings

import tests.core
from limes.mcp import registry
from memberships.models import ProjectMember
from startScan.models import Asset, IssueNote, TrackedIssue
from tests.core.mcp_base import McpBase


@override_settings(MCP_WRITES_ENABLED=True)
class McpRolesTest(McpBase):
    def setUp(self):
        tests.core.ENABLED = False
        self.addCleanup(setattr, tests.core, 'ENABLED', True)
        super().setUp()
        registry.load_tools()
        self.assertEqual(ProjectMember.objects.count(), 0)
        self.host = Asset.objects.create(project=self.p1, kind='hostname', value='a.x.com', scope_tier='owned_host')
        self.other_host = Asset.objects.create(project=self.p2, kind='hostname', value='b.y.com', scope_tier='owned_host')
        self.issue = TrackedIssue.objects.create(project=self.p1, asset=self.host, key='web.hsts_missing', source='check', severity=2)
        self.issue2 = TrackedIssue.objects.create(project=self.p2, asset=self.other_host, key='web.hsts_missing', source='check', severity=2)

    def member(self, user, role, project=None):
        ProjectMember.objects.create(user=user, project=project or self.p1, role=role)

    def note(self, token, project='p1', issue=None):
        return self.call('add_issue_note', token, project=project, issue_id=(issue or self.issue).id, text='hi')

    def test_read_only_member_reads_but_every_write_tool_is_refused(self):
        self.member(self.tester, 'read_only')
        self.data(self.call('get_project_summary', self.t_tester, project='p1'))  # reading is fine
        calls = {'add_assets': dict(entries=['n.x.com'], reason='r'),
                 'start_asm_scan': dict(asset_id=self.host.id),
                 'set_asset_cadence': dict(asset_id=self.host.id, cadence_tier='off'),
                 'waive_issue': dict(issue_id=self.issue.id, kind='false_positive', reason='r'),
                 'revoke_waiver': dict(issue_id=self.issue.id),
                 'add_issue_note': dict(issue_id=self.issue.id, text='t'),
                 'tag_assets': dict(asset_ids=[self.host.id], add=['t'])}
        self.assertEqual({n for n, s in registry.REGISTRY.items() if s.write}, set(calls))  # a new write tool must be added here
        for name, args in calls.items():
            self.assertEqual(self.err(self.call(name, self.t_tester, project='p1', **args)), 'forbidden', name)
        self.assertEqual(IssueNote.objects.count(), 0)
        self.assertFalse(Asset.objects.filter(value='n.x.com').exists())

    def test_standard_member_can_write_in_its_project_only(self):
        self.member(self.tester, 'standard')
        self.data(self.note(self.t_tester))
        self.assertEqual(IssueNote.objects.count(), 1)
        self.assertEqual(self.err(self.note(self.t_tester, 'p2', self.issue2)), 'not_found')
        self.assertEqual(IssueNote.objects.count(), 1)

    def test_non_member_cannot_read_or_write_and_cannot_tell_the_project_exists(self):
        self.member(self.tester, 'admin', self.p2)
        for tool, args in (('get_project_summary', {}), ('list_assets', {})):
            self.assertEqual(self.err(self.call(tool, self.t_tester, project='p1', **args)), 'not_found')
            self.assertEqual(self.err(self.call(tool, self.t_tester, project='nonexistent', **args)), 'not_found')
        self.assertEqual(self.err(self.note(self.t_tester)), 'not_found')

    def test_list_projects_shows_only_mine(self):
        self.member(self.tester, 'read_only', self.p2)
        got = [p['slug'] for p in self.data(self.call('list_projects', self.t_tester))['items']]
        self.assertEqual(got, ['p2'])
        self.assertEqual(sorted(p['slug'] for p in self.data(self.call('list_projects', self.t_admin))['items']), ['p1', 'p2'])

    def test_role_change_applies_to_the_next_call_of_the_same_token(self):
        self.member(self.tester, 'standard')
        self.data(self.note(self.t_tester))
        ProjectMember.objects.filter(user=self.tester).update(role='read_only')
        self.assertEqual(self.err(self.note(self.t_tester)), 'forbidden')
        ProjectMember.objects.filter(user=self.tester).delete()
        self.assertEqual(self.err(self.note(self.t_tester)), 'not_found')

    def test_global_admin_token_reaches_every_project_and_the_global_role_still_applies(self):
        self.data(self.note(self.t_admin, 'p2', self.issue2))
        self.member(self.aud, 'admin')  # project admin, but the auditor role may not write targets
        self.assertEqual(self.err(self.note(self.t_aud)), 'forbidden')
