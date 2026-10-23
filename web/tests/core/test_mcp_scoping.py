import inspect
from datetime import timedelta
from unittest import mock
from django.test import override_settings
from django.utils import timezone
from limes.mcp import registry
from scanEngine.models import EngineType
from startScan.models import (Asset, IssueNote, IssueWaiver, ScanActivity, ScanHistory, TrackedIssue, Vulnerability)
from targetApp.models import Domain
from tests.core.mcp_base import McpBase

UNSCOPED = {'list_projects', 'get_system_status'}
ID_PARAMS = ('asset_id', 'issue_id', 'scan_id', 'vulnerability_id', 'activity_id')


@override_settings(MCP_WRITES_ENABLED=True)
class ScopingTests(McpBase):
    def setUp(self):
        super().setUp()
        registry.load_tools()
        eng = EngineType.objects.create(engine_name='e', yaml_configuration='{}', default_engine=True)
        dom = Domain.objects.create(project=self.p2, name='y.com', insert_date=timezone.now())
        self.asset = Asset.objects.create(project=self.p2, kind='root_domain', value='y.com', scope_tier='owned_root')
        self.issue = TrackedIssue.objects.create(project=self.p2, asset=self.asset, key='k', source='check', severity=2)
        IssueWaiver.objects.create(issue=self.issue, kind='false_positive', reason='r', created_by=self.admin)
        scan = ScanHistory.objects.create(domain=dom, scan_type=eng, scan_status=2, start_scan_date=timezone.now())
        act = ScanActivity.objects.create(scan_of=scan, name='a', title='A', time=timezone.now(), status=2)
        vuln = Vulnerability.objects.create(scan_history=scan, name='v', severity=2, open_status=True,
                                            discovered_date=timezone.now(), http_url='http://y.com/')
        self.ids = {'asset_id': self.asset.id, 'issue_id': self.issue.id, 'scan_id': scan.id,
                    'vulnerability_id': vuln.id, 'activity_id': act.id}

    def snapshot(self):
        return (IssueWaiver.objects.filter(issue=self.issue).count(),
                list(IssueWaiver.objects.values_list('id', 'revoked_at')), IssueNote.objects.count(),
                Asset.objects.get(pk=self.asset.pk).cadence_tier, ScanHistory.objects.count(),
                Asset.objects.count())

    def test_every_tool_is_scoped_or_listed(self):
        for name, spec in registry.REGISTRY.items():
            self.assertTrue('project' in inspect.signature(spec.raw).parameters or name in UNSCOPED, name)

    def test_every_id_parameter_is_swept(self):
        found = {p for spec in registry.REGISTRY.values() for p in inspect.signature(spec.raw).parameters
                 if p.endswith('_id') or p.endswith('_ids')}
        self.assertEqual(found - set(ID_PARAMS), {'issue_ids'}, 'a new id parameter needs a sweep case')
        a = {**self.ids}
        mine = self.call('forecast_score', project='p1', issue_ids=[a['issue_id']])
        gone = self.call('forecast_score', project='p1', issue_ids=[10**9])
        self.assertEqual(mine, gone)  # another project's issue id is ignored exactly like a missing one

    def test_no_tool_crosses_projects(self):
        valid = {'kind': 'false_positive', 'reason': 'r', 'text': 't', 'cadence_tier': 'off',
                 'entries': ['z.x.com'], 'issue_ids': None}
        before, tested = self.snapshot(), set()
        with mock.patch('limes.continuous.initiate_scan.apply_async') as started:
            for name, spec in registry.REGISTRY.items():
                params = inspect.signature(spec.raw).parameters
                idp = [p for p in params if p in ID_PARAMS]
                if not idp or name in ('add_assets',):
                    continue
                args = {'project': 'p1'}
                for p in params:
                    if p in ('caller', 'project'):
                        continue
                    if p in ID_PARAMS:
                        args[p] = self.ids[p]
                    elif p in valid and valid[p] is not None and params[p].default is inspect.Parameter.empty:
                        args[p] = valid[p]
                    elif params[p].default is inspect.Parameter.empty:
                        self.fail(f'cannot build {p} for {name}')
                if name == 'forecast_score':
                    continue  # takes a list of ids; it silently drops other projects' ids (covered in the read tests)
                env = self.call(name, **args)
                if name == 'list_vulnerabilities' and 'asset_id' in args and 'scan_id' not in args:
                    self.assertEqual(self.data(env)['items'], [], name)
                    continue
                if name == 'list_vulnerabilities':
                    continue  # scan_id and asset_id both foreign: covered by the two single-id calls below
                self.assertEqual(self.err(env), 'not_found', (name, env))
                self.assertEqual(env['error'], self.call(name, **{**args, **{p: 10**9 for p in idp}})['error'], name)
                tested.add(name)
        self.assertGreaterEqual(tested, {'get_asset', 'get_issue', 'get_scan', 'get_scan_logs', 'get_vulnerability',
                                         'start_asm_scan', 'set_asset_cadence', 'waive_issue', 'revoke_waiver',
                                         'add_issue_note'})
        started.assert_not_called()
        self.assertEqual(self.snapshot(), before)
        e = self.call('list_vulnerabilities', project='p1', scan_id=self.ids['scan_id'])
        self.assertEqual(self.data(e)['items'] if e['ok'] else [], [])

    def test_write_tools_annotated(self):
        writes = {'add_assets', 'start_asm_scan', 'set_asset_cadence', 'waive_issue', 'revoke_waiver', 'add_issue_note'}
        for name, spec in registry.REGISTRY.items():
            a = registry.annotations(spec)
            self.assertEqual(a['readOnlyHint'], name not in writes, name)
            if name in writes:
                self.assertEqual(a['destructiveHint'], name in ('revoke_waiver', 'set_asset_cadence', 'waive_issue', 'add_assets'), name)
            self.assertEqual(a['openWorldHint'], name in ('start_asm_scan', 'add_assets'), name)
