import os
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.celery_custom_task import LimesTask
from limes.run_urls import RunUrls
from limes.tasks import stages
from scanEngine.models import EngineType
from startScan.models import Asset, IpAddress, ScanHistory
from targetApp.models import Domain


class StageScopeTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.domain = Domain.objects.create(name='x.com', project=self.p, insert_date=timezone.now())
        eng = EngineType.objects.create(engine_name='e', yaml_configuration='{}')
        self.dir = tempfile.mkdtemp()
        self.scan = ScanHistory.objects.create(scan_type=eng, domain=self.domain,
                                               start_scan_date=timezone.now(), results_dir=self.dir)
        self.ctx = {'scan_history_id': self.scan.id, 'results_dir': self.dir, 'track': False}
        for value, tier, ip, auth in (('own.x.com', 'owned_host', '8.8.8.8', False),
                                      ('priv.x.com', 'owned_host', '10.0.0.9', False),
                                      ('dep.x.com', 'dependency', '8.8.4.4', False),
                                      ('cb.x.com', 'co_brand', '1.1.1.1', True)):
            a = Asset.objects.create(project=self.p, kind='hostname', value=value, scope_tier=tier, active_authorized=auth)
            a.ip_addresses.add(IpAddress.objects.create(address=ip))
        p = mock.patch.object(LimesTask, 'notify')
        p.start()
        self.addCleanup(p.stop)

    def seed_urls(self, urls, default=True, status=200):
        store = RunUrls(self.dir)
        for url in urls:
            store.record(url, is_default=default, http_status=status)

    def read(self, name):
        path = os.path.join(self.dir, name)
        return open(path).read().split() if os.path.exists(path) else None

    def test_port_scan_drops_refused_and_co_brand(self):
        with mock.patch.object(stages, 'stream_command', return_value=iter([])) as sc:
            stages.port_scan(hosts=['own.x.com', 'priv.x.com', 'dep.x.com', 'cb.x.com'], ctx=dict(self.ctx))
        self.assertEqual(self.read('input_subdomains_port_scan.txt'), ['own.x.com'])
        sc.assert_called_once()

    def stamp(self, scan_id, *values):
        from limes.tasks import inventory
        for a in Asset.objects.filter(value__in=values):
            inventory._append_source(a, 'discovery', f'scan:{scan_id}')
            a.save()

    def test_port_scan_hosts_default_to_the_hosts_of_this_scan_and_still_pass_the_guard(self):
        self.stamp(self.scan.id, 'own.x.com', 'priv.x.com', 'dep.x.com', 'cb.x.com')
        self.stamp(self.scan.id + 1, 'elsewhere.x.com')  # an asset another scan saw is not this scan's host
        Asset.objects.create(project=self.p, kind='hostname', value='elsewhere.x.com', scope_tier='owned_host')
        with mock.patch.object(stages, 'stream_command', return_value=iter([])):
            stages.port_scan(ctx=dict(self.ctx))
        self.assertEqual(self.read('input_subdomains_port_scan.txt'), ['own.x.com'])

    def test_port_scan_without_hosts_in_the_run_scans_nothing(self):
        with mock.patch.object(stages, 'stream_command') as sc:
            stages.port_scan(ctx=dict(self.ctx))
        sc.assert_not_called()

    def test_fetch_url_starts_from_the_default_urls_of_the_run_only(self):
        self.seed_urls(['https://own.x.com/'])
        self.seed_urls(['https://own.x.com/deep'], default=False)
        self.seed_urls(['https://own.x.com/down'], status=503)
        with mock.patch.object(stages.commands, 'run', return_value=SimpleNamespace(return_code=0, output='')), \
                mock.patch.object(stages, 'stream_command', return_value=iter([])), \
                mock.patch.object(stages, 'run_command'):
            stages.fetch_url(ctx=dict(self.ctx))
        self.assertEqual(self.read('input_endpoints_fetch_url.txt'), ['https://own.x.com/'])

    def test_vulnerability_scan_takes_authorised_co_brand_but_never_candidates_or_rejected(self):
        for value, tier in (('cand.x.com', 'candidate'), ('rej.x.com', 'rejected')):
            a = Asset.objects.create(project=self.p, kind='hostname', value=value, scope_tier=tier)
            a.ip_addresses.add(IpAddress.objects.create(address='9.9.9.9'))
        self.seed_urls([f'https://{h}.x.com/' for h in ('own', 'cand', 'rej', 'cb', 'dep', 'priv')])
        with mock.patch.object(stages.vigil, 'prepare', return_value=('/usr/bin/vigil', {})), \
                mock.patch.object(stages.commands, 'run', return_value=SimpleNamespace(return_code=0, output='')):
            stages.vulnerability_scan(ctx=dict(self.ctx))
        self.assertEqual(self.read('vigil_targets.txt'), ['https://cb.x.com/', 'https://own.x.com/'])

    def test_port_scan_all_refused_never_falls_back(self):
        with mock.patch.object(stages, 'stream_command') as sc, \
                mock.patch.object(stages.inventory, 'run_hostnames') as gs:
            stages.port_scan(hosts=['priv.x.com', 'dep.x.com'], ctx=dict(self.ctx))
        sc.assert_not_called()
        gs.assert_not_called()

    def test_nmap_refuses_out_of_scope_host(self):
        with mock.patch.object(stages, 'run_command') as rc:
            stages.nmap(host='cb.x.com', ports=[443], ctx=dict(self.ctx))
            stages.nmap(host=None, input_file='/tmp/whatever', ports=[443], ctx=dict(self.ctx))
        rc.assert_not_called()

    def test_http_crawl_contact_level(self):
        seen = {}

        def fake_stream(cmd, **kw):  # the input file is removed when the stage ends, so read it while httpx "runs"
            seen['input'] = self.read('httpx_input.txt')
            return iter([])
        with mock.patch.object(stages, 'stream_command', side_effect=fake_stream) as sc:
            stages.http_crawl(urls=['own.x.com', 'priv.x.com', 'dep.x.com', 'cb.x.com'], ctx=dict(self.ctx))
        self.assertEqual(sorted(seen['input']), ['cb.x.com', 'dep.x.com', 'own.x.com'])
        self.assertIsNone(self.read('httpx_input.txt'))  # removed in Python, no `rm`
        sc.assert_called_once()

    def test_vulnerability_scan_attack_level(self):
        self.seed_urls(['https://own.x.com/', 'https://priv.x.com/', 'https://dep.x.com/', 'https://cb.x.com/'])
        with mock.patch.object(stages.vigil, 'prepare', return_value=('/usr/bin/vigil', {})), \
                mock.patch.object(stages.commands, 'run', return_value=SimpleNamespace(return_code=0, output='')) as run:
            stages.vulnerability_scan(ctx=dict(self.ctx))
        self.assertEqual(self.read('vigil_targets.txt'), ['https://cb.x.com/', 'https://own.x.com/'])
        run.assert_called_once()

    def test_vulnerability_scan_that_assessed_nothing_says_so(self):
        # recorded on the SUCCESS activity, so scoring never takes this scan as a baseline
        from limes.definitions import NOTHING_ASSESSED
        stages.vulnerability_scan(ctx=dict(self.ctx))  # the run has no alive URL
        self.assertTrue((stages.vulnerability_scan.error or '').startswith(NOTHING_ASSESSED))
        self.seed_urls(['https://own.x.com/'])
        with mock.patch.object(stages.vigil, 'prepare', return_value=('/usr/bin/vigil', {})), \
                mock.patch.object(stages.commands, 'run', return_value=SimpleNamespace(return_code=0, output='')):
            stages.vulnerability_scan(ctx=dict(self.ctx))  # vigil wrote no report
        self.assertTrue((stages.vulnerability_scan.error or '').startswith(NOTHING_ASSESSED))

    def test_screenshot_contact_level(self):
        self.seed_urls(['https://own.x.com/', 'https://priv.x.com/'])
        with mock.patch.object(stages.commands, 'run', return_value=SimpleNamespace(return_code=0, output='')):
            stages.screenshot(ctx=dict(self.ctx))
        self.assertEqual(self.read('endpoints_alive.txt'), ['https://own.x.com/'])

    def test_fetch_url_attack_level(self):
        with mock.patch.object(stages.commands, 'run', return_value=SimpleNamespace(return_code=0, output='')):
            stages.fetch_url(urls=['https://own.x.com/', 'https://dep.x.com/'], ctx=dict(self.ctx))
        self.assertEqual(self.read('input_endpoints_fetch_url.txt'), ['https://own.x.com/'])

    def test_fetch_url_filters_crawled_output_before_artifact_collection(self):
        def fake_run(argv, output_path=None, **kw):
            if output_path:
                with open(output_path, 'w') as f:
                    f.write('https://own.x.com/a.js\nhttps://dep.x.com/b.js\n')
            return SimpleNamespace(return_code=0, output='')
        with mock.patch.object(stages.commands, 'run', side_effect=fake_run), \
                mock.patch.object(stages.crawl, 'collect_code_artifacts', return_value=([], {})) as cca:
            stages.fetch_url(urls=['https://own.x.com/'], ctx=dict(self.ctx))
        cca.assert_called_once()
        self.assertEqual(sorted(cca.call_args[0][1]), ['https://own.x.com/', 'https://own.x.com/a.js'])

    def test_no_project_means_nothing_is_attacked(self):
        orphan = Domain.objects.create(name='y.com', project=None, insert_date=timezone.now())
        self.scan.domain = orphan
        self.scan.save()
        with mock.patch.object(stages, 'stream_command') as sc:
            stages.port_scan(hosts=['own.x.com'], ctx=dict(self.ctx))
        sc.assert_not_called()

    def test_subdomain_discovery_resolves_even_with_starting_point_path(self):
        ctx = dict(self.ctx, starting_point_path='/app')
        with mock.patch.object(stages.resolution, 'resolve_domain') as rd:
            stages.subdomain_discovery(host='x.com', ctx=ctx)
        rd.assert_called_once()
        self.assertEqual(rd.call_args[0][0], self.domain)
        self.assertEqual(rd.call_args[0][1], self.dir)

    def test_initiate_scan_resolves_before_probing_root(self):
        from limes.tasks import control
        eng = EngineType.objects.create(engine_name='e2', yaml_configuration='{}')
        calls = []
        patches = {
            'send_scan_notif': mock.patch.object(control, 'send_scan_notif'),
            'save_imported_hosts': mock.patch.object(control, 'save_imported_hosts'),
            'save_host': mock.patch.object(control, 'save_host'),
            'probe_url': mock.patch.object(control, 'probe_url', side_effect=lambda *a, **k: calls.append('probe') or (None, False)),
            'resolve_domain': mock.patch.object(control.resolution, 'resolve_domain', side_effect=lambda *a, **k: calls.append('resolve' if k.get('root_only') else 'resolve-all') or 0),
            'build_workflow': mock.patch.object(control, 'build_workflow', return_value=mock.MagicMock(tasks=[])),
            'chain': mock.patch.object(control, 'chain'),
        }
        for p in patches.values():
            p.start()
            self.addCleanup(p.stop)
        res = control.initiate_scan(domain_id=self.domain.id, engine_id=eng.id, scan_history_id=self.scan.id,
                                    results_dir=self.dir)
        self.assertTrue(res.get('success'), res)
        self.assertEqual(calls, ['resolve', 'probe'])

    def test_refusals_are_written_to_scope_refused_file(self):
        with mock.patch.object(stages, 'stream_command', return_value=iter([])), \
                self.assertLogs(stages.logger, level='WARNING') as cm:
            stages.port_scan(hosts=['own.x.com', 'priv.x.com', 'dep.x.com'], ctx=dict(self.ctx))
        with open(os.path.join(self.dir, 'scope_refused.txt')) as f:
            lines = [l.split('\t') for l in f.read().splitlines()]
        self.assertEqual(sorted(l[1] for l in lines), ['dep.x.com', 'priv.x.com'])
        self.assertTrue(all(l[0] == 'port_scan' for l in lines))
        self.assertIn('10.0.0.9', dict((l[1], l[2]) for l in lines)['priv.x.com'])
        self.assertEqual(len([m for m in cm.output if 'Scope' in m]), 1)  # one aggregated warning

    def test_unexpected_tool_blocks_the_scan(self):
        from limes.integrations import vigil
        self.seed_urls(['https://own.x.com/'])
        with mock.patch.object(stages.vigil, 'prepare', side_effect=vigil.VigilError('sqlmap')), \
                mock.patch.object(stages.commands, 'run') as run:
            stages.vulnerability_scan(ctx=dict(self.ctx))  # LimesTask records the failure
        self.assertIn('VigilError', stages.vulnerability_scan.error)
        run.assert_not_called()

    def test_scan_runs_with_resolved_binary_and_restricted_env(self):
        env = {'PATH': '/opt/limes/vigil-bin'}
        self.seed_urls(['https://own.x.com/'])
        with mock.patch.object(stages.vigil, 'prepare', return_value=('/usr/bin/vigil', env)), \
                mock.patch.object(stages.commands, 'run', return_value=SimpleNamespace(return_code=0, output='')) as run:
            stages.vulnerability_scan(ctx=dict(self.ctx))
        self.assertEqual(run.call_args.args[0][0], '/usr/bin/vigil')
        self.assertEqual(run.call_args.kwargs['env'], env)
