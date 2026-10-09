import os
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.celery_custom_task import LimesTask
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

    def read(self, name):
        path = os.path.join(self.dir, name)
        return open(path).read().split() if os.path.exists(path) else None

    def test_port_scan_drops_refused_and_co_brand(self):
        with mock.patch.object(stages, 'stream_command', return_value=iter([])) as sc:
            stages.port_scan(hosts=['own.x.com', 'priv.x.com', 'dep.x.com', 'cb.x.com'], ctx=dict(self.ctx))
        self.assertEqual(self.read('input_subdomains_port_scan.txt'), ['own.x.com'])
        sc.assert_called_once()

    def test_port_scan_all_refused_never_falls_back(self):
        with mock.patch.object(stages, 'stream_command') as sc, \
                mock.patch.object(stages, 'get_subdomains') as gs:
            stages.port_scan(hosts=['priv.x.com', 'dep.x.com'], ctx=dict(self.ctx))
        sc.assert_not_called()
        gs.assert_not_called()

    def test_nmap_refuses_out_of_scope_host(self):
        with mock.patch.object(stages, 'run_command') as rc:
            stages.nmap(host='cb.x.com', ports=[443], ctx=dict(self.ctx))
            stages.nmap(host=None, input_file='/tmp/whatever', ports=[443], ctx=dict(self.ctx))
        rc.assert_not_called()

    def test_http_crawl_contact_level(self):
        # run_command is mocked too: http_crawl ends with `rm <input file>`
        with mock.patch.object(stages, 'stream_command', return_value=iter([])) as sc, \
                mock.patch.object(stages, 'run_command'):
            stages.http_crawl(urls=['own.x.com', 'priv.x.com', 'dep.x.com', 'cb.x.com'], ctx=dict(self.ctx))
        self.assertEqual(sorted(self.read('httpx_input.txt')), ['cb.x.com', 'dep.x.com', 'own.x.com'])
        sc.assert_called_once()

    def test_vulnerability_scan_attack_level(self):
        urls = ['https://own.x.com/', 'https://priv.x.com/', 'https://dep.x.com/', 'https://cb.x.com/']
        with mock.patch.object(stages, 'get_http_urls', return_value=urls), \
                mock.patch.object(stages.commands, 'run', return_value=SimpleNamespace(return_code=0, output='')) as run:
            stages.vulnerability_scan(ctx=dict(self.ctx))
        self.assertEqual(self.read('assay_targets.txt'), ['https://own.x.com/', 'https://cb.x.com/'])
        run.assert_called_once()

    def test_screenshot_contact_level(self):
        urls = ['https://own.x.com/', 'https://priv.x.com/']
        with mock.patch.object(stages, 'get_http_urls', return_value=urls), \
                mock.patch.object(stages.commands, 'run', return_value=SimpleNamespace(return_code=0, output='')):
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
            'save_imported_subdomains': mock.patch.object(control, 'save_imported_subdomains'),
            'save_subdomain': mock.patch.object(control, 'save_subdomain', return_value=(mock.MagicMock(), True)),
            'save_endpoint': mock.patch.object(control, 'save_endpoint', side_effect=lambda *a, **k: calls.append('probe') or (None, False)),
            'resolve_domain': mock.patch.object(control.resolution, 'resolve_domain', side_effect=lambda *a, **k: calls.append('resolve') or 0),
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
