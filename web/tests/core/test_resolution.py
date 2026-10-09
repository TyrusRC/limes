import os
import shutil
import tempfile
from unittest import mock
from types import SimpleNamespace

from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.tasks import resolution
from startScan.models import Asset, IpAddress

FIXTURE = os.path.join(os.path.dirname(__file__), 'fixtures', 'dnsx_sample.jsonl')


class ResolveRootTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='example.com', scope_tier='owned_root')
        self.app = Asset.objects.create(project=self.p, kind='hostname', value='app.example.com',
                                        scope_tier='owned_host', parent=self.root)
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.argvs = []

    def fake_run(self, rc=0, write=True):
        def run(argv, **kw):
            self.kw = kw
            self.argvs.append(argv)
            with open(argv[argv.index('-l') + 1]) as f:
                self.hosts = f.read().split()
            if write:
                shutil.copy(FIXTURE, argv[argv.index('-o') + 1])
            return SimpleNamespace(return_code=rc)
        return run

    def test_records_ips_as_dependencies_and_cname(self):
        n = resolution.resolve_root(self.p, self.root, self.dir, run=self.fake_run())
        self.assertEqual(self.kw.get('timeout'), 1800)
        self.assertEqual(n, 1)                                   # only app.example.com is in inventory
        self.assertEqual(sorted(self.hosts), ['app.example.com', 'example.com'])
        self.app.refresh_from_db()
        self.assertEqual(self.app.cname, 'edge.cdn.net')
        self.assertIsNotNone(self.app.last_resolved_at)
        self.assertEqual(sorted(self.app.ip_addresses.values_list('address', flat=True)),
                         ['2606:2800:220:1::1', '93.184.216.34'])
        ip = Asset.objects.get(project=self.p, kind='ip', value='93.184.216.34')
        self.assertEqual(ip.scope_tier, 'dependency')
        self.assertEqual(ip.sources[0]['source'], 'dns')

    def test_failed_run_records_nothing_and_ignores_stale_output(self):
        resolution.resolve_root(self.p, self.root, self.dir, run=self.fake_run())
        Asset.objects.filter(kind='ip').delete()
        n = resolution.resolve_root(self.p, self.root, self.dir, run=self.fake_run(rc=1, write=False))
        self.assertEqual(n, 0)
        self.assertFalse(Asset.objects.filter(kind='ip').exists())

    def test_runner_exception_is_contained(self):
        def boom(argv, **kw):
            raise OSError('dnsx missing')
        with self.assertLogs('limes.tasks.resolution', level='ERROR'):
            self.assertEqual(resolution.resolve_root(self.p, self.root, self.dir, run=boom), 0)

    def test_record_failure_is_contained(self):
        with mock.patch('limes.tasks.inventory.record_resolution', side_effect=RuntimeError('db')):
            with self.assertLogs('limes.tasks.resolution', level='ERROR'):
                n = resolution.resolve_root(self.p, self.root, self.dir, run=self.fake_run())
        self.assertEqual(n, 0)

    def test_existing_ip_asset_keeps_its_tier(self):
        Asset.objects.create(project=self.p, kind='ip', value='93.184.216.34', scope_tier='owned_host')
        resolution.resolve_root(self.p, self.root, self.dir, run=self.fake_run())
        self.assertEqual(Asset.objects.get(project=self.p, kind='ip', value='93.184.216.34').scope_tier, 'owned_host')

    def test_duplicate_legacy_ip_rows_do_not_crash(self):
        IpAddress.objects.create(address='93.184.216.34')
        IpAddress.objects.create(address='93.184.216.34')
        self.assertEqual(resolution.resolve_root(self.p, self.root, self.dir, run=self.fake_run()), 1)


class StaleIpReplacementTest(ResolveRootTest):
    def runner_with(self, line):
        def run(argv, **kw):
            with open(argv[argv.index('-o') + 1], 'w') as f:
                f.write(line + '\n')
            return SimpleNamespace(return_code=0)
        return run

    def test_new_answer_replaces_stale_private_link(self):
        from limes import scope
        resolution.resolve_root(self.p, self.root, self.dir,
                                run=self.runner_with('{"host":"app.example.com","a":["10.1.2.3"]}'))
        self.assertEqual(scope.may_contact(self.p, ['app.example.com'])[0], [])
        resolution.resolve_root(self.p, self.root, self.dir,
                                run=self.runner_with('{"host":"app.example.com","a":["93.184.216.34"]}'))
        self.assertEqual(list(self.app.ip_addresses.values_list('address', flat=True)), ['93.184.216.34'])
        self.assertEqual(scope.may_contact(self.p, ['app.example.com'])[0], ['app.example.com'])

    def test_unanswered_host_keeps_previous_ips(self):
        resolution.resolve_root(self.p, self.root, self.dir,
                                run=self.runner_with('{"host":"app.example.com","a":["93.184.216.34"]}'))
        resolution.resolve_root(self.p, self.root, self.dir,
                                run=self.runner_with('{"host":"example.com","a":["93.184.216.35"]}'))
        self.assertEqual(list(self.app.ip_addresses.values_list('address', flat=True)), ['93.184.216.34'])


class PerHostContainmentTest(ResolveRootTest):
    def test_one_bad_host_does_not_stop_the_rest(self):
        real = resolution.inventory.record_resolution
        def flaky(asset, record):
            if asset.value == 'example.com':
                raise RuntimeError('boom')
            return real(asset, record)
        run = lambda argv, **kw: (open(argv[argv.index('-o') + 1], 'w').write(
            '{"host":"example.com","a":["93.184.216.35"]}\n{"host":"app.example.com","a":["93.184.216.34"]}\n'),
            SimpleNamespace(return_code=0))[1]
        with mock.patch('limes.tasks.inventory.record_resolution', side_effect=flaky), \
                self.assertLogs('limes.tasks.resolution', level='ERROR') as cm:
            n = resolution.resolve_root(self.p, self.root, self.dir, run=run)
        self.assertEqual(n, 1)
        self.assertIn('example.com', cm.output[0])
        self.assertEqual(list(self.app.ip_addresses.values_list('address', flat=True)), ['93.184.216.34'])
