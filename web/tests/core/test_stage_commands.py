"""The commands the stages run are argv lists (quoted with shlex.join, executed without a shell), built by the
real stage code; only the process launch is faked."""
import os
import shlex
import tempfile
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.celery_custom_task import LimesTask
from limes.tasks import stages
from scanEngine.models import EngineType
from startScan.models import Asset, IpAddress, ScanHistory
from targetApp.models import Domain


class StageCommandsTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.domain = Domain.objects.create(name='x.com', project=self.p, insert_date=timezone.now())
        eng = EngineType.objects.create(engine_name='e', yaml_configuration='{}')
        self.dir = tempfile.mkdtemp()
        self.scan = ScanHistory.objects.create(scan_type=eng, domain=self.domain, start_scan_date=timezone.now(),
                                               results_dir=self.dir)
        a = Asset.objects.create(project=self.p, kind='hostname', value='own.x.com', scope_tier='owned_host')
        a.ip_addresses.add(IpAddress.objects.create(address='8.8.8.8'))
        patcher = mock.patch.object(LimesTask, 'notify')
        patcher.start()
        self.addCleanup(patcher.stop)

    def ctx(self, **cfg):
        return {'scan_history_id': self.scan.id, 'results_dir': self.dir, 'track': False, 'yaml_configuration': cfg}

    def test_subfinder_argv_and_the_merge_of_the_tools_files(self):
        calls = []

        def fake_run(cmd, **kw):
            calls.append((cmd, kw))
            argv = shlex.split(cmd)
            with open(argv[argv.index('-o') + 1], 'w') as f:
                f.write('b.x.com\na.x.com')  # no trailing newline: must not glue to the next file's first line
        with open(os.path.join(self.dir, 'subdomains_amass.txt'), 'w') as f:
            f.write('c.x.com\na.x.com')
        cfg = {'subdomain_discovery': {'uses_tools': ['subfinder'], 'use_subfinder_config': True, 'timeout': 7, 'threads': 9,
                                       'enable_http_crawl': False}}
        with mock.patch.object(stages, 'run_command', side_effect=fake_run), \
                mock.patch.object(stages, 'get_random_proxy', return_value='http://p:1'), \
                mock.patch.object(stages.resolution, 'resolve_domain'):
            stages.subdomain_discovery(host='x.com', ctx=self.ctx(**cfg))
        self.assertEqual(len(calls), 1)  # subfinder only: cat and sort are Python now
        cmd, kw = calls[0]
        self.assertFalse(kw.get('shell'))
        self.assertEqual(shlex.split(cmd), [
            'subfinder', '-d', 'x.com', '-o', f'{self.dir}/subdomains_subfinder.txt',
            '-config', '/root/.config/subfinder/config.yaml', '-proxy', 'http://p:1', '-timeout', '7', '-t', '9', '-silent'])
        from limes.tasks import inventory
        # every line of every tool's file, once (the old `cat | sort -u`); the missing final newline glues nothing
        self.assertEqual(inventory.run_hostnames(self.p, self.scan.id), ['a.x.com', 'b.x.com', 'c.x.com'])

    def naabu_cmd(self, ports):
        seen = []
        with mock.patch.object(stages, 'stream_command', side_effect=lambda cmd, **kw: seen.append((cmd, kw)) or iter([])):
            stages.port_scan(hosts=['own.x.com'], ctx=self.ctx(port_scan={'ports': ports, 'exclude_ports': ['22', '25']}))
        self.assertEqual(len(seen), 1)
        self.assertFalse(seen[0][1].get('shell'))
        return shlex.split(seen[0][0])

    def test_naabu_argv(self):
        with mock.patch.object(stages, 'get_random_proxy', return_value='http://p:1'):
            argv = self.naabu_cmd(['80', '443'])
        inp = f'{self.dir}/input_subdomains_port_scan.txt'
        self.assertEqual(argv[:7], ['naabu', '-json', '-exclude-cdn', '-list', inp, '-p', '80,443'])
        self.assertIn('-silent', argv[7:])
        self.assertEqual(argv[argv.index('-proxy') + 1], 'http://p:1')
        self.assertEqual(argv[argv.index('-exclude-ports') + 1], '22,25')
        self.assertEqual(self.naabu_cmd(['full'])[5:7], ['-p', '-'])
        self.assertEqual(self.naabu_cmd(['top-100'])[5:7], ['-top-ports', '100'])
        self.assertEqual(self.naabu_cmd(['top-1000'])[5:7], ['-top-ports', '1000'])

    def test_httpx_input_with_a_quote_in_a_url_stays_one_argument(self):
        seen = []
        url = "https://own.x.com/it's;id"
        with mock.patch.object(stages, 'stream_command', side_effect=lambda cmd, **kw: seen.append(cmd) or iter([])):
            stages.http_crawl(urls=[url], ctx=self.ctx())
        argv = shlex.split(seen[0])
        self.assertEqual(argv[argv.index('-u') + 1], url)


class AmassWordlistTest(TestCase):
    def test_only_a_plain_name_of_an_existing_wordlist_is_used(self):
        from limes.pipeline import amass
        d = tempfile.mkdtemp()
        open(os.path.join(d, 'good-list.txt'), 'w').close()
        os.mkdir(os.path.join(d, 'sub.txt'))
        self.assertEqual(amass.wordlist_path('good-list', d), os.path.join(d, 'good-list.txt'))
        for name in ('../good-list', 'a/b', '/etc/passwd', '..', '', 'missing', 'sub', 'good-list\n', 'good list', None, 5):
            self.assertIsNone(amass.wordlist_path(name, d), repr(name))
