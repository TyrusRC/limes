import shlex
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase

from limes.common_func import get_nmap_argv, get_output_file_name, is_valid_nmap_command

OUT = '/usr/src/scan_results/x.com_7/' + 'a.x.com_' + get_output_file_name(7, 'nmap.xml')  # contains '#7_'


class NmapArgvTest(SimpleTestCase):
    """The REAL builder and validator, no stubs: the argv must be one nmap can run."""

    def build(self, **kw):
        return get_nmap_argv(None, host='a.x.com', ports='80,8443', output_file=OUT, **kw)

    def test_default_command_is_valid_for_nmap(self):
        argv = self.build()
        self.assertEqual(argv, ['nmap', '-sV', '-p', '80,8443', '-oX', OUT, 'a.x.com'])
        self.assertIn('#', OUT)  # the output path is safe in an argv list, it was only unsafe in a shell string

    def test_service_detection_flag_takes_no_value(self):
        argv = self.build()
        self.assertEqual(argv[argv.index('-sV') + 1], '-p')
        self.assertNotIn('True', argv)
        self.assertNotIn('-sV', self.build(service_detection=False))

    def test_allowed_base_command_scripts_rate_and_flags(self):
        argv = self.build(cmd='nmap -Pn -T4 -n --open --max-retries 2 --host-timeout 300s --min-rate 50',
                          script='vulners,vulscan', script_args='vulscandb=cve.csv,vulners.shodan=1', max_rate=150,
                          flags=['reason'])
        self.assertEqual(argv, ['nmap', '-Pn', '-T4', '-n', '--open', '--max-retries', '2', '--host-timeout', '300s',
                                '--min-rate', '50', '-sV', '-p', '80,8443', '--script', 'vulners,vulscan',
                                '--script-args', 'vulscandb=cve.csv,vulners.shodan=1', '--max-rate', '150', '-oX', OUT,
                                '--reason', 'a.x.com'])

    def test_each_allowed_base_option(self):
        for cmd in ('nmap', 'nmap -Pn', 'nmap -n', 'nmap -sS', 'nmap -sT', 'nmap -sV', 'nmap --open', 'nmap -T0', 'nmap -T5', 'nmap --max-retries=3', 'nmap --host-timeout 90m',
                    'nmap --min-rate 1', 'nmap --max-rate 100000'):
            self.assertIsNotNone(self.build(cmd=cmd), cmd)

    def test_input_file_replaces_the_host(self):
        argv = get_nmap_argv('/r/hosts.txt', host='a.x.com', ports='80', output_file=OUT)
        self.assertEqual(argv[-2:], ['-iL', '/r/hosts.txt'])
        self.assertNotIn('a.x.com', argv)

    def test_base_command_is_an_allowlist_every_probe_is_refused(self):
        refused = [
            'nmap -Pn 8.8.8.8', 'nmap 8.8.8.8', 'nmap scanme.example.org', 'nmap -iR 500', 'nmap -iR500',
            'nmap -iL/etc/passwd', 'nmap -iL /etc/passwd', 'nmap --excludefile=/etc/shadow', 'nmap --excludefile /e',
            'nmap --exclude 10.0.0.1', 'nmap -oN/etc/cron.d/x', 'nmap -oX /tmp/x', 'nmap -oG /tmp/x', 'nmap -oA /tmp/x',
            'nmap -oS /tmp/x', 'nmap --resume=/tmp/x', 'nmap --datadir=/tmp/x', 'nmap --datadir /tmp/x',
            'nmap --script=/tmp/evil.nse', 'nmap --script vulners', 'nmap --script-args=newtargets',
            'nmap --script-args newtargets', 'nmap --proxies=socks4://x:1', 'nmap --spoof-mac 0', 'nmap --send-eth',
            'nmap -e eth0', 'nmap --interface eth0', 'nmap -D RND:5', 'nmap -S 1.2.3.4', 'nmap --servicedb=/x',
            'nmap --versiondb /x', 'nmap --stylesheet=/x', 'nmap -sC', 'nmap -A', 'nmap -sU', 'nmap -p-', 'nmap -p 1-65535',
            'nmap -T6', 'nmap -T', 'nmap -T-1', 'nmap --max-retries', 'nmap --max-retries 99', 'nmap --max-retries=-1',
            'nmap --host-timeout 5', 'nmap --host-timeout 99999999s', 'nmap --min-rate 0', 'nmap --min-rate 1000000',
            'nmap --max-rate 10x', 'nmap --totally-unknown', 'nmap --reason', 'nmap -v', 'nmap -Pn;id', 'nmap -Pn $(id)', 'nmap -Pn `id`',
            'nmap "-Pn', 'nmap -Pn\n8.8.8.8', 'nmap\t8.8.8.8', 'curl -Pn', 'nmap-x -Pn', '/usr/bin/nmap -Pn',
            '-Pn', 'nmap --open=1', 'nmap -sV=x', 'nmap -Pn -- 8.8.8.8',
        ]
        for cmd in refused:
            self.assertIsNone(self.build(cmd=cmd), repr(cmd))
        self.assertFalse(is_valid_nmap_command('nmap -Pn 8.8.8.8'))
        self.assertTrue(is_valid_nmap_command('nmap -Pn -T4'))

    def test_scripts_come_from_a_small_allowlist_of_plain_names(self):
        for script in ('vulners', 'vulscan', 'banner', 'http-title', 'safe', 'version', 'vulners,http-headers'):
            self.assertIsNotNone(self.build(script=script), script)
        refused = ['*', 'http-*', '/tmp/evil.nse', 'vulscan/vulscan.nse', '../x', 'a;b', '$(id)', 'http-x\n', 'vulners\n',
                   'intrusive', 'exploit', 'brute', 'dos', 'external', 'fuzzer', 'vuln', 'default', 'auth', 'malware',
                   'all', 'http-slowloris', 'http-brute', 'ssh-brute', 'smb-vuln-ms17-010', 'Vulners', 'vulners,',
                   ',vulners', 'vulners,exploit', 'a' * 65, '-vulners', 'not-in-the-list']
        for script in refused:
            self.assertIsNone(self.build(script=script), repr(script))

    def test_script_args_are_plain_key_value_pairs(self):
        for args in ('vulscandb=cve.csv', 'a.b=1,c-d=x_y:z@w', 'k='):
            self.assertIsNotNone(self.build(script_args=args), args)
        refused = ['newtargets', 'newtargets=1', 'NewTargets=true', 'targets-asn.asn=13335,newtargets', 'a=b,newtargets',
                   'x y', 'a|b', 'a=b\n', 'k=/etc/passwd', 'k=../x', 'dbfile=x', 'path=x', 'x.dir=1', 'scriptx=1',
                   'a==b', '=v', 'k=v;id', 'k=$(id)', 'k=' + 'v' * 200, ('k' * 65) + '=v', 'k', ',', 'a=b,']
        for args in refused:
            self.assertIsNone(self.build(script_args=args), repr(args))

    def test_dedicated_fields_are_checked_with_a_full_match(self):
        self.assertIsNone(get_nmap_argv(None, host='a.x.com', ports='80\n', output_file=OUT))
        self.assertIsNone(get_nmap_argv(None, host='a.x.com\n', ports='80', output_file=OUT))
        self.assertIsNone(self.build(max_rate='150\n'))
        for ports in ('80;id', '', '-1', '80 443', '80,\n'):
            if ports:
                self.assertIsNone(get_nmap_argv(None, host='a.x.com', ports=ports, output_file=OUT), repr(ports))
        for kw in (dict(max_rate='1; id'), dict(max_rate=0), dict(max_rate='100001'), dict(flags=['script=/tmp/e.nse']),
                   dict(flags=['x;y']), dict(flags=['open\n']), dict(flags=['iL=/x'])):
            self.assertIsNone(self.build(**kw), kw)
        self.assertIsNone(get_nmap_argv(None, host='-oN/etc/passwd', ports='80', output_file=OUT))  # option injection
        self.assertIsNone(get_nmap_argv(None, host='a.x.com b.x.com', ports='80', output_file=OUT))
        self.assertIsNone(get_nmap_argv('-iL', host=None, ports='80', output_file=OUT))
        self.assertIsNone(get_nmap_argv('/r/h.txt\n', host=None, ports='80', output_file=OUT))


class NmapStageCommandTest(TestCase):
    def test_stage_runs_the_built_command_without_a_shell(self):
        from django.utils import timezone
        from dashboard.models import Project
        from limes.celery_custom_task import LimesTask
        from limes.tasks import stages
        from scanEngine.models import EngineType
        from startScan.models import Asset, IpAddress, ScanHistory
        from targetApp.models import Domain
        import tempfile
        p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        d = Domain.objects.create(name='x.com', project=p, insert_date=timezone.now())
        eng = EngineType.objects.create(engine_name='e', yaml_configuration='{}')
        tmp = tempfile.mkdtemp()
        scan = ScanHistory.objects.create(scan_type=eng, domain=d, start_scan_date=timezone.now(), results_dir=tmp)
        a = Asset.objects.create(project=p, kind='hostname', value='a.x.com', scope_tier='owned_host')
        a.ip_addresses.add(IpAddress.objects.create(address='8.8.8.8'))
        with mock.patch.object(LimesTask, 'notify'), \
                mock.patch.object(stages, 'run_command') as rc, \
                mock.patch.object(stages, 'parse_nmap_results', return_value=[]):
            stages.nmap(host='a.x.com', ports=[80, 8443], max_rate=50,
                        ctx={'scan_history_id': scan.id, 'results_dir': tmp, 'track': False})
        args, kwargs = rc.call_args
        self.assertFalse(kwargs.get('shell'))
        argv = shlex.split(args[0])
        self.assertEqual(argv[:4], ['nmap', '-sV', '-p', '80,8443'])
        self.assertEqual(argv[-1], 'a.x.com')
        self.assertTrue(argv[argv.index('-oX') + 1].startswith(tmp + '/a.x.com_'))
