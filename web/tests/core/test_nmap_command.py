import shlex
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase

from limes.common_func import get_nmap_argv, get_output_file_name

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

    def test_user_command_scripts_rate_and_flags(self):
        argv = self.build(cmd='nmap -Pn -T4', script='vulners,vulscan/vulscan', script_args='vulscandb=cve.csv', max_rate=150,
                          flags=['open'])
        self.assertEqual(argv, ['nmap', '-Pn', '-T4', '-sV', '-p', '80,8443', '--script', 'vulners,vulscan/vulscan',
                                '--script-args', 'vulscandb=cve.csv', '--max-rate', '150', '-oX', OUT, '--open', 'a.x.com'])

    def test_input_file_replaces_the_host(self):
        argv = get_nmap_argv('/r/hosts.txt', host='a.x.com', ports='80', output_file=OUT)
        self.assertEqual(argv[-2:], ['-iL', '/r/hosts.txt'])
        self.assertNotIn('a.x.com', argv)

    def test_untrusted_pieces_are_refused(self):
        bad = [dict(cmd='nmap; rm -rf /'), dict(cmd='curl http://evil'), dict(cmd='nmap `id`'), dict(cmd='nmap "unterminated'),
               dict(script='a;b'), dict(script='$(id)'), dict(script_args='x y'), dict(script_args='a|b'),
               dict(max_rate='1; id'), dict(flags=['x;y'])]
        for kw in bad:
            self.assertIsNone(self.build(**kw), kw)
        self.assertIsNone(get_nmap_argv(None, host='a.x.com', ports='80;id', output_file=OUT))
        self.assertIsNone(get_nmap_argv(None, host='-oN/etc/passwd', ports='80', output_file=OUT))  # option injection
        self.assertIsNone(get_nmap_argv(None, host='a.x.com b.x.com', ports='80', output_file=OUT))
        self.assertIsNone(get_nmap_argv('-iL', host=None, ports='80', output_file=OUT))


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
