"""Characterization of the target lists every scan stage derives (hostnames to port-scan, URLs to
screenshot / crawl / attack with vigil, nmap URL matches) and the host state the probes leave on
the inventory. The GOLDEN lists were captured from the pipeline while it still read the legacy
Subdomain/EndPoint tables; the Asset + per-run URL file pipeline must produce the same lists.
Everything below the stage functions is faked (httpx, naabu, subfinder, katana); only the DB and
the scope guard are real."""
import json
import os
import shlex
import subprocess
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.celery_custom_task import LimesTask
from limes.tasks import control, stages
from scanEngine.models import EngineType
from startScan.models import Asset, IpAddress, ScanHistory, Vulnerability
from targetApp.models import Domain

SUBFINDER_OUT = '\n'.join([
    'a.x.com', 'b.x.com', 'c.x.com', 'p.x.com', 'old.x.com', 'dead.x.com', 'cand.x.com', 'dep.x.com',
    'rej.x.com', 'not a domain!', 'https://url.x.com/path', 'x.com.evil.org', 'A.X.COM'])

LONG = 'k' * 400


def _line(host, status=200, ip='8.8.8.8', title='T', length=100, **extra):
    return {'url': f'https://{host}', 'host_ip': ip, 'a': [ip], 'status_code': status, 'title': title,
            'content_length': length, 'webserver': 'nginx', 'content_type': 'text/html', 'time': '120ms',
            'tech': ['nginx'], 'cname': [], 'cdn': False, **extra}


# what the fake httpx answers per input (bare host or URL); inputs not listed fail to answer
HTTPX = {
    'x.com': [_line('x.com', ip='8.8.1.1', title='Home', length=1000)],
    'imp.x.com': [_line('imp.x.com', ip='8.8.1.2')],
    'a.x.com': [_line('a.x.com', ip='8.8.1.3', title='A', length=2000)],
    'b.x.com': [_line('b.x.com', status=404, ip='8.8.1.4', length=3)],
    'p.x.com': [_line('p.x.com', ip='10.0.0.5')],
    'old.x.com': [_line('old.x.com', status=301, ip='8.8.1.5', final_url='https://new.x.com/')],
    'cand.x.com': [_line('cand.x.com', ip='8.8.1.6')],
    'dep.x.com': [_line('dep.x.com', ip='8.8.1.7')],
    'rej.x.com': [_line('rej.x.com', ip='8.8.1.8')],
    'url.x.com': [_line('url.x.com', status=500, ip='8.8.1.9')],
    'a.x.com:8443': [_line('a.x.com:8443', ip='8.8.1.3', title='Admin', length=55)],
    'https://a.x.com/login': [_line('a.x.com/login', title='Login', length=777)],
    'https://a.x.com/api': [_line('a.x.com/api', status=403, length=9)],
    'https://a.x.com/gone': [_line('a.x.com/gone', status=404, length=9)],
    'https://other.org/x': [_line('other.org/x')],
}
for i in range(1, 13):  # twelve soft-404 pages: more than DELETE_DUPLICATES_THRESHOLD share one length
    HTTPX[f'https://a.x.com/p{i}'] = [_line(f'a.x.com/p{i}', title=f'P{i}', length=777)]
HTTPX['https://a.x.com/'] = [_line('a.x.com/', length=777)]

NAABU = [
    {'host': 'a.x.com', 'ip': '8.8.1.3', 'port': 80},
    {'host': 'a.x.com', 'ip': '8.8.1.3', 'port': 8443},
    {'host': 'x.com', 'ip': '8.8.1.1', 'port': 443},
]
KATANA = ['https://a.x.com/login', 'https://a.x.com/api', 'https://a.x.com/gone', 'https://other.org/x',
          'https://a.x.com/'] + [f'https://a.x.com/p{i}' for i in range(1, 13)]


def fake_stream(cmd, **kw):
    if 'naabu' in cmd:
        return iter(NAABU)
    tokens = shlex.split(cmd)
    if '-u' in tokens:
        inputs = [tokens[tokens.index('-u') + 1]]
    else:
        with open(tokens[tokens.index('-l') + 1]) as f:
            inputs = f.read().split()
    return iter([row for i in inputs for row in HTTPX.get(i, [{'failed': True}])])


def fake_run_command(cmd, **kw):
    if isinstance(cmd, str) and cmd.startswith(('cat ', 'sort ')):
        subprocess.run(cmd, shell=True, check=True)  # test-only: the real merge of the tools' files
    elif isinstance(cmd, str) and cmd.startswith('subfinder'):
        out = cmd.split(' -o ')[1].split()[0]
        with open(out, 'w') as f:
            f.write(SUBFINDER_OUT)


RESOLVE = {'x.com': '8.8.1.1', 'imp.x.com': '8.8.1.2', 'a.x.com': '8.8.1.3', 'b.x.com': '8.8.1.4',
           'p.x.com': '10.0.0.5', 'old.x.com': '8.8.1.5', 'cand.x.com': '8.8.1.6', 'dep.x.com': '8.8.1.7',
           'rej.x.com': '8.8.1.8', 'url.x.com': '8.8.1.9', 'new.x.com': '8.8.1.10'}


def fake_resolve(domain, results_dir, root_only=False):
    """Stands in for dnsx: links the known hosts of the project to their (fake) public IPs."""
    for a in Asset.objects.filter(project=domain.project, kind__in=('hostname', 'root_domain')):
        if a.value in RESOLVE and (not root_only or a.value == domain.name):
            a.ip_addresses.add(IpAddress.objects.get_or_create(address=RESOLVE[a.value])[0])
    return 0


def fake_commands_run(argv, output_path=None, **kw):
    if output_path and 'katana' in os.path.basename(output_path):
        with open(output_path, 'w') as f:
            f.write('\n'.join(KATANA))
    elif output_path:
        open(output_path, 'w').close()
    return SimpleNamespace(return_code=0, output='')


class Scenario:
    """Runs one scan's stages in pipeline order against a fresh project and records what each stage targets."""

    def __init__(self, case, crawl=True):
        self.case, self.crawl, self.guard = case, crawl, []

    def run(self):
        c = self.case
        yaml_cfg = {'enable_http_crawl': self.crawl, 'subdomain_discovery': {'uses_tools': ['subfinder']},
                    'http_crawl': {}, 'port_scan': {'enable_http_crawl': self.crawl},
                    'fetch_url': {'enable_http_crawl': self.crawl}, 'screenshot': {'enable_http_crawl': self.crawl},
                    'vulnerability_scan': {}, 'nmap': {}}
        c.engine.yaml_configuration = json.dumps(yaml_cfg)
        c.engine.save()
        real_in_scope = stages._in_scope

        def spy(task, targets, level, **kw):
            allowed = real_in_scope(task, targets, level, **kw)
            self.guard.append((task.task_name, level, list(targets), list(allowed)))
            return allowed

        patches = [
            mock.patch.object(stages, '_in_scope', side_effect=spy),
            mock.patch.object(stages, 'stream_command', side_effect=fake_stream),
            mock.patch.object(stages, 'run_command', side_effect=fake_run_command),
            mock.patch.object(stages.commands, 'run', side_effect=fake_commands_run),
            mock.patch.object(stages.resolution, 'resolve_domain', side_effect=fake_resolve),
            mock.patch.object(stages.crawl, 'collect_code_artifacts', return_value=([], {})),
            mock.patch.object(control, 'send_scan_notif'),
            mock.patch.object(control, 'build_workflow', return_value=mock.MagicMock(tasks=[])),
            mock.patch.object(control, 'chain'),
            mock.patch.object(LimesTask, 'notify'),
            # NOTE: the real command builder refuses the '#<scan id>' in the output file name; that is outside
            # this characterization, which is about which URL nmap findings are matched to.
            mock.patch.object(stages, 'get_nmap_cmd', return_value='nmap a.x.com'),
        ]
        for p in patches:
            p.start()
            c.addCleanup(p.stop)
        res = control.initiate_scan(
            domain_id=c.domain.id, engine_id=c.engine.id, scan_history_id=c.scan.id, results_dir=c.base,
            imported_subdomains=['imp.x.com', 'other.org'], out_of_scope_subdomains=['c.x.com'])
        c.assertTrue(res.get('success'), res)
        scan = ScanHistory.objects.get(pk=c.scan.id)
        self.dir = scan.results_dir
        ctx = lambda: {'scan_history_id': scan.id, 'engine_id': c.engine.id, 'domain_id': c.domain.id,
                       'results_dir': self.dir, 'starting_point_path': '', 'excluded_paths': [],
                       'yaml_configuration': yaml_cfg, 'out_of_scope_subdomains': ['c.x.com'], 'track': False}
        stages.subdomain_discovery(host='x.com', ctx=ctx())
        stages.port_scan(ctx=ctx())
        stages.fetch_url(ctx=ctx())
        stages.screenshot(ctx=ctx())
        with mock.patch.object(stages.vigil, 'prepare', return_value=('/usr/bin/vigil', {})):
            stages.vulnerability_scan(ctx=ctx())
        nmap_vulns = [{'http_url': 'a.x.com:8443', 'name': 'n1', 'severity': 2, 'type': 't'},
                      {'http_url': 'a.x.com', 'name': 'n2', 'severity': 1, 'type': 't'},
                      {'http_url': 'zz.x.com:22', 'name': 'n3', 'severity': 3, 'type': 't'}]
        with mock.patch.object(stages, 'parse_nmap_results', return_value=nmap_vulns):
            stages.nmap(host='a.x.com', ports=[8443], ctx=ctx())
        return self.summary()

    def raw_final(self, task):
        rows = [(lvl, raw, ok) for t, lvl, raw, ok in self.guard if t == task]
        return {'raw': rows[-1][1], 'final': rows[-1][2]} if rows else None

    def read(self, name):
        path = os.path.join(self.dir, name)
        return open(path).read().split() if os.path.exists(path) else None

    def summary(self):
        hosts = {}
        for a in Asset.objects.filter(kind__in=('hostname', 'root_domain')).order_by('kind', 'value'):
            hosts[f'{a.kind}:{a.value}'] = [a.scope_tier, a.http_status, a.page_title,
                                            sorted(t.name for t in a.technologies.all()),
                                            sorted(i.address for i in a.ip_addresses.all())]
        return {
            'port_scan': self.raw_final('port_scan'),
            'port_scan_file': self.read('input_subdomains_port_scan.txt'),
            'screenshot': self.raw_final('screenshot'),
            'fetch_url': self.raw_final('fetch_url'),
            'vigil': self.raw_final('vulnerability_scan'),
            'vigil_file': self.read('vigil_targets.txt'),
            'nmap_vulns': sorted(Vulnerability.objects.values_list('name', 'http_url', 'asset__value')),
            'hosts': hosts,
            'ip_assets': sorted(Asset.objects.filter(kind='ip').values_list('value', 'scope_tier')),
        }


class Stage4TargetsBase(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.domain = Domain.objects.create(name='x.com', project=self.p, insert_date=timezone.now())
        self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='{}')
        self.base = tempfile.mkdtemp()
        self.scan = ScanHistory.objects.create(scan_type=self.engine, domain=self.domain,
                                               start_scan_date=timezone.now(), results_dir=self.base)
        # tiers that the scope guard must keep out of active testing, however they were discovered
        for value, tier, auth in (('cand.x.com', 'candidate', False), ('dep.x.com', 'dependency', False),
                                  ('rej.x.com', 'rejected', False)):
            Asset.objects.create(project=self.p, kind='hostname', value=value, scope_tier=tier, active_authorized=auth)

    def lists(self, summary):
        return {k: summary[k] for k in ('port_scan', 'port_scan_file', 'screenshot', 'fetch_url', 'vigil', 'vigil_file')}


GOLDEN = os.path.join(os.path.dirname(__file__), 'fixtures', 'stage4_targets.json')


def _golden(name):
    with open(GOLDEN) as f:
        return json.load(f)[name]


def _ordered(summary):
    """Target lists are sets: the legacy queries sorted in the database's collation, the files in Python's."""
    out = json.loads(json.dumps(summary))
    for key in ('port_scan', 'screenshot', 'fetch_url', 'vigil'):
        if out[key]:
            out[key] = {k: sorted(v) for k, v in out[key].items()}
    for key in ('port_scan_file', 'vigil_file'):
        out[key] = out[key] and sorted(out[key])
    return out


class TargetListsTest(Stage4TargetsBase):
    maxDiff = None

    def check(self, name, summary):
        if os.environ.get('STAGE4_CAPTURE'):  # regenerate only from a pipeline whose lists were reviewed
            path = os.environ['STAGE4_CAPTURE']
            data = json.load(open(path)) if os.path.exists(path) else {}
            data[name] = summary
            json.dump(data, open(path, 'w'), indent=1, sort_keys=True)
        self.assertEqual(_ordered(summary), _ordered(_golden(name)))

    def test_crawl_enabled(self):
        self.check('crawl_enabled', Scenario(self, crawl=True).run())

    def test_crawl_disabled(self):
        self.check('crawl_disabled', Scenario(self, crawl=False).run())
