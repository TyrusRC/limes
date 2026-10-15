import os
import shutil
import tempfile
from types import SimpleNamespace

from celery.exceptions import SoftTimeLimitExceeded
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.pipeline import dnsx
from limes.tasks import attribution
from startScan.models import Asset, AssetFact

FIXTURE = os.path.join(os.path.dirname(__file__), 'fixtures', 'dnsx_ns_mx_sample.jsonl')


class NsMxParseTest(SimpleTestCase):
    def test_argv(self):
        argv = dnsx.build_ns_mx_argv('/r/h.txt', '/r/o.jsonl')
        for flag in ('-a', '-ns', '-mx', '-resp', '-json', '-silent'):
            self.assertIn(flag, argv)
        self.assertEqual(argv[argv.index('-l') + 1], '/r/h.txt')
        self.assertEqual(argv[argv.index('-o') + 1], '/r/o.jsonl')

    def test_parse(self):
        with open(FIXTURE) as f:
            out = dnsx.parse_ns_mx(f)
        self.assertEqual(out['partner-co.com'], {'a': ['198.51.99.10'], 'ns': ['ns1.example.com', 'ns2.example.com'],
                                                 'mx': ['mail.example.com']})
        self.assertEqual(out['lame.net'], {'a': [], 'ns': ['ns1.example.com'], 'mx': []})
        self.assertEqual(out['weird.com'], {'a': [], 'ns': [], 'mx': []})


class CollectDnsTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        for v in ('partner-co.com', 'lame.net', 'thirdparty.org'):
            Asset.objects.create(project=self.p, kind='root_domain', value=v, scope_tier='candidate')
        Asset.objects.create(project=self.p, kind='root_domain', value='decided.com', scope_tier='rejected')
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)

    def run_with(self, fixture=FIXTURE, rc=0):
        def run(argv, **kw):
            self.kw = kw
            with open(argv[argv.index('-l') + 1]) as f:
                self.hosts = f.read().split()
            shutil.copy(fixture, argv[argv.index('-o') + 1])
            return SimpleNamespace(return_code=rc)
        return run

    def facts(self, value, kind):
        return sorted(AssetFact.objects.filter(asset__value=value, kind=kind).values_list('value', flat=True))

    def test_records_ns_mx_and_a_only_for_resolving_candidates(self):
        out = attribution.collect_dns(self.p, self.dir, run=self.run_with())
        self.assertEqual(sorted(self.hosts), ['lame.net', 'partner-co.com', 'thirdparty.org'])  # candidates only
        self.assertEqual(self.kw.get('timeout'), 600)
        self.assertEqual(self.facts('partner-co.com', 'ns'), ['ns1.example.com', 'ns2.example.com'])
        self.assertEqual(self.facts('partner-co.com', 'mx'), ['mail.example.com'])
        self.assertEqual(self.facts('partner-co.com', 'ip'), ['198.51.99.10'])
        self.assertEqual(self.facts('lame.net', 'ns'), [])  # did not resolve: delegation unproven
        self.assertEqual(out['dns_checked'], 3)

    def test_ns_facts_replaced_by_latest_lookup(self):
        attribution.collect_dns(self.p, self.dir, run=self.run_with())
        moved = os.path.join(self.dir, 'moved.jsonl')
        with open(moved, 'w') as f:
            f.write('{"host":"partner-co.com","a":["198.51.99.10"],"ns":["ns9.elsewhere.net"]}\n')
        attribution.collect_dns(self.p, self.dir, run=self.run_with(fixture=moved))
        self.assertEqual(self.facts('partner-co.com', 'ns'), ['ns9.elsewhere.net'])
        self.assertEqual(self.facts('partner-co.com', 'mx'), [])

    def test_failures_contained_but_time_limit_propagates(self):
        def boom(argv, **kw):
            raise OSError('dnsx missing')
        with self.assertLogs('limes.tasks.attribution', level='ERROR'):
            self.assertEqual(attribution.collect_dns(self.p, self.dir, run=boom), {'dns_checked': 0})

        def slow(argv, **kw):
            raise SoftTimeLimitExceeded()
        with self.assertRaises(SoftTimeLimitExceeded):
            attribution.collect_dns(self.p, self.dir, run=slow)
