import json
import os
from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.tasks import intel
from startScan.models import Asset, IpAddress

FX = os.path.join(os.path.dirname(__file__), 'fixtures')


def load(name):
    with open(os.path.join(FX, name)) as f:
        return json.load(f)


class Fake:
    """get_json stand-in: provider -> (status, body) or callable(url) -> (status, body)."""
    def __init__(self, **by_provider):
        self.by_provider, self.calls = by_provider, []

    def __call__(self, url, *, provider):
        self.calls.append((provider, url))
        r = self.by_provider[provider]
        return r(url) if callable(r) else r


class IntelRunTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='example.com', scope_tier='owned_root')
        self.www = Asset.objects.create(project=self.p, kind='hostname', value='www.example.com',
                                        scope_tier='owned_host', parent=self.root)
        self.cdn_host = Asset.objects.create(project=self.p, kind='hostname', value='cdn.example.com',
                                             scope_tier='owned_host', parent=self.root)
        self.own_ip = Asset.objects.create(project=self.p, kind='ip', value='203.0.114.7', scope_tier='owned_host')
        self.dep_ip = Asset.objects.create(project=self.p, kind='ip', value='104.16.1.1', scope_tier='dependency')
        self.www.ip_addresses.add(IpAddress.objects.create(address='203.0.114.7'))
        self.cdn_host.ip_addresses.add(IpAddress.objects.create(address='104.16.1.1'))

    def tier(self, value):
        return Asset.objects.get(project=self.p, value=value).scope_tier

    # crt.sh
    def test_crtsh_hostnames_and_co_tenancy_candidates(self):
        out = intel.run_crtsh(self.p, self.root, get=Fake(crtsh=(200, load('crtsh_sample.json'))))
        self.assertEqual(self.tier('api.example.com'), 'owned_host')
        self.assertEqual(Asset.objects.get(value='api.example.com').parent, self.root)
        self.assertEqual(self.tier('example-brand.net'), 'candidate')
        self.assertEqual(self.tier('example.org'), 'candidate')
        self.assertIn('cert:102 (api.example.com) shared with example.com', Asset.objects.get(value='example.org').sources[0]['evidence'])
        self.assertFalse(Asset.objects.filter(kind='hostname', value='example.com').exists())
        self.assertEqual(out['candidates'], 2)

    def test_crtsh_never_resuggests_or_downgrades(self):
        Asset.objects.create(project=self.p, kind='root_domain', value='example.org', scope_tier='rejected')
        Asset.objects.create(project=self.p, kind='root_domain', value='example-brand.net', scope_tier='owned_root')
        intel.run_crtsh(self.p, self.root, get=Fake(crtsh=(200, load('crtsh_sample.json'))))
        self.assertEqual(self.tier('example.org'), 'rejected')
        self.assertEqual(self.tier('example-brand.net'), 'owned_root')

    def test_candidate_under_owned_root_is_not_created(self):
        rows = [{'id': 7, 'name_value': 'Example.COM.\nmail.EXAMPLE.com'}]
        intel.run_crtsh(self.p, self.root, get=Fake(crtsh=(200, rows)))
        self.assertFalse(Asset.objects.filter(scope_tier='candidate').exists())

    def test_mass_shared_certificate_is_skipped(self):
        names = '\n'.join(['example.com'] + [f'site{i}.com' for i in range(21)])
        intel.run_crtsh(self.p, self.root, get=Fake(crtsh=(200, [{'id': 9, 'name_value': names}])))
        self.assertFalse(Asset.objects.filter(scope_tier='candidate').exists())

    def test_candidates_are_capped_per_run(self):
        rows = [{'id': i, 'name_value': f'h{i}.example.com\nco{i}.net'} for i in range(1, 151)]
        out = intel.run_crtsh(self.p, self.root, get=Fake(crtsh=(200, rows)))
        self.assertEqual(Asset.objects.filter(scope_tier='candidate').count(), 100)
        self.assertEqual((out['candidates'], out['candidates_capped']), (100, 50))

    def test_cert_without_in_root_name_contributes_no_candidates(self):
        rows = [{'id': 5, 'name_value': 'other.net\nco.org'}]
        out = intel.run_crtsh(self.p, self.root, get=Fake(crtsh=(200, rows)))
        self.assertFalse(Asset.objects.filter(scope_tier='candidate').exists())
        self.assertEqual(out['candidates'], 0)

    def test_crtsh_failure_is_harmless(self):
        self.assertEqual(intel.run_crtsh(self.p, self.root, get=Fake(crtsh=(None, None))),
                         {'hostnames': 0, 'candidates': 0, 'candidates_capped': 0})

    # InternetDB
    def test_internetdb_enriches_and_suggests_only_from_owned_ips(self):
        body = load('internetdb_sample.json')
        out = intel.run_internetdb(self.p, self.root, get=Fake(internetdb=lambda url: (200, dict(body, ip=url.rsplit('/', 1)[1]))))
        self.own_ip.refresh_from_db(); self.dep_ip.refresh_from_db()
        self.assertEqual(self.own_ip.enrichment['internetdb']['ports'], [80, 443])
        self.assertIn('fetched_at', self.dep_ip.enrichment['internetdb'])
        self.assertEqual(self.tier('partner-co.com'), 'candidate')
        ev = [s['evidence'] for s in Asset.objects.get(value='partner-co.com').sources]
        self.assertEqual(ev, ['ip:203.0.114.7'])  # not from the dependency IP
        self.assertEqual(out['internetdb_enriched'], 2)

    def test_internetdb_404_cached_as_no_data_and_fresh_skipped(self):
        fake = Fake(internetdb=(404, load('internetdb_404.json')))
        intel.run_internetdb(self.p, self.root, get=fake)
        self.own_ip.refresh_from_db()
        self.assertTrue(self.own_ip.enrichment['internetdb']['no_data'])
        intel.run_internetdb(self.p, self.root, get=fake)
        self.assertEqual(len(fake.calls), 2)  # second run: both IPs fresh, no calls

    def test_stale_entries_are_refetched(self):
        old = (timezone.now() - timedelta(hours=25)).isoformat()
        for ip in (self.own_ip, self.dep_ip):
            ip.enrichment = {'internetdb': {'no_data': True, 'fetched_at': old}}
            ip.save()
        fake = Fake(internetdb=(404, load('internetdb_404.json')))
        intel.run_internetdb(self.p, self.root, get=fake)
        self.assertEqual(len(fake.calls), 2)

    def test_provider_failure_is_not_cached(self):
        intel.run_internetdb(self.p, self.root, get=Fake(internetdb=(None, None)))
        self.own_ip.refresh_from_db()
        self.assertNotIn('internetdb', self.own_ip.enrichment)

    def test_internetdb_aborts_after_three_consecutive_failures(self):
        for i in range(3):
            Asset.objects.create(project=self.p, kind='ip', value=f'198.51.100.{i}', scope_tier='dependency')
            self.cdn_host.ip_addresses.add(IpAddress.objects.create(address=f'198.51.100.{i}'))
        fake = Fake(internetdb=(None, None))
        out = intel.run_internetdb(self.p, self.root, get=fake)
        self.assertEqual(len(fake.calls), 3)
        self.assertEqual(out['internetdb_aborted'], 1)

    def test_ripestat_aborts_after_three_consecutive_failures(self):
        for i in range(3):
            Asset.objects.create(project=self.p, kind='ip', value=f'198.51.100.{i}', scope_tier='dependency')
            self.cdn_host.ip_addresses.add(IpAddress.objects.create(address=f'198.51.100.{i}'))
        fake = Fake(ripestat=(None, None))
        out = intel.run_ripestat(self.p, self.root, get=fake)
        self.assertEqual(len(fake.calls), 3)
        self.assertEqual(out['ripestat_aborted'], 1)

    # RIPEstat
    def test_ripestat_enrichment_and_holder_cached_per_asn(self):
        def ripe(url):
            if 'network-info' in url:
                return 200, load('ripestat_network_info.json')
            return 200, load('ripestat_as_overview.json')
        fake = Fake(ripestat=ripe)
        out = intel.run_ripestat(self.p, self.root, get=fake)
        self.dep_ip.refresh_from_db()
        r = self.dep_ip.enrichment['ripestat']
        self.assertEqual((r['asn'], r['prefix'], r['holder']), ('13335', '104.16.0.0/13', 'CLOUDFLARENET - Cloudflare, Inc., US'))
        self.assertEqual(sum(1 for p, u in fake.calls if 'as-overview' in u), 1)  # one holder lookup for one ASN
        self.assertEqual(out['ripestat_enriched'], 2)
