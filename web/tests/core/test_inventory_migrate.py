from django.apps import apps as django_apps
from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from startScan import inventory_migrate as im
from startScan.asset_models import Asset
from startScan.models import IpAddress, ScanHistory, Subdomain
from scanEngine.models import EngineType
from targetApp.models import Domain


def seed(project, domain_name='x.com'):
    domain = Domain.objects.create(name=domain_name, project=project, insert_date=timezone.now())
    engine = EngineType.objects.create(engine_name='e', yaml_configuration='{}')
    scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=timezone.now())
    return domain, scan


class NormalizeTest(TestCase):
    def test_normalize(self):
        self.assertEqual(im.normalize_host('A.X.COM.'), 'a.x.com')
        self.assertEqual(im.normalize_host('  b.x.com '), 'b.x.com')


class BackfillTest(TestCase):
    def setUp(self):
        self.project = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.domain, self.scan = seed(self.project)

    def test_root_domain_backfill_idempotent(self):
        n1 = im.backfill_root_domains(django_apps)
        n2 = im.backfill_root_domains(django_apps)
        self.assertEqual(n1, 1)
        self.assertEqual(n2, 0)  # idempotent
        a = Asset.objects.get(kind='root_domain', value='x.com')
        self.assertEqual(a.scope_tier, 'owned_root')
        self.assertEqual(a.project_id, self.project.id)

    def test_hostname_dedup_latest_state_and_dates(self):
        early = timezone.now() - timezone.timedelta(days=5)
        late = timezone.now()
        Subdomain.objects.create(name='a.x.com', scan_history=self.scan, target_domain=self.domain,
                                 http_status=301, page_title='old', discovered_date=early)
        Subdomain.objects.create(name='A.X.COM', scan_history=self.scan, target_domain=self.domain,
                                 http_status=200, page_title='new', discovered_date=late)
        im.backfill_root_domains(django_apps)
        n = im.backfill_hostname_assets(django_apps)
        self.assertEqual(n, 1)  # deduped to one
        a = Asset.objects.get(kind='hostname', value='a.x.com')
        self.assertEqual(a.http_status, 200)  # latest wins
        self.assertEqual(a.page_title, 'new')
        self.assertEqual(a.scope_tier, 'owned_host')
        self.assertEqual(a.parent.value, 'x.com')
        self.assertEqual(a.first_seen, early)
        self.assertEqual(a.last_seen, late)

    def test_hostname_null_date_does_not_crash(self):
        Subdomain.objects.create(name='n.x.com', scan_history=self.scan, target_domain=self.domain,
                                 http_status=200, discovered_date=None)
        im.backfill_root_domains(django_apps)
        im.backfill_hostname_assets(django_apps)
        a = Asset.objects.get(kind='hostname', value='n.x.com')
        self.assertIsNotNone(a.last_seen)  # fell back, not NULL

    def test_ip_backfill_skips_blank_and_dedupes(self):
        IpAddress.objects.create(address='192.0.2.1')
        IpAddress.objects.create(address='192.0.2.1')  # dup
        IpAddress.objects.create(address='')  # blank
        IpAddress.objects.create(address=None)
        n = im.backfill_ip_assets(django_apps)
        self.assertEqual(n, 1)  # one unique non-blank
        self.assertTrue(Asset.objects.filter(kind='ip', value='192.0.2.1').exists())

    def test_hostname_abc_ordering(self):
        early = timezone.now() - timezone.timedelta(days=5)
        late = timezone.now()
        for status, title, date in ((301, 'a', early), (302, 'b', None), (200, 'c', late)):
            Subdomain.objects.create(name='h.x.com', scan_history=self.scan, target_domain=self.domain,
                                     http_status=status, page_title=title, discovered_date=date)
        im.backfill_root_domains(django_apps)
        im.backfill_hostname_assets(django_apps)
        a = Asset.objects.get(kind='hostname', value='h.x.com')
        self.assertEqual((a.http_status, a.page_title), (200, 'c'))
        self.assertEqual(a.first_seen, early)
        self.assertEqual(a.last_seen, late)

    def test_hostname_and_ip_idempotent(self):
        sub = Subdomain.objects.create(name='i.x.com', scan_history=self.scan, target_domain=self.domain,
                                       discovered_date=timezone.now())
        sub.ip_addresses.add(IpAddress.objects.create(address='192.0.2.9'))
        im.backfill_root_domains(django_apps)
        self.assertEqual(im.backfill_hostname_assets(django_apps), 1)
        self.assertEqual(im.backfill_ip_assets(django_apps), 1)
        total = Asset.objects.count()
        self.assertEqual(im.backfill_hostname_assets(django_apps), 0)
        self.assertEqual(im.backfill_ip_assets(django_apps), 0)
        self.assertEqual(Asset.objects.count(), total)

    def test_hostname_missing_root_gets_null_parent(self):
        Subdomain.objects.create(name='m.x.com', scan_history=self.scan, target_domain=self.domain,
                                 discovered_date=timezone.now())
        self.assertEqual(im.backfill_hostname_assets(django_apps), 1)
        self.assertIsNone(Asset.objects.get(kind='hostname', value='m.x.com').parent)

    def test_ip_attributed_to_its_own_project(self):
        p2 = Project.objects.create(name='p2', slug='p2', insert_date=timezone.now())
        d2, scan2 = seed(p2, 'y.com')
        sub = Subdomain.objects.create(name='s.y.com', scan_history=scan2, target_domain=d2,
                                       discovered_date=timezone.now())
        sub.ip_addresses.add(IpAddress.objects.create(address='198.51.100.7'))
        IpAddress.objects.create(address='203.0.113.5')  # orphan -> fallback to first project
        self.assertEqual(im.backfill_ip_assets(django_apps), 2)
        self.assertEqual(Asset.objects.get(kind='ip', value='198.51.100.7').project_id, p2.id)
        self.assertEqual(Asset.objects.get(kind='ip', value='203.0.113.5').project_id, self.project.id)


class VulnBackfillTest(TestCase):
    def setUp(self):
        self.project = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.domain, self.scan = seed(self.project)

    def test_vuln_asset_backfill_fallbacks(self):
        from startScan.models import EndPoint, Vulnerability
        sub = Subdomain.objects.create(name='a.x.com', scan_history=self.scan, target_domain=self.domain,
                                       http_status=200, discovered_date=timezone.now())
        v_sub = Vulnerability.objects.create(name='v1', severity=3, scan_history=self.scan,
                                             target_domain=self.domain, subdomain=sub, discovered_date=timezone.now())
        v_dom = Vulnerability.objects.create(name='v2', severity=1, scan_history=self.scan,
                                             target_domain=self.domain, discovered_date=timezone.now())
        im.run_all(django_apps)
        v_sub.refresh_from_db(); v_dom.refresh_from_db()
        self.assertEqual(v_sub.asset.kind, 'hostname')
        self.assertEqual(v_sub.asset.value, 'a.x.com')
        self.assertEqual(v_dom.asset.kind, 'root_domain')  # fallback to root

    def test_vuln_asset_backfill_via_endpoint_subdomain(self):
        from startScan.models import EndPoint, Vulnerability
        sub = Subdomain.objects.create(name='B.x.com.', scan_history=self.scan, target_domain=self.domain,
                                       http_status=200, discovered_date=timezone.now())
        ep = EndPoint.objects.create(scan_history=self.scan, target_domain=self.domain, subdomain=sub,
                                     http_url='http://b.x.com/a')
        v = Vulnerability.objects.create(name='v3', severity=2, scan_history=self.scan, target_domain=self.domain,
                                         endpoint=ep, subdomain=None, discovered_date=timezone.now())
        im.run_all(django_apps)
        v.refresh_from_db()
        self.assertEqual(v.asset.kind, 'hostname')
        self.assertEqual(v.asset.value, 'b.x.com')

    def test_run_all_idempotent(self):
        Subdomain.objects.create(name='a.x.com', scan_history=self.scan, target_domain=self.domain,
                                 http_status=200, discovered_date=timezone.now())
        im.run_all(django_apps)
        count1 = Asset.objects.count()
        im.run_all(django_apps)
        self.assertEqual(Asset.objects.count(), count1)  # second run adds nothing


class CidrBackfillTest(TestCase):
    def test_cidr_asset_created(self):
        project = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        Domain.objects.create(name='x.com', project=project, insert_date=timezone.now(),
                              ip_address_cidr=' 192.0.2.0/24 ')
        im.backfill_root_domains(django_apps)
        self.assertEqual(Asset.objects.filter(project=project, kind='cidr', value='192.0.2.0/24').count(), 1)
