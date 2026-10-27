from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.tasks.persistence import save_vulnerability
from scanEngine.models import EngineType
from startScan.models import Asset, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain


class LinkTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.other = Project.objects.create(name='o', slug='o', insert_date=timezone.now())
        eng = EngineType.objects.create(engine_name='e', yaml_configuration='{}')
        self.domain = Domain.objects.create(project=self.p, name='x.com', insert_date=timezone.now())
        self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=eng, start_scan_date=timezone.now())
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='x.com', scope_tier='owned_root')
        self.host = Asset.objects.create(project=self.p, kind='hostname', value='app.x.com', scope_tier='owned_host')
        Asset.objects.create(project=self.other, kind='hostname', value='api.x.com', scope_tier='owned_host')

    def save(self, **kw):
        save_vulnerability(scan_history=self.scan, name=f'n{Vulnerability.objects.count()}', severity=3, **kw)
        return Vulnerability.objects.latest('id')

    def test_links_by_subdomain_then_url(self):
        sub = Subdomain.objects.create(scan_history=self.scan, target_domain=self.domain, name='app.x.com')
        self.assertEqual(self.save(subdomain=sub, http_url='https://other.x.com/').asset, self.host)
        self.assertEqual(self.save(http_url='https://APP.x.com.:8443/login').asset, self.host)
        self.assertEqual(self.save(http_url='x.com/path').asset, self.root)

    def test_never_crosses_projects_or_invents(self):
        self.assertIsNone(self.save(http_url='https://api.x.com/').asset)  # only the other project has it
        self.assertIsNone(self.save(http_url='https://unknown.x.com/').asset)
        self.assertIsNone(self.save().asset)
