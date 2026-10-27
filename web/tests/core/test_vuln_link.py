from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.tasks.persistence import save_vulnerability
from scanEngine.models import EngineType
from startScan.models import Asset, ScanHistory, Vulnerability
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

    def test_links_by_the_host_of_the_url(self):
        self.assertEqual(self.save(http_url='https://app.x.com/').asset, self.host)
        self.assertEqual(self.save(http_url='https://APP.x.com.:8443/login').asset, self.host)
        self.assertEqual(self.save(http_url='x.com/path').asset, self.root)

    def test_never_crosses_projects_or_invents(self):
        self.assertIsNone(self.save(http_url='https://api.x.com/').asset)  # only the other project has it
        self.assertIsNone(self.save(http_url='https://unknown.x.com/').asset)
        self.assertIsNone(self.save().asset)

    def test_tags_cwes_and_references_are_kept_as_lists_without_duplicates(self):
        v = self.save(http_url='https://app.x.com/', tags=['xss', 'xss', 'cve'], cwe_ids=['CWE-79', ''],
                      references=['https://r/1', 'https://r/1', 'https://r/2'], cve_ids=['CVE-2024-1'])
        self.assertEqual((v.tag_names, v.cwe_names, v.reference_urls), (['xss', 'cve'], ['CWE-79'], ['https://r/1', 'https://r/2']))
        self.assertEqual([c.name for c in v.cve_ids.all()], ['CVE-2024-1'])

    def test_saving_the_same_finding_again_merges_its_lists_and_is_not_a_new_row(self):
        kw = dict(name='same', severity=3, http_url='https://app.x.com/')
        first, created = save_vulnerability(scan_history=self.scan, tags=['a'], **kw)
        again, created_again = save_vulnerability(scan_history=self.scan, tags=['a', 'b'], references=['https://r'], **kw)
        self.assertEqual((first.id, created, created_again), (again.id, True, False))
        again.refresh_from_db()
        self.assertEqual((again.tag_names, again.reference_urls), (['a', 'b'], ['https://r']))
