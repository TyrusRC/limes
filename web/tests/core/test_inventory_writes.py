from django.test import TestCase
from django.utils import timezone
from dashboard.models import Project
from startScan.models import Asset
from limes.tasks import inventory as inv
from limes.tasks.persistence import save_subdomain, save_ip_address
from scanEngine.models import EngineType
from startScan.models import ScanHistory, IpAddress
from targetApp.models import Domain


class InventoryHelpersTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.root = inv.upsert_root_asset(self.p, 'Example.com.')

    def test_root_normalized_and_scoped(self):
        self.assertEqual(self.root.kind, 'root_domain')
        self.assertEqual(self.root.value, 'example.com')
        self.assertEqual(self.root.scope_tier, 'owned_root')

    def test_hostname_upsert_dedup_and_sources(self):
        a1 = inv.upsert_hostname_asset(self.p, 'A.example.com', parent=self.root, source='amass', evidence='e1')
        a2 = inv.upsert_hostname_asset(self.p, 'a.example.com', parent=self.root, source='amass', evidence='e1')
        a3 = inv.upsert_hostname_asset(self.p, 'a.example.com', parent=self.root, source='httpx', evidence='e2')
        self.assertEqual(a1.id, a2.id); self.assertEqual(a1.id, a3.id)
        self.assertEqual(a3.parent_id, self.root.id)
        self.assertEqual(len(a3.sources), 2)  # amass/e1 once + httpx/e2

    def test_root_request_headers_persisted(self):
        hdr = {'user_agent': 'UA', 'headers': []}
        a = inv.upsert_root_asset(self.p, 'x.com', request_headers=hdr)
        a.refresh_from_db()
        self.assertEqual(a.request_headers, hdr)

    def test_root_empty_name_returns_none(self):
        n = Asset.objects.count()
        self.assertIsNone(inv.upsert_root_asset(self.p, ''))
        self.assertEqual(Asset.objects.count(), n)

    def test_hostname_upsert_does_not_promote_scope(self):
        cb = Asset.objects.create(project=self.p, kind='hostname', value='cb.example.com', scope_tier='co_brand')
        inv.upsert_hostname_asset(self.p, 'cb.example.com', parent=self.root, scope_tier='owned_host')
        cb.refresh_from_db()
        self.assertEqual(cb.scope_tier, 'co_brand')

    def test_hostname_empty_name_returns_none(self):
        self.assertIsNone(inv.upsert_hostname_asset(self.p, '', parent=self.root))

    def test_update_host_state_skips_none(self):
        a = inv.upsert_hostname_asset(self.p, 'h.example.com', parent=self.root)
        inv.update_host_state(a, webserver='old')
        inv.update_host_state(a, http_status=200, page_title='T', webserver=None)
        a.refresh_from_db()
        self.assertEqual(a.webserver, 'old')
        self.assertEqual(a.http_status, 200); self.assertEqual(a.page_title, 'T')

    def test_finalize_lifecycle_marks_unseen_missing(self):
        from startScan.asset_models import ScanRun
        a = inv.upsert_hostname_asset(self.p, 'stale.example.com', parent=self.root)
        run = ScanRun.objects.create(project=self.p, root_asset=self.root,
                                     start_scan_date=timezone.now())
        # asset last_seen is before run start (seeded earlier)
        Asset.objects.filter(id=a.id).update(last_seen=run.start_scan_date - timezone.timedelta(minutes=1))
        for _ in range(3):
            inv.finalize_lifecycle(run)
        a.refresh_from_db()
        self.assertEqual(a.state, 'missing'); self.assertEqual(a.missed_count, 3)


class SaveSubdomainDualWriteTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p2', slug='p2', insert_date=timezone.now())
        self.domain = Domain.objects.create(name='x.com', project=self.p, insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='t', yaml_configuration='{}')
        self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now())
        self.ctx = {'scan_history_id': self.scan.id, 'domain_id': self.domain.id}

    def test_hostname_asset_written_and_deduped(self):
        sub, created = save_subdomain('a.x.com', ctx=self.ctx)
        self.assertTrue(created)
        save_subdomain('a.x.com', ctx=self.ctx)
        qs = Asset.objects.filter(project=self.p, kind='hostname', value='a.x.com')
        self.assertEqual(qs.count(), 1)
        a = qs.get()
        self.assertEqual(a.scope_tier, 'owned_host')
        self.assertEqual(a.parent.value, 'x.com')
        self.assertEqual(a.parent.kind, 'root_domain')

    def test_co_brand_not_promoted(self):
        Asset.objects.create(project=self.p, kind='hostname', value='cb.x.com', scope_tier='co_brand')
        save_subdomain('cb.x.com', ctx=self.ctx)
        self.assertEqual(Asset.objects.get(project=self.p, value='cb.x.com').scope_tier, 'co_brand')


class SaveIpAddressDualWriteTest(SaveSubdomainDualWriteTest):
    def test_cdn_persisted_and_ip_asset_linked(self):
        sub, _ = save_subdomain('h.x.com', ctx=self.ctx)
        host = Asset.objects.get(project=self.p, kind='hostname', value='h.x.com')
        ip, created = save_ip_address('1.2.3.4', subdomain=sub, cdn=True)
        self.assertTrue(created)
        self.assertTrue(IpAddress.objects.get(address='1.2.3.4').is_cdn)
        ipa = Asset.objects.get(project=self.p, kind='ip', value='1.2.3.4')
        self.assertIn(ip, host.ip_addresses.all())
        self.assertTrue(ipa)

    def test_no_subdomain_ok(self):
        ip, _ = save_ip_address('5.6.7.8')
        self.assertIsNotNone(ip)


class MirrorSubdomainStateTest(SaveSubdomainDualWriteTest):
    def test_state_and_technologies_mirrored(self):
        from startScan.models import Technology
        sub, _ = save_subdomain('m.x.com', ctx=self.ctx)
        sub.http_status = 200; sub.page_title = 'T'; sub.webserver = 'nginx'
        sub.content_type = 'text/html'; sub.content_length = 42; sub.response_time = 0.5
        sub.cname = 'c.cdn.net'; sub.is_cdn = True; sub.cdn_name = 'cf'
        sub.screenshot_path = 'a/b.png'; sub.save()
        tech = Technology.objects.create(name='nginx')
        sub.technologies.add(tech)
        asset = inv.mirror_subdomain_state(sub, self.p)
        asset.refresh_from_db()
        self.assertEqual(asset.value, 'm.x.com')
        for f in inv.STATE_FIELDS:
            self.assertEqual(getattr(asset, f), getattr(sub, f), f)
        self.assertEqual(list(asset.technologies.all()), [tech])

    def test_no_project_returns_none(self):
        sub, _ = save_subdomain('n.x.com', ctx=self.ctx)
        self.assertIsNone(inv.mirror_subdomain_state(sub, None))
