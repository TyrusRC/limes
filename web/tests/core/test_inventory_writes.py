from unittest import mock

from django.test import TestCase
from django.utils import timezone
from dashboard.models import Project
from startScan.models import Asset
from limes.tasks import inventory as inv
from limes.tasks.persistence import save_host, save_ip_address
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


class SaveHostTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p2', slug='p2', insert_date=timezone.now())
        self.domain = Domain.objects.create(name='x.com', project=self.p, insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='t', yaml_configuration='{}')
        self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now())
        self.ctx = {'scan_history_id': self.scan.id, 'domain_id': self.domain.id}

    def test_hostname_asset_written_deduped_and_stamped_with_the_scan(self):
        first = save_host('a.x.com', ctx=self.ctx)
        self.assertEqual(save_host('a.x.com', ctx=self.ctx), first)
        qs = Asset.objects.filter(project=self.p, kind='hostname', value='a.x.com')
        self.assertEqual(qs.count(), 1)
        a = qs.get()
        self.assertEqual(a.scope_tier, 'owned_host')
        self.assertEqual(a.parent.value, 'x.com')
        self.assertEqual(a.parent.kind, 'root_domain')
        self.assertEqual(inv.run_hostnames(self.p, self.scan.id), ['a.x.com'])
        self.assertEqual(inv.run_hostnames(self.p, self.scan.id + 1), [])

    def test_co_brand_not_promoted(self):
        Asset.objects.create(project=self.p, kind='hostname', value='cb.x.com', scope_tier='co_brand')
        save_host('cb.x.com', ctx=self.ctx)
        self.assertEqual(Asset.objects.get(project=self.p, value='cb.x.com').scope_tier, 'co_brand')

    def test_names_the_scan_must_not_take_are_refused(self):
        ctx = dict(self.ctx, out_of_scope_subdomains=['skip.x.com'])
        for name in ('not a host!', 'skip.x.com', 'a.other.org'):
            self.assertIsNone(save_host(name, ctx=ctx), name)
        self.assertFalse(Asset.objects.filter(kind='hostname').exists())

    def test_only_the_root_or_a_real_subdomain_is_a_host_of_the_scan(self):
        for name in ('x.com.evil.org', 'notx.com', 'evilx.com', 'x.com.edgekey.net', 'a.x.com.evil.org', 'x.comx'):
            self.assertIsNone(save_host(name, ctx=self.ctx), name)
        for name in ('x.com', 'a.x.com', 'a.b.x.com'):
            self.assertIsNotNone(save_host(name, ctx=self.ctx), name)
        self.assertEqual(sorted(Asset.objects.filter(kind='hostname').values_list('value', flat=True)),
                         ['a.b.x.com', 'a.x.com', 'x.com'])

    def test_a_root_spelled_with_case_or_a_trailing_dot_still_owns_its_subdomains(self):
        self.domain.name = 'X.com.'
        self.domain.save()
        self.assertIsNotNone(save_host('a.x.com', ctx=self.ctx))

    def test_stamps_from_two_interleaved_scans_both_survive(self):
        other = ScanHistory.objects.create(domain=self.domain, scan_type=self.scan.scan_type,
                                           start_scan_date=timezone.now())
        save_host('a.x.com', ctx=self.ctx)
        stale = Asset.objects.get(value='a.x.com', kind='hostname')  # scan B read the row here ...
        save_host('a.x.com', ctx=dict(self.ctx, scan_history_id=other.id))  # ... scan C stamps it ...
        with mock.patch.object(Asset.objects, 'get_or_create', side_effect=lambda **kw: (stale, False)):
            third = ScanHistory.objects.create(domain=self.domain, scan_type=self.scan.scan_type,
                                               start_scan_date=timezone.now())
            save_host('a.x.com', ctx=dict(self.ctx, scan_history_id=third.id))  # ... and B writes from its stale copy
        for scan in (self.scan, other, third):
            self.assertEqual(inv.run_hostnames(self.p, scan.id), ['a.x.com'], scan.id)

    def test_the_same_stamp_twice_is_one_entry(self):
        save_host('a.x.com', ctx=self.ctx)
        save_host('a.x.com', ctx=self.ctx)
        a = Asset.objects.get(value='a.x.com', kind='hostname')
        self.assertEqual([s['evidence'] for s in a.sources].count(f'scan:{self.scan.id}'), 1)

    def test_a_domain_without_a_project_saves_nothing(self):
        orphan = Domain.objects.create(name='y.com', project=None, insert_date=timezone.now())
        self.scan.domain = orphan
        self.scan.save()
        self.assertIsNone(save_host('a.y.com', ctx=dict(self.ctx, domain_id=orphan.id)))

    def test_run_host_only_finds_hosts_this_scan_saved(self):
        save_host('a.x.com', ctx=self.ctx)
        inv.upsert_hostname_asset(self.p, 'old.x.com', source='discovery', evidence=f'scan:{self.scan.id + 1}')
        self.assertEqual(inv.run_host(self.p, self.scan.id, 'A.x.com.').value, 'a.x.com')
        self.assertIsNone(inv.run_host(self.p, self.scan.id, 'old.x.com'))
        self.assertIsNone(inv.run_host(None, self.scan.id, 'a.x.com'))


class SaveIpAddressTest(SaveHostTest):
    def test_cdn_persisted_and_ip_asset_linked(self):
        host = save_host('h.x.com', ctx=self.ctx)
        ip, created = save_ip_address('1.2.3.4', host, cdn=True)
        self.assertTrue(created)
        self.assertTrue(IpAddress.objects.get(address='1.2.3.4').is_cdn)
        self.assertTrue(Asset.objects.filter(project=self.p, kind='ip', value='1.2.3.4').exists())
        self.assertIn(ip, host.ip_addresses.all())

    def test_no_host_ok(self):
        ip, _ = save_ip_address('5.6.7.8')
        self.assertIsNotNone(ip)
        self.assertFalse(Asset.objects.filter(kind='ip').exists())

    def test_invalid_ip_is_refused(self):
        self.assertEqual(save_ip_address('not-an-ip'), (None, False))


class RecordHostStateTest(SaveHostTest):
    def test_state_and_technologies_land_on_the_hostname_asset(self):
        from startScan.models import Technology
        host = save_host('m.x.com', ctx=self.ctx)
        tech = Technology.objects.create(name='nginx')
        state = dict(http_status=200, page_title='T', webserver='nginx', content_type='text/html', content_length=42,
                     response_time=0.5, cname='c.cdn.net', is_cdn=True, cdn_name='cf', screenshot_path='a/b.png')
        asset = inv.record_host_state(self.p, 'M.x.com', technologies=[tech], **state)
        self.assertEqual(asset.id, host.id)
        asset.refresh_from_db()
        for f, v in state.items():
            self.assertEqual(getattr(asset, f), v, f)
        self.assertEqual(list(asset.technologies.all()), [tech])
        self.assertIn({'source': 'probe', 'evidence': 'httpx'}, [{k: s[k] for k in ('source', 'evidence')} for s in asset.sources])

    def test_a_later_partial_write_keeps_the_earlier_fields(self):
        save_host('m.x.com', ctx=self.ctx)
        inv.record_host_state(self.p, 'm.x.com', http_status=200, page_title='T')
        inv.record_host_state(self.p, 'm.x.com', screenshot_path='s.png')
        a = Asset.objects.get(value='m.x.com', kind='hostname')
        self.assertEqual((a.http_status, a.page_title, a.screenshot_path), (200, 'T', 's.png'))

    def test_no_project_returns_none(self):
        self.assertIsNone(inv.record_host_state(None, 'n.x.com', http_status=200))
