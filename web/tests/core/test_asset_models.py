from django.db import IntegrityError
from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from startScan.asset_models import Asset, Tag


def mk_project(slug='p'):
    return Project.objects.create(name=slug, slug=slug, insert_date=timezone.now())


class AssetModelTest(TestCase):
    def setUp(self):
        self.project = mk_project()

    def test_unique_per_project_kind_value(self):
        Asset.objects.create(project=self.project, kind='hostname', value='a.x.com')
        with self.assertRaises(IntegrityError):
            Asset.objects.create(project=self.project, kind='hostname', value='a.x.com')

    def test_same_value_different_kind_ok(self):
        Asset.objects.create(project=self.project, kind='hostname', value='x.com')
        Asset.objects.create(project=self.project, kind='root_domain', value='x.com')  # no raise

    def test_active_scan_allowed_by_tier(self):
        owned = Asset(project=self.project, kind='hostname', value='h', scope_tier='owned_host')
        root = Asset(project=self.project, kind='root_domain', value='r', scope_tier='owned_root')
        cand = Asset(project=self.project, kind='hostname', value='c', scope_tier='candidate')
        rej = Asset(project=self.project, kind='hostname', value='j', scope_tier='rejected')
        cob = Asset(project=self.project, kind='hostname', value='b', scope_tier='co_brand', active_authorized=False)
        cob_ok = Asset(project=self.project, kind='hostname', value='b2', scope_tier='co_brand', active_authorized=True)
        self.assertTrue(owned.is_active_scan_allowed)
        self.assertTrue(root.is_active_scan_allowed)
        self.assertFalse(cand.is_active_scan_allowed)
        self.assertFalse(rej.is_active_scan_allowed)
        self.assertFalse(cob.is_active_scan_allowed)
        self.assertTrue(cob_ok.is_active_scan_allowed)

    def test_lifecycle_missed_then_seen(self):
        a = Asset.objects.create(project=self.project, kind='hostname', value='h', state='active')
        for _ in range(3):
            a.mark_missing_or_seen(seen=False)
        self.assertEqual(a.state, 'missing')
        self.assertEqual(a.missed_count, 3)
        a.mark_missing_or_seen(seen=True)
        self.assertEqual(a.state, 'active')
        self.assertEqual(a.missed_count, 0)

    def test_missed_below_threshold_stays_active(self):
        a = Asset.objects.create(project=self.project, kind='hostname', value='h', state='active')
        a.mark_missing_or_seen(seen=False)
        a.mark_missing_or_seen(seen=False)
        self.assertEqual(a.state, 'active')


class ScanRunJobTest(TestCase):
    def setUp(self):
        from startScan.asset_models import ScanRun, ScanJob
        self.ScanRun, self.ScanJob = ScanRun, ScanJob
        self.project = mk_project('r')
        self.root = Asset.objects.create(project=self.project, kind='root_domain', value='x.com', scope_tier='owned_root')

    def test_run_and_job(self):
        run = self.ScanRun.objects.create(project=self.project, root_asset=self.root, profile='normal',
                                          start_scan_date=timezone.now())
        job = self.ScanJob.objects.create(run=run, asset=self.root, stage='discovery')
        self.assertEqual(job.run_id, run.id)
        self.assertEqual(run.jobs.count(), 1)
        self.assertEqual(job.stage, 'discovery')

    def test_scanrun_mode_defaults_to_full(self):
        run = self.ScanRun.objects.create(project=self.project, root_asset=self.root, start_scan_date=timezone.now())
        self.assertEqual(run.mode, 'full')
        run2 = self.ScanRun.objects.create(project=self.project, root_asset=self.root, mode='asm',
                                           start_scan_date=timezone.now())
        self.assertEqual(run2.mode, 'asm')


class VulnerabilityAssetFkTest(TestCase):
    def test_vulnerability_links_to_asset_and_set_null_on_delete(self):
        from startScan.models import Vulnerability
        project = mk_project('v')
        asset = Asset.objects.create(project=project, kind='hostname', value='a.x.com')
        vuln = Vulnerability.objects.create(name='v', severity=0, asset=asset)
        vuln.refresh_from_db()
        self.assertEqual(vuln.asset_id, asset.id)
        self.assertEqual(asset.vulnerabilities.count(), 1)
        asset.delete()
        vuln.refresh_from_db()
        self.assertIsNone(vuln.asset_id)
