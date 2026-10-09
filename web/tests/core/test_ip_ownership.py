from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.tasks import inventory
from startScan.models import Asset


class IpOwnershipTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        Asset.objects.create(project=self.p, kind='cidr', value='203.0.114.0/24', scope_tier='owned_host')
        Asset.objects.create(project=self.p, kind='cidr', value='198.51.99.0/24', scope_tier='candidate')

    def tier(self, address):
        return inventory.upsert_ip_asset(self.p, address, source='dns', evidence='host:a').scope_tier

    def test_new_ip_inside_owned_cidr_is_owned(self):
        self.assertEqual(self.tier('203.0.114.7'), 'owned_host')

    def test_new_ip_elsewhere_is_dependency(self):
        self.assertEqual(self.tier('104.16.1.1'), 'dependency')
        self.assertEqual(self.tier('198.51.99.4'), 'dependency')  # candidate CIDR proves nothing
        self.assertEqual(self.tier('10.1.2.3'), 'dependency')

    def test_existing_tier_never_changes(self):
        Asset.objects.create(project=self.p, kind='ip', value='8.8.8.8', scope_tier='owned_host')
        Asset.objects.create(project=self.p, kind='ip', value='203.0.114.9', scope_tier='dependency')
        self.assertEqual(self.tier('8.8.8.8'), 'owned_host')
        self.assertEqual(self.tier('203.0.114.9'), 'dependency')

    def test_dependency_is_not_scannable(self):
        a = Asset.objects.create(project=self.p, kind='ip', value='9.9.9.9', scope_tier='dependency')
        self.assertFalse(a.is_active_scan_allowed)
