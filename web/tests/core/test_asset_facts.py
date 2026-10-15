from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.tasks import inventory
from startScan.models import Asset, AssetFact


class AssetFactTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.a = Asset.objects.create(project=self.p, kind='root_domain', value='x.com', scope_tier='candidate')

    def test_record_is_unique_and_refreshes_last_seen(self):
        f1 = inventory.record_fact(self.a, 'cert', '101', 'crtsh')
        first = f1.last_seen
        f2 = inventory.record_fact(self.a, 'cert', '101', 'crtsh')
        self.assertEqual(AssetFact.objects.filter(asset=self.a).count(), 1)
        self.assertGreaterEqual(f2.last_seen, first)

    def test_value_normalized_and_empty_ignored(self):
        f = inventory.record_fact(self.a, 'ns', ' NS1.X.COM ', 'dns')
        self.assertEqual(f.value, 'ns1.x.com')
        self.assertIsNone(inventory.record_fact(self.a, 'ns', '  ', 'dns'))

    def test_defaults(self):
        self.a.refresh_from_db()
        self.assertIsNone(self.a.confidence)
        self.assertIsNone(self.a.confidence_detail)
        self.assertEqual(Project.objects.get(pk=self.p.pk).brand_keywords, [])
