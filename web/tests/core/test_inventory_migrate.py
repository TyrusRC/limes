from django.test import TestCase

from startScan import inventory_migrate as im


class NormalizeTest(TestCase):
    def test_normalize(self):
        self.assertEqual(im.normalize_host('A.X.COM.'), 'a.x.com')
        self.assertEqual(im.normalize_host('  b.x.com '), 'b.x.com')
