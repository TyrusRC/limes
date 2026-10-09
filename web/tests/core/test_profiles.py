from django.test import SimpleTestCase

from limes import profiles


class ProfileTest(SimpleTestCase):
    def test_four_profiles(self):
        self.assertEqual(set(profiles.PROFILES), {'quick', 'normal', 'thorough', 'passive'})

    def test_passive_disables_active(self):
        self.assertEqual(profiles.PROFILES['passive'].assay_profile, 'passive')
        self.assertFalse(profiles.PROFILES['passive'].nmap_enabled)

    def test_resolve_unknown_is_normal(self):
        self.assertEqual(profiles.resolve_profile('nope').name, 'normal')

    def test_thorough_deeper_than_quick(self):
        self.assertGreater(profiles.PROFILES['thorough'].crawl_depth, profiles.PROFILES['quick'].crawl_depth)

    def test_map_engine_thorough(self):
        y = "subdomain_discovery: {}\nport_scan: {'enable_nmap': true}\nvulnerability_scan: {}\nfetch_url: {}\nscreenshot: {}"
        self.assertEqual(profiles.map_engine_to_profile(y), 'thorough')

    def test_map_engine_passive(self):
        self.assertEqual(profiles.map_engine_to_profile("subdomain_discovery: {}"), 'passive')

    def test_map_engine_garbage_is_normal(self):
        self.assertEqual(profiles.map_engine_to_profile(":::not yaml:::"), 'normal')
