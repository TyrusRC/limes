from django.test import SimpleTestCase

from limes import profiles


class EngineProfileMappingTest(SimpleTestCase):
    def test_representative_configs_map_to_valid_profiles(self):
        configs = [
            'subdomain_discovery: {}\n',
            'subdomain_discovery: {}\nport_scan: {}\nfetch_url: {}\n',
            'vulnerability_scan: {}\nscreenshot: {}\n',
        ]
        got = [profiles.map_engine_to_profile(c) for c in configs]
        self.assertEqual(got, ['passive', 'normal', 'thorough'])
        for name in got:
            self.assertIn(name, profiles.PROFILES)

    def test_unmappable_yields_normal(self):
        for bad in ['', ': : [', 'just a string', '- a\n- b']:
            self.assertEqual(profiles.map_engine_to_profile(bad), 'normal')
