import pathlib

from django.test import SimpleTestCase

from limes.pipeline import amass

FIX = pathlib.Path(__file__).parent / 'fixtures' / 'amass_subs_sample.txt'


class AmassArgvTest(SimpleTestCase):
    def test_passive_enum(self):
        argv = amass.build_enum_argv('example.com', '/root/.config/amass', active=False, brute=False, wordlist=None)
        self.assertEqual(argv[:2], ['amass', 'enum'])
        self.assertIn('-d', argv)
        self.assertIn('example.com', argv)
        self.assertNotIn('-active', argv)
        self.assertNotIn('-brute', argv)

    def test_active_brute_with_wordlist(self):
        argv = amass.build_enum_argv('example.com', '/root/.config/amass', active=True, brute=True, wordlist='/w.txt')
        self.assertIn('-active', argv)
        self.assertIn('-brute', argv)
        self.assertIn('-w', argv)
        self.assertIn('/w.txt', argv)

    def test_subs_argv(self):
        argv = amass.build_subs_argv('example.com', '/root/.config/amass')
        self.assertEqual(argv[:2], ['amass', 'subs'])
        self.assertIn('-names', argv)

    def test_parse_filters_to_domain_and_dedupes(self):
        out = FIX.read_text()
        names = amass.parse_subs(out, 'example.com')
        self.assertTrue(all(n == 'example.com' or n.endswith('.example.com') for n in names))
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(all(n == n.lower() for n in names))

    def test_parse_empty_returns_empty(self):
        self.assertEqual(amass.parse_subs('', 'example.com'), [])
