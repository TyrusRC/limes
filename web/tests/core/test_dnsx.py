import os

from django.test import SimpleTestCase

from limes.pipeline import dnsx

FIXTURE = os.path.join(os.path.dirname(__file__), 'fixtures', 'dnsx_sample.jsonl')


class DnsxTest(SimpleTestCase):
    def test_argv_is_a_list_with_files(self):
        argv = dnsx.build_argv('/r/hosts.txt', '/r/out.jsonl')
        self.assertEqual(argv[0], 'dnsx')
        self.assertEqual(argv[argv.index('-l') + 1], '/r/hosts.txt')
        self.assertEqual(argv[argv.index('-o') + 1], '/r/out.jsonl')
        for flag in ('-a', '-aaaa', '-cname', '-resp', '-json', '-silent'):
            self.assertIn(flag, argv)

    def test_parse_fixture(self):
        with open(FIXTURE) as f:
            out = dnsx.parse(f)
        self.assertEqual(out['app.example.com'], {'a': ['93.184.216.34'], 'aaaa': ['2606:2800:220:1::1'],
                                                  'cname': ['edge.cdn.net']})
        self.assertEqual(out['alias.example.com'], {'a': [], 'aaaa': [], 'cname': ['app.example.com']})
        self.assertEqual(out['bad.example.com'], {'a': [], 'aaaa': [], 'cname': []})
        self.assertEqual(set(out), {'app.example.com', 'alias.example.com', 'bad.example.com'})
