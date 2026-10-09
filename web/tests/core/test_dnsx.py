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

    def test_non_list_values_are_ignored(self):
        out = dnsx.parse(['{"host":"n.example.com","a":5,"cname":"x"}'])
        self.assertEqual(out['n.example.com'], {'a': [], 'aaaa': [], 'cname': []})

    def test_ips_are_canonical_and_family_checked(self):
        line = ('{"host":"v.example.com","a":["::1","1.2.3.4"],'
                '"aaaa":["2606:2800:0220:0001::1","10.0.0.1","fe80::1%eth0"]}')
        out = dnsx.parse([line])
        self.assertEqual(out['v.example.com']['a'], ['1.2.3.4'])
        self.assertEqual(out['v.example.com']['aaaa'], ['2606:2800:220:1::1'])
