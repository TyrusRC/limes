from django.test import SimpleTestCase
from api.asset_add import classify_asset_entry

class ClassifyEntryTest(SimpleTestCase):
    def test_root_and_host(self):
        self.assertEqual(classify_asset_entry('Example.com')['kind'], 'root_domain')
        self.assertEqual(classify_asset_entry('a.example.com')['kind'], 'hostname')
    def test_ip_and_cidr(self):
        self.assertEqual(classify_asset_entry('8.8.8.8')['kind'], 'ip')
        self.assertEqual(classify_asset_entry('8.8.8.0/24')['kind'], 'cidr')
    def test_rejects_private_reserved_loopback_linklocal(self):
        for bad in ('10.0.0.1','127.0.0.1','192.168.0.0/16','169.254.1.1','::1','fe80::1'):
            self.assertIsNotNone(classify_asset_entry(bad)['error'], bad)
    def test_rejects_wildcard_and_garbage(self):
        self.assertIsNotNone(classify_asset_entry('*.example.com')['error'])
        self.assertIsNotNone(classify_asset_entry('not a domain')['error'])
    def test_punycode_idn(self):
        r = classify_asset_entry('bücher.de')
        self.assertEqual(r['kind'] in ('root_domain','hostname'), True)
        self.assertEqual(r['value'], 'xn--bcher-kva.de')
    def test_blank(self):
        self.assertIsNotNone(classify_asset_entry('   ')['error'])

    def test_rejects_supernets_cgnat_and_non_global(self):
        for bad in ('0.0.0.0/0', '1.1.1.1/0', '0.0.0.0/1', '128.0.0.0/1', '::/0',
                    '10.0.0.0/8', '100.64.0.0/10', '100.64.0.1', '0.0.0.0', '224.0.0.1'):
            r = classify_asset_entry(bad)
            self.assertIsNotNone(r['error'], bad)
            self.assertIsNone(r['kind'], bad)

    def test_normalization(self):
        r = classify_asset_entry(' 8.8.8.8 ')
        self.assertEqual((r['kind'], r['value']), ('ip', '8.8.8.8'))
        r = classify_asset_entry('Example.COM.')
        self.assertEqual((r['kind'], r['value']), ('root_domain', 'example.com'))

    def test_rejects_bare_tld_and_url(self):
        self.assertIsNotNone(classify_asset_entry('com')['error'])
        self.assertIsNotNone(classify_asset_entry('http://x.com')['error'])

    def test_rejects_ipv6_ranges_that_reach_private_space(self):
        # NAT64 / 6to4 / Teredo / benchmarking / discard can all embed or route to internal v4.
        for bad in ('64:ff9b::a00:1', '64:ff9b::/96', '64:ff9b:1::/48', '2002::/16', '2001::/32',
                    '2001:2::/48', '100::/64', '5f00::1', '2001:20::1'):
            r = classify_asset_entry(bad)
            self.assertIsNotNone(r['error'], bad)
        self.assertEqual(classify_asset_entry('2606:4700::/32')['kind'], 'cidr')
        self.assertEqual(classify_asset_entry('2606:4700:4700::1111')['kind'], 'ip')

    def test_rejects_internal_only_tlds(self):
        for bad in ('foo.local', 'x.internal', 'a.b.localhost', 'svc.test', 'h.invalid',
                    'site.example', 'nas.home.arpa', 'pc.lan', 'dc.corp'):
            self.assertIsNotNone(classify_asset_entry(bad)['error'], bad)

    def test_ipv4_mapped_ipv6_collapses_to_ipv4(self):
        r = classify_asset_entry('::ffff:8.8.8.8')
        self.assertEqual((r['kind'], r['value']), ('ip', '8.8.8.8'))
