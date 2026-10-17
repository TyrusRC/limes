from django.test import SimpleTestCase, override_settings
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
        self.assertEqual(classify_asset_entry('2606:4700::/116')['kind'], 'cidr')
        self.assertEqual(classify_asset_entry('2606:4700:4700::1111')['kind'], 'ip')

    def test_rejects_internal_only_tlds(self):
        for bad in ('foo.local', 'x.internal', 'a.b.localhost', 'svc.test', 'h.invalid',
                    'site.example', 'nas.home.arpa', 'pc.lan', 'dc.corp'):
            self.assertIsNotNone(classify_asset_entry(bad)['error'], bad)

    def test_ipv4_mapped_ipv6_collapses_to_ipv4(self):
        r = classify_asset_entry('::ffff:8.8.8.8')
        self.assertEqual((r['kind'], r['value']), ('ip', '8.8.8.8'))

    def test_rejects_public_suffix_as_root(self):
        r = classify_asset_entry('co.uk')
        self.assertIsNone(r['kind'])
        self.assertIn('public suffix', r['error'])
        self.assertIsNone(classify_asset_entry('example.co.uk')['error'])

    def test_private_suffix_is_not_a_root(self):
        self.assertIsNotNone(classify_asset_entry('github.io')['error'])
        self.assertIsNone(classify_asset_entry('myorg.github.io')['error'])

    def test_psl_roots(self):
        self.assertEqual(classify_asset_entry('example.co.uk')['kind'], 'root_domain')
        self.assertEqual(classify_asset_entry('www.example.co.uk')['kind'], 'hostname')
        self.assertEqual(classify_asset_entry('www.example.com')['kind'], 'hostname')
        self.assertEqual(classify_asset_entry('foo.github.io')['kind'], 'root_domain')
        self.assertIsNotNone(classify_asset_entry('co.uk')['error'])

    def test_start_end_range(self):
        r = classify_asset_entry('8.8.8.0-8.8.8.255')
        self.assertEqual((r['kind'], r['values'], r['value']), ('cidr', ['8.8.8.0/24'], '8.8.8.0/24'))
        r = classify_asset_entry('8.8.8.1 - 8.8.8.6')
        self.assertEqual(r['values'], ['8.8.8.1/32', '8.8.8.2/31', '8.8.8.4/31', '8.8.8.6/32'])
        self.assertEqual(r['value'], '8.8.8.1/32')
        for bad in ('8.8.8.9-8.8.8.1', '8.8.8.1-2606:4700::1', '8.8.8.1-8.8.8.2-8.8.8.3', '8.8.8.1-foo'):
            self.assertIsNotNone(classify_asset_entry(bad)['error'], bad)
        r = classify_asset_entry('a-b.example.com')
        self.assertEqual((r['kind'], r['values']), ('hostname', ['a-b.example.com']))

    def test_asn_entry(self):
        for ok in ('AS12345', 'as12345', 'AS 12345'):
            r = classify_asset_entry(ok)
            self.assertEqual((r['kind'], r['value'], r['values']), ('asn', 'AS12345', ['AS12345']), ok)
        self.assertIn('AS12345', classify_asset_entry('12345')['error'])
        for bad in ('AS0', 'AS23456', 'AS64512', 'AS4200000000', 'AS4294967296', 'AS4294967295'):
            self.assertIsNotNone(classify_asset_entry(bad)['error'], bad)

    def test_size_refusals(self):
        r = classify_asset_entry('8.8.0.0/19')
        self.assertIn('8192', r['error'])
        self.assertIn('4096', r['error'])
        self.assertIsNotNone(classify_asset_entry('8.8.0.0-8.8.16.0')['error'])
        self.assertIsNone(classify_asset_entry('8.8.0.0/20')['error'])
        self.assertIsNotNone(classify_asset_entry('2606:4700::-2606:4700::1000')['error'])
        self.assertIsNone(classify_asset_entry('2606:4700::-2606:4700::fff')['error'])

    def test_range_touching_reserved_refused(self):
        r = classify_asset_entry('192.0.1.0-192.0.2.255')
        self.assertIsNotNone(r['error'])
        self.assertIsNone(r['kind'])
        self.assertEqual(r['values'], [])

    @override_settings(RANGE_ENUMERATION=False)
    def test_enumeration_off_warning(self):
        for e in ('8.8.8.0/24', 'AS12345'):
            self.assertIn('enumeration is off', classify_asset_entry(e)['warning'], e)
        self.assertIsNone(classify_asset_entry('example.com')['warning'])

    @override_settings(RANGE_ENUMERATION=True)
    def test_enumeration_on_no_warning(self):
        self.assertIsNone(classify_asset_entry('8.8.8.0/24')['warning'])
