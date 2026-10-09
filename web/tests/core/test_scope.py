import ipaddress

from django.test import SimpleTestCase

from limes import scope


class ReservedTest(SimpleTestCase):
    def test_reserved_and_public(self):
        for bad in ('10.0.0.1', '127.0.0.1', '169.254.1.1', '100.64.0.1', '224.0.0.1', '0.0.0.0',
                    '::1', 'fe80::1', '64:ff9b::a00:1', '2002:a00:1::', '::ffff:10.0.0.1', 'nonsense', ''):
            self.assertTrue(scope.is_reserved_ip(bad), bad)
        for ok in ('8.8.8.8', '2606:4700:4700::1111', '::ffff:8.8.8.8'):
            self.assertFalse(scope.is_reserved_ip(ok), ok)

    def test_parse_ip_collapses_mapped(self):
        self.assertEqual(str(scope.parse_ip('::ffff:8.8.8.8')), '8.8.8.8')
        self.assertIsNone(scope.parse_ip('example.com'))

    def test_reserved_network_overlap(self):
        self.assertTrue(scope.is_reserved_network(ipaddress.ip_network('0.0.0.0/0')))
        self.assertTrue(scope.is_reserved_network(ipaddress.ip_network('2002::/16')))
        self.assertFalse(scope.is_reserved_network(ipaddress.ip_network('8.8.8.0/24')))


class TargetHostTest(SimpleTestCase):
    def test_forms(self):
        cases = {
            'https://App.Example.com:8443/x?y=1': 'app.example.com',
            'app.example.com': 'app.example.com',
            'app.example.com.': 'app.example.com',
            'app.example.com:80': 'app.example.com',
            '10.0.0.1': '10.0.0.1',
            'http://[::ffff:10.0.0.1]/': '::ffff:10.0.0.1',
            '[2606:4700::1]:443': '2606:4700::1',
        }
        for raw, host in cases.items():
            self.assertEqual(scope.target_host(raw), host, raw)

    def test_empty_or_broken(self):
        for raw in ('', '   ', None, 'http://[::1'):
            self.assertIsNone(scope.target_host(raw), raw)
