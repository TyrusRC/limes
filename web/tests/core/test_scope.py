import ipaddress
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from dashboard.models import Project
from limes import scope
from startScan.models import Asset, IpAddress


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
            '2606:4700::1': '2606:4700::1',
            'ok.x.com\t': 'ok.x.com',
            '  ok.x.com\n': 'ok.x.com',
            '::ffff:10.0.0.1': '::ffff:10.0.0.1',
        }
        for raw, host in cases.items():
            self.assertEqual(scope.target_host(raw), host, raw)

    def test_empty_or_broken(self):
        for raw in ('', '   ', None, 'http://[::1', 'http://10.0.0.1\\@ok.x.com/', 'http://ok.x.com /',
                    'ok.x\tcom', 'ok\x00.x.com'):
            self.assertIsNone(scope.target_host(raw), raw)


class GuardTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.other = Project.objects.create(name='o', slug='o', insert_date=timezone.now())

    def host(self, value, tier='owned_host', ips=(), authorized=False, project=None):
        a = Asset.objects.create(project=project or self.p, kind='hostname', value=value,
                                 scope_tier=tier, active_authorized=authorized)
        for ip in ips:
            a.ip_addresses.add(IpAddress.objects.create(address=ip))
        return a

    def test_contact_requires_resolution_and_public_ips(self):
        self.host('ok.x.com', ips=['8.8.8.8'])
        self.host('mixed.x.com', ips=['8.8.8.8', '10.0.0.5'])
        self.host('10.0.0.1.nip.io', ips=['10.0.0.1'])
        self.host('unresolved.x.com')
        allowed, refused = scope.may_contact(self.p, [
            'https://ok.x.com/a', 'mixed.x.com', '10.0.0.1.nip.io', 'unresolved.x.com',
            'unknown.x.com', '8.8.4.4', 'http://[::ffff:10.0.0.1]/'])
        self.assertEqual(allowed, ['https://ok.x.com/a', '8.8.4.4'])
        reasons = dict(refused)
        self.assertIn('10.0.0.5', reasons['mixed.x.com'])
        self.assertIn('not resolved', reasons['unresolved.x.com'])
        self.assertIn('not resolved', reasons['unknown.x.com'])

    def test_attack_requires_scannable_tier(self):
        for value, tier, auth in (('own.x.com', 'owned_host', False), ('dep.x.com', 'dependency', False),
                                  ('cand.x.com', 'candidate', False), ('rej.x.com', 'rejected', False),
                                  ('cb.x.com', 'co_brand', False), ('cba.x.com', 'co_brand', True)):
            self.host(value, tier=tier, ips=['8.8.8.8'], authorized=auth)
        targets = ['own.x.com', 'dep.x.com', 'cand.x.com', 'rej.x.com', 'cb.x.com', 'cba.x.com', '1.1.1.1']
        allowed, _ = scope.may_attack(self.p, targets)
        self.assertEqual(allowed, ['own.x.com', 'cba.x.com'])
        allowed, _ = scope.may_attack(self.p, targets, allow_co_brand=False)
        self.assertEqual(allowed, ['own.x.com'])

    def test_project_isolation(self):
        self.host('theirs.x.com', ips=['8.8.8.8'], project=self.other)
        self.assertEqual(scope.may_attack(self.p, ['theirs.x.com'])[0], [])

    def test_fails_closed(self):
        self.host('ok.x.com', ips=['8.8.8.8'])
        self.assertEqual(scope.may_attack(None, ['ok.x.com'])[0], [])
        with mock.patch('limes.scope._assets_by_value', side_effect=RuntimeError('db down')):
            allowed, refused = scope.may_contact(self.p, ['ok.x.com'])
        self.assertEqual(allowed, [])
        self.assertIn('scope check failed', refused[0][1])

    def test_mixed_kind_same_value_all_must_be_scannable(self):
        a = self.host('example.com', tier='owned_root', ips=['8.8.8.8'])
        a.kind = 'root_domain'
        a.save()
        self.host('example.com', tier='rejected')
        self.assertEqual(scope.may_attack(self.p, ['example.com'])[0], [])

    def test_dependency_never_vetoes_but_never_grants(self):
        for tier, kind in (('owned_root', 'root_domain'), ('dependency', 'ip')):
            Asset.objects.create(project=self.p, kind=kind, value='203.0.114.10', scope_tier=tier)
        Asset.objects.create(project=self.p, kind='ip', value='9.9.9.9', scope_tier='dependency')
        Asset.objects.create(project=self.p, kind='ip', value='8.8.4.4', scope_tier='rejected')
        allowed, _ = scope.may_attack(self.p, ['203.0.114.10', '9.9.9.9', '8.8.4.4'])
        self.assertEqual(allowed, ['203.0.114.10'])

    def test_contact_refuses_loopback_literal_and_backslash_confusion(self):
        self.host('ok.x.com', ips=['8.8.8.8'])
        allowed, _ = scope.may_contact(self.p, ['127.0.0.1', 'http://10.0.0.1\\@ok.x.com/'])
        self.assertEqual(allowed, [])
