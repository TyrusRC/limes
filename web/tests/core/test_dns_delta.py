from unittest import mock

import dns.resolver
from django.test import SimpleTestCase

from limes import dns_delta, monitor
from limes.tasks import inventory
from startScan.models import Asset, ChangeEvent
from tests.core.test_monitor import Base, public
from tests.core.test_safe_fetch import PUBLIC, stub


def rec(a=(), aaaa=(), cname=()):
    return {'a': list(a), 'aaaa': list(aaaa), 'cname': list(cname)}


class SignificantTest(SimpleTestCase):
    def test_cdn_rotation_is_silent(self):
        self.assertIsNone(dns_delta.significant(rec(['1.2.3.4']), rec(['1.2.3.9'])))
        self.assertIsNone(dns_delta.significant(rec(aaaa=['2001:db8:1::1']), rec(aaaa=['2001:db8:1:5::1'])))

    def test_moves_and_cname_and_resolution(self):
        s = dns_delta.significant
        self.assertEqual(s(rec(['1.2.3.4']), rec(['5.6.7.8'])), 'moved')
        self.assertEqual(s(rec(['1.2.3.4'], cname=['a.cdn.net']), rec(['1.2.3.4'], cname=['B.other.net.'])), 'cname')
        self.assertIsNone(s(rec(['1.2.3.4'], cname=['A.cdn.net']), rec(['1.2.3.4'], cname=['a.cdn.net'])))
        self.assertEqual(s(rec(['1.2.3.4']), rec()), 'unresolved')
        self.assertEqual(s(rec(), rec(['1.2.3.4'])), 'resolved')
        self.assertIsNone(s(rec(['1.2.3.4']), rec(['1.2.3.4'], ['2001:db8::1'])))  # gains v6, v4 /24 unchanged
        self.assertIsNone(s(rec(['1.2.3.4'], ['2001:db8:1::1']), rec(['1.2.3.9'], ['2001:db9::1'])))  # v4 stayed in its /24
        self.assertEqual(s(rec(['1.2.3.4'], ['2001:db8:1::1']), rec(['5.6.7.8'], ['2001:db9::1'])), 'moved')


class ObserveTest(Base):
    def host(self, value='h.x.com', **kw):
        return self.asset('hostname', value, **kw)

    def test_observe_emits_once(self):
        h = self.host()
        self.assertIsNone(dns_delta.observe(h, rec(['1.2.3.4'])))  # silent baseline
        self.assertEqual(self.reload(h).enrichment['dns']['a'], ['1.2.3.4'])
        self.assertIn('fetched_at', h.enrichment['dns'])
        self.assertIsNone(dns_delta.observe(h, rec(['1.2.3.4'])))
        ev = dns_delta.observe(h, rec(['5.6.7.8']))
        self.assertEqual(ChangeEvent.objects.filter(kind='dns_changed').count(), 1)
        self.assertEqual(ev.detail['before']['a'], ['1.2.3.4'])
        self.assertIn('moved to new addresses', ev.title)
        self.assertIsNone(dns_delta.observe(h, rec(['5.6.7.8'])))
        self.assertEqual(ChangeEvent.objects.filter(kind='dns_changed').count(), 1)
        self.assertIn('changed_at', self.reload(h).enrichment['dns'])

    def test_candidate_and_ip_record_nothing(self):
        c = self.host('c.x.com', tier='candidate')
        dns_delta.observe(c, rec(['1.2.3.4']))
        dns_delta.observe(c, rec(['5.6.7.8']))
        self.assertNotIn('dns', self.reload(c).enrichment or {})
        ip = self.asset('ip', '9.9.9.9')
        self.assertIsNone(dns_delta.observe(ip, rec(['5.6.7.8'])))
        self.assertFalse(ChangeEvent.objects.exists())

    def test_caps_and_watched(self):
        h = self.host()
        dns_delta.observe(h, rec([f'1.2.{i}.1' for i in range(30)]), watched=True)
        d = self.reload(h).enrichment['dns']
        self.assertEqual(len(d['a']), 20)
        self.assertIn('watched_at', d)

    def test_record_resolution_and_nxdomain_paths(self):
        h = self.host()
        inventory.record_resolution(h, rec([PUBLIC], cname=['a.cdn.net']))
        inventory.record_resolution(h, rec([PUBLIC], cname=['b.other.net']))
        self.assertEqual([e.detail['reason'] for e in ChangeEvent.objects.filter(kind='dns_changed')], ['cname'])
        g = self.host('g.x.com')
        self.check(g, public('g.x.com'))
        self.check(g, {})  # A and AAAA now NXDOMAIN
        self.assertEqual([e.detail['reason'] for e in ChangeEvent.objects.filter(kind='dns_changed', asset=g)],
                         ['unresolved'])
        s = self.host('s.x.com')
        self.check(s, public('s.x.com'))
        self.check(s, {('s.x.com', 'A'): dns.resolver.NoNameservers, ('s.x.com', 'AAAA'): dns.resolver.NoNameservers})
        self.assertFalse(ChangeEvent.objects.filter(kind='dns_changed', asset=s).exists())
