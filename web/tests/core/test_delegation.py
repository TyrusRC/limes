from unittest import mock

from celery.exceptions import SoftTimeLimitExceeded
from django.test import SimpleTestCase

import dns.exception
import dns.flags
import dns.message
import dns.nameserver
import dns.rcode
import dns.rrset

from limes.intel import delegation

PARENT = {'a.gtld-servers.net': '192.5.6.30', 'b.gtld-servers.net': '192.33.14.30'}
RESERVED = {'ns1.inside.example': '10.0.0.53'}
OURS = {'ns1.example.com': '45.33.10.1', 'ns2.example.com': '45.33.10.2'}


def fake_resolve(name, rdtype):
    if rdtype == 'NS':
        return {'net': sorted(PARENT), 'io': ['ns-tld.io'], 'github.io': ['dns1.p05.nsone.net']}.get(name, [])
    return [ip] if (ip := {**PARENT, **OURS, **RESERVED, 'ns-tld.io': '65.22.160.17', 'dns1.p05.nsone.net': '198.51.44.5'}.get(name)) else []


def referral(qname, ns, rcode=dns.rcode.NOERROR, aa=False, owner=None):
    r = dns.message.make_response(dns.message.make_query(qname, 'NS'))
    r.set_rcode(rcode)
    if aa:
        r.flags |= dns.flags.AA
    if ns:
        r.authority.append(dns.rrset.from_text(owner or qname, 3600, 'IN', 'NS', *[h + '.' for h in ns]))
    return r


def soa(qname, aa=True):
    r = dns.message.make_response(dns.message.make_query(qname, 'SOA'))
    if aa:
        r.flags |= dns.flags.AA
    r.answer.append(dns.rrset.from_text(qname, 3600, 'IN', 'SOA', 'ns1.example.com. hostmaster.example.com. 1 7200 900 1209600 300'))
    return r


class FakeDNS:
    """Answers by server IP; an exception instance in the table is raised (a timeout)."""

    def __init__(self, table):
        self.table, self.asked = table, []

    def __call__(self, qname, rdtype, ip):
        self.asked.append((qname, rdtype, ip))
        out = self.table.get((rdtype, ip))
        if isinstance(out, Exception):
            raise out
        if out is None:
            raise dns.exception.Timeout()
        return out


OK = ('ns1.example.com', 'ns2.example.com')


def ours_ok(qname='ours.net', ns=OK):
    return {('NS', '192.5.6.30'): referral(qname, ns), ('SOA', '45.33.10.1'): soa(qname)}


class VerifyTest(SimpleTestCase):
    def check(self, table, domain='ours.net', control=OK):
        fake = FakeDNS(table)
        return delegation.verify(domain, control, query=fake, resolve=fake_resolve), fake

    def test_matching_referral_and_authoritative_soa(self):
        (ok, reason), fake = self.check(ours_ok())
        self.assertEqual((ok, reason), (True, 'delegation verified at a.gtld-servers.net'))
        self.assertEqual({ip for _, _, ip in fake.asked}, {'192.5.6.30', '45.33.10.1'})  # registry + ours only

    def test_names_compare_case_and_dot_insensitive(self):
        (ok, _), _ = self.check(ours_ok(ns=('NS2.Example.COM', 'ns1.example.com')), domain='Ours.NET.')
        self.assertTrue(ok)

    def test_parent_delegates_elsewhere(self):
        (ok, reason), _ = self.check(ours_ok(ns=('ns1.attacker.net',)))
        self.assertEqual((ok, reason), (False, 'parent delegates elsewhere: ns1.attacker.net'))

    def test_partial_overlap_fails(self):
        (ok, _), _ = self.check(ours_ok(ns=OK + ('ns1.attacker.net',)))
        self.assertFalse(ok)

    def test_authoritative_answer_at_parent_is_not_a_delegation(self):
        (ok, reason), _ = self.check({('NS', '192.5.6.30'): referral('ours.net', OK, aa=True)})
        self.assertEqual((ok, reason), (False, 'no delegation at parent'))

    def test_nxdomain_and_foreign_owner_are_not_delegations(self):
        for resp in (referral('ours.net', None, rcode=dns.rcode.NXDOMAIN), referral('ours.net', OK, owner='other.net')):
            (ok, reason), _ = self.check({('NS', '192.5.6.30'): resp})
            self.assertEqual((ok, reason), (False, 'no delegation at parent'))

    def test_first_parent_timeout_falls_through(self):
        table = ours_ok()
        table[('NS', '192.33.14.30')] = table.pop(('NS', '192.5.6.30'))
        (ok, reason), _ = self.check(table)
        self.assertEqual((ok, reason), (True, 'delegation verified at b.gtld-servers.net'))

    def test_all_parents_unreachable(self):
        (ok, reason), _ = self.check({('NS', '192.5.6.30'): OSError('unreachable')})
        self.assertEqual((ok, reason), (False, 'parent unreachable'))

    def test_soa_without_aa_is_not_authoritative(self):
        table = ours_ok()
        table[('SOA', '45.33.10.1')] = soa('ours.net', aa=False)
        (ok, reason), _ = self.check(table)
        self.assertEqual((ok, reason), (False, 'not authoritative'))

    def test_nameservers_unreachable(self):
        table = ours_ok()
        del table[('SOA', '45.33.10.1')]
        (ok, reason), _ = self.check(table)
        self.assertEqual((ok, reason), (False, 'nameservers unreachable'))

    def test_private_suffix_tenant_fails_closed(self):
        # the platform answers for its tenants itself: no referral
        tenant = 'myorg.github.io'
        resp = referral(tenant, None, aa=True)
        (ok, reason), _ = self.check({('NS', '198.51.44.5'): resp}, domain=tenant)
        self.assertEqual((ok, reason), (False, 'no delegation at parent'))

    def test_unknown_suffix_has_no_parent_servers(self):
        (ok, reason), _ = self.check({}, domain='ours.invalid')
        self.assertEqual((ok, reason), (False, 'no parent servers'))

    def test_reserved_nameserver_address_is_never_queried(self):
        inside = ('ns1.inside.example',)
        table = {('NS', '192.5.6.30'): referral('ours.net', inside), ('SOA', '10.0.0.53'): soa('ours.net')}
        (ok, reason), fake = self.check(table, control=inside)
        self.assertEqual((ok, reason), (False, 'nameservers unreachable'))
        self.assertNotIn('10.0.0.53', {ip for _, _, ip in fake.asked})

    def test_truncated_referral_is_not_a_delegation(self):
        table = ours_ok()
        table[('NS', '192.5.6.30')].flags |= dns.flags.TC  # a partial NS set could equal ours
        (ok, reason), _ = self.check(table)
        self.assertEqual((ok, reason), (False, 'no delegation at parent'))

    def test_queries_are_non_recursive_with_edns(self):
        with mock.patch('dns.query.udp') as udp:
            delegation._udp_query('ours.net', 'NS', '192.5.6.30')
        q = udp.call_args[0][0]
        self.assertFalse(q.flags & dns.flags.RD)
        self.assertEqual(q.edns, 0)  # larger referrals fit without truncation

    def test_soft_time_limit_inside_the_resolver_propagates(self):
        # dnspython's resolver records per-server exceptions and retries; Celery's limit must escape
        with mock.patch.object(dns.nameserver.Do53Nameserver, 'query', side_effect=SoftTimeLimitExceeded()):
            with self.assertRaises(SoftTimeLimitExceeded):
                delegation._resolve('net', 'NS')

