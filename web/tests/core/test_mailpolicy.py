from unittest import mock

import dns.resolver
from django.core.cache import cache
from django.test import SimpleTestCase

from limes import mailpolicy
from limes.checks import dns as dns_checks, mailpolicy as pure
from limes.checks.catalogue import CHECKS, PROVISIONAL
from limes.intel import ratelimit
from startScan.models import RiskCheck
from tests.core.test_dangling import Body
from tests.core.test_dashboard_stats import Base
from tests.core.test_safe_fetch import FakeSession, PUBLIC, stub

IDS = ('email.mta_sts_missing', 'email.mta_sts_testing', 'email.tls_rpt_missing', 'email.bimi_invalid', 'dns.dangling_ns')
GOOD = b'version: STSv1\r\nmode: enforce\r\nmx: mx1.x.com\r\nmx: *.mail.x.com\r\nmax_age: 604800\r\n'
STS = ['v=STSv1; id=20260101']
RPT = ['v=TLSRPTv1; rua=mailto:r@x.com']


def obs(**kw):
    return {'mx': ['mx1.x.com'], 'sts': STS, 'policy': {'status': 200, 'body': GOOD}, 'tlsrpt': RPT, 'bimi': [],
            'dmarc': ['v=DMARC1; p=reject'], **kw}


def run(**kw):
    return {r.check: r for r in pure.evaluate(obs(**kw))}


class CatalogueTest(SimpleTestCase):
    def test_all_provisional_and_worded(self):
        for i in IDS:
            self.assertIn(i, PROVISIONAL)
            c = CHECKS[i]
            self.assertTrue(c.title and c.fix and c.group in ('email', 'dns'))


class PureTest(SimpleTestCase):
    def test_all_good_passes(self):
        self.assertEqual({r.status for r in run().values()}, {'pass', 'not_applicable'})
        self.assertEqual(run()['email.bimi_invalid'].status, 'not_applicable')

    def test_no_sts_record(self):
        r = run(sts=[], policy=None)
        self.assertEqual((r['email.mta_sts_missing'].status, r['email.mta_sts_testing'].status), ('fail', 'not_applicable'))
        self.assertEqual(run(sts=['v=STSv1'], policy=None)['email.mta_sts_missing'].status, 'fail')  # no id

    def test_mode_testing_and_none_fail(self):
        for mode in (b'testing', b'none'):
            r = run(policy={'status': 200, 'body': GOOD.replace(b'enforce', mode)})['email.mta_sts_testing']
            self.assertEqual((r.status, r.evidence['mode']), ('fail', mode.decode()))

    def test_policy_validation(self):
        def one(body):
            return run(policy={'status': 200, 'body': body})['email.mta_sts_testing']
        self.assertEqual(one(GOOD).status, 'pass')
        self.assertEqual(one(GOOD.replace(b'604800', b'60')).evidence['problems'], ['max_age_short'])
        self.assertEqual(one(GOOD.replace(b'604800', b'soon')).evidence['problems'], ['max_age_invalid'])
        self.assertEqual(one(GOOD.replace(b'STSv1', b'STSv2')).evidence['problems'], ['version'])
        self.assertEqual(one(b'version: STSv1\nmode: enforce\nmax_age: 604800\n').evidence['problems'], ['mx_missing'])
        self.assertEqual(one(GOOD.replace(b'mx1.x.com', b'other.example.net')).evidence['problems'], ['mx_not_covered'])
        self.assertEqual(one(GOOD.replace(b'mx1.x.com', b'mx1.*.com')).evidence['problems'], ['mx_pattern_invalid'])

    def test_wildcard_matches_exactly_one_label(self):
        self.assertTrue(pure.mx_covered('a.mail.x.com.', '*.mail.x.com'))
        self.assertFalse(pure.mx_covered('a.b.mail.x.com', '*.mail.x.com'))
        self.assertFalse(pure.mx_covered('mail.x.com', '*.mail.x.com'))

    def test_policy_fetch_outcomes(self):
        self.assertEqual(run(policy={'status': 404, 'body': None})['email.mta_sts_testing'].evidence['problems'], ['http_404'])
        self.assertEqual(run(policy={'status': 'error', 'body': None, 'reason': 'budget'})['email.mta_sts_testing'].status, 'error')
        self.assertEqual(run(policy=None)['email.mta_sts_testing'].status, 'error')
        self.assertEqual(run(sts='error')['email.mta_sts_missing'].status, 'error')

    def test_tls_rpt(self):
        self.assertEqual(run(tlsrpt=[])['email.tls_rpt_missing'].status, 'fail')
        self.assertEqual(run(tlsrpt=['v=TLSRPTv1'])['email.tls_rpt_missing'].evidence['actual'], 'record without rua')
        self.assertEqual(run(tlsrpt='error')['email.tls_rpt_missing'].status, 'error')

    def test_bimi_only_matters_when_published(self):
        bimi = ['v=BIMI1; l=https://x.com/logo.svg']
        self.assertEqual(run(bimi=bimi)['email.bimi_invalid'].status, 'pass')
        r = run(bimi=bimi, dmarc=['v=DMARC1; p=none'])['email.bimi_invalid']
        self.assertEqual((r.status, r.evidence['problems']), ('fail', ['dmarc_not_enforced']))
        self.assertEqual(run(bimi=bimi, dmarc=[])['email.bimi_invalid'].evidence['dmarc_policy'], 'absent')
        self.assertEqual(run(bimi=['v=BIMI1; l=http://x.com/l.svg'])['email.bimi_invalid'].evidence['problems'], ['logo_not_https'])
        self.assertEqual(run(bimi=bimi, dmarc='error')['email.bimi_invalid'].status, 'error')

    def test_evidence_never_carries_policy_text(self):
        body = GOOD.replace(b'enforce', b'testing') + b'mx: secret-host.internal.example\n'
        self.assertNotIn('secret-host', repr(run(policy={'status': 200, 'body': body})['email.mta_sts_testing'].evidence))
        bad_mode = run(policy={'status': 200, 'body': GOOD.replace(b'enforce', b'<script>')})['email.mta_sts_testing']
        self.assertEqual(bad_mode.evidence['mode'], 'invalid')

    def test_dangling_ns(self):
        ev = dns_checks.evaluate_ns
        self.assertEqual(ev({'ns': ['a.net'], 'gone': [], 'unknown': 0}).status, 'pass')
        r = ev({'ns': ['a.net', 'b.net'], 'gone': ['b.net'], 'unknown': 0})
        self.assertEqual((r.status, r.evidence['nameservers']), ('fail', ['b.net']))
        self.assertEqual(ev({'ns': ['a.net', 'b.net'], 'gone': [], 'unknown': 1}).status, 'error')  # unknown is never a pass
        self.assertEqual(ev({'ns': 'error', 'gone': [], 'unknown': 0}).status, 'error')
        self.assertEqual(ev({'ns': [], 'gone': [], 'unknown': 0}).status, 'not_applicable')


class StageTest(Base):
    def setUp(self):
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        patch = mock.patch.object(mailpolicy.ratelimit, 'reserve', return_value=0.0)
        patch.start()
        self.addCleanup(patch.stop)
        self.session = FakeSession(lambda url: Body(200, GOOD))

    def scan(self, answers=None):
        base = {('x.com', 'MX'): ['10 mx1.x.com.'], ('x.com', 'NS'): ['ns1.dns.net.'], ('ns1.dns.net', 'A'): [PUBLIC],
                ('_mta-sts.x.com', 'TXT'): STS, ('_smtp._tls.x.com', 'TXT'): RPT,
                ('mta-sts.x.com', 'A'): [PUBLIC]}
        self.resolve = stub({**base, **(answers or {})})
        return mailpolicy.discover(self.p, self.root, self.now, resolve=self.resolve, sleep=lambda s: None,
                                   session_factory=lambda: self.session, clock=lambda: 1000.0)

    def rows(self):
        return dict(RiskCheck.objects.filter(asset=self.root, check_id__in=IDS).values_list('check_id', 'status'))

    def test_healthy_domain_and_pinned_https_fetch(self):
        self.scan()
        self.assertEqual(self.rows(), {'email.mta_sts_missing': 'pass', 'email.mta_sts_testing': 'pass',
                                       'email.tls_rpt_missing': 'pass', 'email.bimi_invalid': 'not_applicable',
                                       'dns.dangling_ns': 'pass'})
        (url, kw), = self.session.requests
        self.assertEqual(url, f'https://{PUBLIC}/.well-known/mta-sts.txt')
        self.assertFalse(kw['allow_redirects'])

    def test_no_mx_means_not_applicable_and_no_fetch(self):
        self.scan({('x.com', 'MX'): dns.resolver.NoAnswer})
        r = self.rows()
        for i in IDS[:4]:
            self.assertEqual(r[i], 'not_applicable', i)
        self.assertEqual(self.session.requests, [])
        self.assertEqual(r['dns.dangling_ns'], 'pass')

    def test_missing_records_fail_without_a_fetch(self):
        self.scan({('_mta-sts.x.com', 'TXT'): dns.resolver.NXDOMAIN, ('_smtp._tls.x.com', 'TXT'): dns.resolver.NXDOMAIN})
        r = self.rows()
        self.assertEqual((r['email.mta_sts_missing'], r['email.mta_sts_testing'], r['email.tls_rpt_missing']),
                         ('fail', 'not_applicable', 'fail'))
        self.assertEqual(self.session.requests, [])

    def test_private_policy_host_is_not_contacted(self):
        self.scan({('mta-sts.x.com', 'A'): ['10.0.0.5']})
        self.assertEqual(self.session.requests, [])
        self.assertEqual(self.rows()['email.mta_sts_testing'], 'error')

    def test_unresolvable_policy_host_is_a_finding_but_a_failed_lookup_is_not(self):
        self.scan({('mta-sts.x.com', 'A'): dns.resolver.NXDOMAIN})
        self.assertEqual(self.rows()['email.mta_sts_testing'], 'fail')
        self.scan({('mta-sts.x.com', 'A'): dns.resolver.NoNameservers})
        self.assertEqual(self.rows()['email.mta_sts_testing'], 'error')
        self.assertEqual(self.session.requests, [])

    def test_budget_fails_closed(self):
        broken = mock.Mock()
        broken.add.side_effect = ConnectionError('down')
        real = ratelimit.take_daily
        with mock.patch.object(ratelimit, 'take_daily', lambda provider, limit, *a: real(provider, limit, cache=broken)):
            self.scan()
        self.assertEqual(self.session.requests, [])
        self.assertEqual(self.rows()['email.mta_sts_testing'], 'error')

    def test_dead_nameserver_is_flagged(self):
        self.scan({('x.com', 'NS'): ['ns1.dns.net.', 'ns2.gone.example.'], ('ns2.gone.example', 'A'): dns.resolver.NXDOMAIN})
        row = RiskCheck.objects.get(asset=self.root, check_id='dns.dangling_ns')
        self.assertEqual((row.status, row.evidence['nameservers']), ('fail', ['ns2.gone.example']))

    def test_failed_mx_lookup_is_error_not_pass(self):
        self.scan({('x.com', 'MX'): dns.resolver.NoNameservers})
        self.assertEqual(set(v for k, v in self.rows().items() if k.startswith('email.')), {'error'})

    def test_only_owned_roots(self):
        cand = self.asset('c.com', tier='candidate', kind='root_domain')
        self.assertEqual(mailpolicy.discover(self.p, cand, self.now), {'checked': 0})
