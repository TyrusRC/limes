from django.db import IntegrityError, transaction
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.checks.catalogue import CHECKS, RISKY_PORTS
from startScan.asset_models import Asset, RiskCheck

SPEC = {
    'web.https_missing': 3, 'web.http_no_redirect': 2, 'web.hsts_missing': 2, 'web.csp_missing': 1,
    'web.frame_options_missing': 1, 'web.content_type_options_missing': 1,
    'web.cookie_flags_missing': 1, 'web.version_disclosure': 1,
    'tls.cert_expired': 3, 'tls.cert_expiring': 2, 'tls.cert_hostname_mismatch': 3,
    'tls.cert_untrusted': 3, 'tls.legacy_protocol': 2,
    'email.spf_missing': 2, 'email.spf_permissive': 2, 'email.dmarc_missing': 2,
    'email.dmarc_none': 1, 'email.mx_unprotected': 1,
    'dns.dnssec_missing': 1, 'dns.caa_missing': 1,
}
PORTS = {'ftp': 21, 'telnet': 23, 'smb': 445, 'rdp': 3389, 'mssql': 1433, 'oracle': 1521,
         'mysql': 3306, 'postgres': 5432, 'redis': 6379, 'elasticsearch': 9200,
         'memcached': 11211, 'mongodb': 27017, 'docker': 2375, 'vnc': 5900}


class CatalogueTest(SimpleTestCase):
    def test_ids_and_severities_match_the_spec(self):
        want = dict(SPEC)
        want.update({f'net.exposed_{s}': 2 if s == 'ftp' else 3 for s in PORTS})
        self.assertEqual({k: c.severity for k, c in CHECKS.items()}, want)
        self.assertEqual(CHECKS['net.exposed_ftp'].severity, 2)
        self.assertEqual({p: v[0] for p, v in RISKY_PORTS.items()}, {p: s for s, p in PORTS.items()})
        for port, (svc, sev) in RISKY_PORTS.items():
            self.assertEqual(sev, CHECKS[f'net.exposed_{svc}'].severity)
        for k, c in CHECKS.items():
            self.assertEqual(c.id, k)

    def test_every_check_has_title_and_fix(self):
        for c in CHECKS.values():
            for text in (c.title, c.fix):
                self.assertTrue(text.strip(), c.id)
                self.assertNotIn('\n', text, c.id)


class RiskCheckModelTest(TestCase):
    def test_one_row_per_asset_and_check(self):
        project = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        asset = Asset.objects.create(project=project, kind='hostname', value='a.example.com')
        RiskCheck.objects.create(asset=asset, check_id='web.hsts_missing', status='fail', severity=2)
        with self.assertRaises(IntegrityError), transaction.atomic():
            RiskCheck.objects.create(asset=asset, check_id='web.hsts_missing', status='pass', severity=2)


def _by_id(results):
    return {r.check: r for r in results}


class WebEvalTest(SimpleTestCase):
    GOOD = {
        'status': 200, 'url': 'https://h/',
        'headers': {'strict-transport-security': 'max-age=1', 'content-security-policy': "frame-ancestors 'self'",
                    'x-content-type-options': 'nosniff'},
        'cookies': ['a=1; Secure; HttpOnly; SameSite=Lax'],
    }

    def ev(self, https, http):
        from limes.checks import web
        return _by_id(web.evaluate({'https': https, 'http': http}))

    def test_good_https_site_passes(self):
        res = self.ev(self.GOOD, {'status': 301, 'location': 'https://h/'})
        self.assertEqual(len(res), 8)
        self.assertEqual({r.status for r in res.values()}, {'pass'})

    def test_no_web_server_is_not_applicable(self):
        res = self.ev(None, None)
        self.assertEqual(len(res), 8)
        self.assertEqual({r.status for r in res.values()}, {'not_applicable'})

    def test_http_only_host(self):
        res = self.ev(None, {'status': 200, 'location': None})
        self.assertEqual(res['web.https_missing'].status, 'fail')
        self.assertEqual(res['web.http_no_redirect'].status, 'fail')
        for c in ('hsts_missing', 'csp_missing', 'frame_options_missing', 'content_type_options_missing',
                  'cookie_flags_missing', 'version_disclosure'):
            self.assertEqual(res['web.' + c].status, 'not_applicable', c)

    def test_header_failures_carry_evidence(self):
        https = {'status': 200, 'url': 'https://h/', 'headers': {'server': 'nginx/1.18.0'}, 'cookies': ['sid=x']}
        res = self.ev(https, None)
        self.assertEqual(res['web.version_disclosure'].status, 'fail')
        self.assertEqual(res['web.version_disclosure'].evidence, {'server': 'nginx/1.18.0'})
        self.assertEqual(res['web.cookie_flags_missing'].status, 'fail')
        self.assertEqual(res['web.cookie_flags_missing'].evidence['cookies'], ['sid'])
        for c in ('hsts_missing', 'csp_missing', 'frame_options_missing', 'content_type_options_missing'):
            self.assertEqual(res['web.' + c].status, 'fail', c)

    def test_redirect_to_other_host_fails(self):
        res = self.ev(self.GOOD, {'status': 302, 'location': 'https://evil.example/'})
        self.assertEqual(res['web.http_no_redirect'].status, 'fail')

    def test_https_error_is_error(self):
        res = self.ev('error', None)
        for c in ('hsts_missing', 'csp_missing', 'frame_options_missing', 'content_type_options_missing',
                  'cookie_flags_missing', 'version_disclosure', 'https_missing'):
            self.assertEqual(res['web.' + c].status, 'error', c)


class TlsEvalTest(SimpleTestCase):
    NOW = timezone.now()

    def ev(self, cert, legacy=None):
        from limes.checks import tls
        legacy = legacy or {'TLSv1': False, 'TLSv1_1': False}
        return _by_id(tls.evaluate({'cert': cert, 'legacy': legacy}, self.NOW))

    def cert(self, **kw):
        base = {'not_after': self.NOW + timezone.timedelta(days=90), 'expired': False,
                'hostname_ok': True, 'trusted': True}
        base.update(kw)
        return base

    def test_expiry_windows(self):
        d = timezone.timedelta
        res = self.ev(self.cert(not_after=self.NOW + d(days=10)))
        self.assertEqual((res['tls.cert_expiring'].status, res['tls.cert_expired'].status), ('fail', 'pass'))
        res = self.ev(self.cert(not_after=self.NOW + d(days=30)))
        self.assertEqual((res['tls.cert_expiring'].status, res['tls.cert_expired'].status), ('pass', 'pass'))
        res = self.ev(self.cert(not_after=None, expired=True))
        self.assertEqual(res['tls.cert_expired'].status, 'fail')
        self.assertEqual(res['tls.cert_expiring'].status, 'not_applicable')

    def test_mismatch_untrusted_legacy(self):
        res = self.ev(self.cert(hostname_ok=False, trusted=False), {'TLSv1': True, 'TLSv1_1': False})
        self.assertEqual(res['tls.cert_hostname_mismatch'].status, 'fail')
        self.assertEqual(res['tls.cert_untrusted'].status, 'fail')
        self.assertEqual(res['tls.legacy_protocol'].status, 'fail')
        self.assertEqual(res['tls.legacy_protocol'].evidence, {'accepted': ['TLSv1']})

    def test_legacy_context_refused_is_error(self):
        res = self.ev(self.cert(), {'TLSv1': None, 'TLSv1_1': False})
        self.assertEqual(res['tls.legacy_protocol'].status, 'error')

    def test_no_tls_is_not_applicable(self):
        res = self.ev(None)
        self.assertEqual(len(res), 5)
        self.assertEqual({r.status for r in res.values()}, {'not_applicable'})

    def test_cert_error_is_error(self):
        self.assertEqual({r.status for r in self.ev('error').values()}, {'error'})


class MailDnsEvalTest(SimpleTestCase):
    def mail(self, txt, dmarc, mx):
        from limes.checks import email as mail_checks
        res = mail_checks.evaluate({'txt': txt, 'dmarc': dmarc, 'mx': mx})
        self.assertEqual([r.check for r in res], [i for i in CHECKS if i.startswith('email.')])
        return {r.check: r for r in res}

    def test_spf_and_dmarc_good(self):
        r = self.mail(['v=spf1 include:_spf.x -all'], ['v=DMARC1; p=reject'], ['mx.x'])
        self.assertEqual({x.status for x in r.values()}, {'pass'})

    def test_spf_permissive_and_dmarc_none(self):
        ok = self.mail(['v=spf1 ~all'], ['v=DMARC1; p=reject'], ['mx.x'])
        self.assertEqual(ok['email.spf_permissive'].status, 'pass')
        for rec in ('v=spf1 +all', 'v=spf1 ?all', 'v=spf1 all'):
            r = self.mail([rec], ['v=DMARC1; p=reject'], ['mx.x'])
            self.assertEqual(r['email.spf_permissive'].status, 'fail', rec)
            self.assertEqual(r['email.spf_permissive'].evidence, {'spf': rec})
        r = self.mail(['v=spf1 -all'], ['v=DMARC1; P=None'], ['mx.x'])
        self.assertEqual(r['email.dmarc_none'].status, 'fail')

    def test_missing_records(self):
        r = self.mail([], [], ['mx.x'])
        for i in ('spf_missing', 'dmarc_missing', 'mx_unprotected'):
            self.assertEqual(r['email.' + i].status, 'fail', i)
        self.assertEqual(r['email.spf_permissive'].status, 'not_applicable')
        self.assertEqual(r['email.dmarc_none'].status, 'not_applicable')
        self.assertEqual(self.mail([], [], [])['email.mx_unprotected'].status, 'pass')

    def test_lookup_error_is_error(self):
        r = self.mail('error', ['v=DMARC1; p=reject'], ['mx.x'])
        self.assertEqual(r['email.spf_missing'].status, 'error')
        self.assertEqual(r['email.spf_permissive'].status, 'error')
        self.assertEqual(r['email.mx_unprotected'].status, 'error')
        r = self.mail(['v=spf1 -all'], ['v=DMARC1; p=reject'], 'error')
        self.assertEqual(r['email.mx_unprotected'].status, 'error')

    def test_dnssec_and_caa(self):
        from limes.checks import dns as dns_checks
        r = {x.check: x.status for x in dns_checks.evaluate({'ds': False, 'caa': True})}
        self.assertEqual(r, {'dns.dnssec_missing': 'fail', 'dns.caa_missing': 'pass'})
        r = {x.check: x.status for x in dns_checks.evaluate({'ds': 'error', 'caa': 'error'})}
        self.assertEqual(set(r.values()), {'error'})


class NetworkEvalTest(SimpleTestCase):
    def test_risky_ports(self):
        from limes.checks import network
        res = {r.check: r for r in network.evaluate({3389: ['naabu'], 443: ['internetdb 2026-10-10']})}
        self.assertEqual(len(res), 14)
        self.assertEqual(res['net.exposed_rdp'].status, 'fail')
        self.assertEqual(res['net.exposed_rdp'].evidence, {'port': 3389, 'seen_by': ['naabu']})
        self.assertEqual({c for c, r in res.items() if r.status == 'pass'}, set(res) - {'net.exposed_rdp'})

    def test_no_fresh_port_data_is_error(self):
        from limes.checks import network
        res = network.evaluate(None)
        self.assertEqual(len(res), 14)
        self.assertEqual({r.status for r in res}, {'error'})
