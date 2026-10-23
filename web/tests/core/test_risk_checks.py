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
    # provisional (cost no points)
    'rep.listed_drop': 3, 'rep.listed_asndrop': 3, 'rep.listed_c2': 4, 'rep.listed_attacker': 2, 'rep.dnsbl_listed': 2,
    'net.exposed_ollama': 3, 'net.exposed_openai_api': 3, 'net.exposed_triton': 2, 'net.exposed_gradio': 2,
    'net.exposed_jupyter': 4, 'net.exposed_ray': 4, 'leak.supabase_secret_key': 4, 'leak.hibp_breach': 2,
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

    def ev(self, https, http, host='h'):
        from limes.checks import web
        return _by_id(web.evaluate({'host': host, 'https': https, 'http': http}))

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

    def test_redirect_host_is_checked_when_https_is_unknown(self):
        for https in (None, 'error'):
            for loc, want in (('https://evil.example/', 'fail'), ('https://evil.example\\@h/', 'fail'),
                              ('https://h:8443/', 'fail'), ('https://H/login', 'pass')):
                res = self.ev(https, {'status': 301, 'location': loc})
                self.assertEqual(res['web.http_no_redirect'].status, want, (https, loc))
        self.assertEqual(self.ev(None, {'status': 301, 'location': 'https://h/'}, host=None)
                         ['web.http_no_redirect'].status, 'error')

    def test_collector_records_the_probed_host(self):
        from limes.checks import collect
        from limes.identity import ScanIdentity
        self.assertEqual(collect.observe_http('h', ScanIdentity(headers=[]), get=lambda url, **kw: _Resp(404))['host'], 'h')

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

    def test_good_verified_cert_passes(self):
        res = self.ev(self.cert(), {'TLSv1': False, 'TLSv1_1': False})
        for c in ('cert_hostname_mismatch', 'cert_untrusted', 'legacy_protocol', 'cert_expired', 'cert_expiring'):
            self.assertEqual(res['tls.' + c].status, 'pass', c)

    def test_unknown_after_failed_verification_is_error(self):
        unknown = {'unknown': 'certificate failed verification (code 18)'}
        res = self.ev(self.cert(not_after=None, expired=None, hostname_ok=None, trusted=False, verify_code=18))
        self.assertEqual(res['tls.cert_untrusted'].status, 'fail')
        for c in ('cert_expired', 'cert_expiring', 'cert_hostname_mismatch'):
            self.assertEqual((res['tls.' + c].status, res['tls.' + c].evidence), ('error', unknown), c)
        res = self.ev(self.cert(not_after=None, expired=None, hostname_ok=False, trusted=None, verify_code=62))
        self.assertEqual(res['tls.cert_hostname_mismatch'].status, 'fail')
        for c in ('cert_expired', 'cert_expiring', 'cert_untrusted'):
            self.assertEqual(res['tls.' + c].status, 'error', c)
        self.assertEqual(res['tls.cert_untrusted'].evidence, {'unknown': 'certificate failed verification (code 62)'})

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
        res = {r.check: r for r in network.evaluate({3389: ['naabu'], 443: ['internetdb 2026-10-10']}, True)}
        self.assertEqual(len(res), 14)
        self.assertEqual(res['net.exposed_rdp'].status, 'fail')
        self.assertEqual(res['net.exposed_rdp'].evidence, {'port': 3389, 'seen_by': ['naabu']})
        self.assertEqual({c for c, r in res.items() if r.status == 'pass'}, set(res) - {'net.exposed_rdp'})

    def test_partial_port_data_never_passes(self):
        from limes.checks import network
        res = {r.check: r.status for r in network.evaluate({6379: ['naabu']}, False)}
        self.assertEqual(res['net.exposed_redis'], 'fail')
        self.assertEqual(set(res.values()) - {'fail'}, {'error'})
        self.assertEqual(res['net.exposed_rdp'], 'error')

    def test_no_fresh_port_data_is_error(self):
        from limes.checks import network
        res = network.evaluate({}, False)
        self.assertEqual(len(res), 14)
        self.assertEqual({r.status for r in res}, {'error'})


class _Resp:
    def __init__(self, status=200, headers=None, cookies=None):
        self.status_code = status
        self.headers = headers or {}
        self.cookies_raw = cookies or []
        self.raw = type('Raw', (), {'headers': type('H', (), {'getlist': lambda s, k: cookies or []})()})()

    def close(self):
        pass


class CollectTest(SimpleTestCase):
    def ident(self, *headers):
        from limes.identity import ScanIdentity
        return ScanIdentity(headers=list(headers))

    def test_redirect_is_followed_within_host_only(self):
        from limes.checks import collect
        seen = []

        def get(url, **kw):
            seen.append(url)
            if url == 'https://h/':
                return _Resp(301, {'Location': 'https://h/a'})
            if url == 'https://h/a':
                return _Resp(200, {'Strict-Transport-Security': 'x'})
            return _Resp(404)
        obs = collect.observe_http('h', self.ident(), get=get)
        self.assertEqual(obs['https']['status'], 200)
        self.assertIn('strict-transport-security', obs['https']['headers'])

        def away(url, **kw):
            return _Resp(301, {'Location': 'https://evil.example/'}) if url.startswith('https') else _Resp(404)
        obs = collect.observe_http('h', self.ident(), get=away)
        self.assertEqual(obs['https']['status'], 301)

    def test_redirect_host_rule_is_strict(self):
        from limes.checks import collect
        for loc in ('https://evil.example\\@h/', 'https://evil.example@h/', 'https://h:8443/',
                    'https://other.example/', 'http://h/a', 'https://h\\x/'):
            seen = []

            def get(url, loc=loc, **kw):
                seen.append(url)
                return _Resp(302, {'Location': loc}) if url == 'https://h/' else _Resp(200)
            obs = collect.observe_http('h', self.ident(), get=get)
            self.assertEqual(obs['https']['status'], 302, loc)
            self.assertEqual([u for u in seen if u.startswith('https')], ['https://h/'], loc)
        seen = []

        def rel(url, **kw):
            seen.append(url)
            return _Resp(301, {'Location': '/login'}) if url == 'https://H/' else _Resp(200)
        obs = collect.observe_http('H', self.ident(), get=rel)
        self.assertEqual(obs['https']['status'], 200)
        self.assertEqual(seen[:2], ['https://H/', 'https://H/login'])
        seen = []
        obs = collect.observe_http('h', self.ident(), get=lambda url, **kw: (
            seen.append(url), _Resp(301, {'Location': 'https://H:443/x'}) if url == 'https://h/' else _Resp(200))[1])
        self.assertEqual(obs['https']['status'], 200)

    def test_plain_http_probe_sends_only_user_agent(self):
        from limes.checks import collect
        from limes.identity import Header
        sent = {}

        def get(url, headers=None, **kw):
            sent[url] = headers
            return _Resp(200)
        ident = self.ident(Header('X-Key', 's3cr3t', True), Header('X-Team', 'blue', False))
        collect.observe_http('h', ident, get=get)
        self.assertEqual(sent['http://h/'], {'User-Agent': ident.ua})
        self.assertEqual(sent['https://h/']['X-Key'], 's3cr3t')

    def test_tls_verify_codes_are_classified(self):
        import ssl
        from limes.checks import collect

        def raising(code):
            def connect(host, legacy=None):
                e = ssl.SSLCertVerificationError(code, 'x')
                e.verify_code = code
                raise e
            return connect
        c = collect.observe_tls('h', connect=raising(10))['cert']
        self.assertEqual((c['expired'], c['trusted'], c['hostname_ok'], c['not_after']), (True, True, True, None))
        for code in (18, 19, 20, 21):
            c = collect.observe_tls('h', connect=raising(code))['cert']
            self.assertEqual((c['expired'], c['trusted'], c['hostname_ok'], c['verify_code']), (None, False, None, code))
        c = collect.observe_tls('h', connect=raising(62))['cert']
        self.assertEqual((c['expired'], c['trusted'], c['hostname_ok'], c['verify_code']), (None, None, False, 62))

        def legacy_with(exc):
            def connect(host, legacy=None):
                if legacy is None:
                    return {'notAfter': 'Jun  1 12:00:00 2099 GMT'}
                raise exc
            return collect.observe_tls('h', connect=connect)['legacy']
        cert_err = ssl.SSLCertVerificationError(18, 'x')
        cert_err.verify_code = 18
        self.assertEqual(legacy_with(cert_err), {'TLSv1': True, 'TLSv1_1': True})
        self.assertEqual(legacy_with(ConnectionResetError()), {'TLSv1': False, 'TLSv1_1': False})
        self.assertEqual(legacy_with(ssl.SSLError('alert')), {'TLSv1': None, 'TLSv1_1': None})

        def ssl_err(reason):
            e = ssl.SSLError(1, f'[SSL: {reason}] x')
            e.reason = reason
            return e
        for reason in collect.SERVER_REFUSALS:
            self.assertEqual(legacy_with(ssl_err(reason)), {'TLSv1': False, 'TLSv1_1': False}, reason)
        for reason in ('UNSAFE_LEGACY_RENEGOTIATION_DISABLED', 'DH_KEY_TOO_SMALL', 'NO_PROTOCOLS_AVAILABLE'):
            self.assertEqual(legacy_with(ssl_err(reason)), {'TLSv1': None, 'TLSv1_1': None}, reason)
        self.assertEqual(legacy_with(ssl.SSLEOFError()), {'TLSv1': None, 'TLSv1_1': None})
        self.assertEqual(legacy_with(TimeoutError()), {'TLSv1': None, 'TLSv1_1': None})
        no_ciphers = ssl.SSLError(1, '[SSL: NO_CIPHERS_AVAILABLE] no ciphers available')
        no_ciphers.reason = 'NO_CIPHERS_AVAILABLE'
        self.assertEqual(legacy_with(no_ciphers), {'TLSv1': None, 'TLSv1_1': None})
        self.assertEqual(legacy_with(collect.ContextRefused()), {'TLSv1': None, 'TLSv1_1': None})

    def test_good_cert_parses_not_after_aware(self):
        from limes.checks import collect
        c = collect.observe_tls('h', connect=lambda host, legacy=None: {'notAfter': 'Jun  1 12:00:00 2099 GMT'})['cert']
        self.assertEqual(c['not_after'].year, 2099)
        self.assertIsNotNone(c['not_after'].tzinfo)
        self.assertTrue(c['trusted'] and c['hostname_ok'] and not c['expired'])

    def test_timeouts_become_error_not_pass(self):
        import requests
        from limes.checks import collect, web

        def slow(url, **kw):
            raise requests.exceptions.ReadTimeout()
        obs = collect.observe_http('h', self.ident(), get=slow)
        self.assertEqual(obs['https'], 'error')
        obs = collect.observe_http('h', self.ident(), get=lambda url, **kw: (_ for _ in ()).throw(requests.exceptions.SSLError()))
        self.assertEqual(obs['https'], 'error')
        res = {r.check: r.status for r in web.evaluate(obs)}
        self.assertNotIn('pass', [res[c] for c in res if c != 'web.http_no_redirect'])
        refused = collect.observe_http('h', self.ident(), get=lambda url, **kw: (_ for _ in ()).throw(requests.exceptions.ConnectionError()))
        self.assertEqual(refused, {'host': 'h', 'https': None, 'http': None})

    def test_evidence_never_contains_request_secrets(self):
        from limes.checks import collect
        from limes.identity import Header
        sent = []

        def get(url, headers=None, **kw):
            sent.append(headers)
            return _Resp(200, {'Server': 'nginx'})
        obs = collect.observe_http('h', self.ident(Header('X-Key', 's3cr3t', True)), get=get)
        self.assertEqual(sent[0]['X-Key'], 's3cr3t')
        self.assertNotIn('s3cr3t', repr(obs))

    def test_mail_dns_null_mx_and_errors(self):
        import dns.resolver
        from limes.checks import collect

        def resolve(name, rdtype):
            if rdtype == 'MX':
                return ['0 .']
            if rdtype == 'TXT' and name.startswith('_dmarc'):
                raise dns.resolver.NXDOMAIN()
            if rdtype == 'TXT':
                return ['v=spf1 -all']
            if rdtype == 'CAA':
                raise dns.resolver.NoAnswer()
            raise dns.resolver.NoNameservers()
        mail, d = collect.observe_mail_dns('x.com', resolve=resolve)
        self.assertEqual(mail, {'txt': ['v=spf1 -all'], 'dmarc': [], 'mx': []})
        self.assertEqual(d, {'ds': 'error', 'caa': False})


class PortsTest(TestCase):
    def test_ports_union_and_freshness(self):
        from datetime import timedelta
        from limes.checks import collect
        from startScan.models import IpAddress, Port
        project = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        now = timezone.now()
        a = Asset.objects.create(project=project, kind='ip', value='93.184.216.34', scope_tier='owned_host',
                                 enrichment={'internetdb': {'ports': [3389], 'fetched_at': (now - timedelta(days=5)).isoformat()}})
        ip = IpAddress.objects.create(address='93.184.216.34')
        ip.ports.add(Port.objects.create(number=6379))
        IpAddress.objects.create(address='93.184.216.34')  # a second scan's row, no ports
        got, complete = collect.ports_for_ip(a, now)
        self.assertTrue(complete)
        self.assertEqual(got[6379], ['naabu'])
        self.assertEqual(list(got), [3389, 6379])
        self.assertTrue(got[3389][0].startswith('internetdb '))
        b = Asset.objects.create(project=project, kind='ip', value='93.184.216.35', scope_tier='owned_host',
                                 enrichment={'internetdb': {'ports': [3389], 'fetched_at': (now - timedelta(days=40)).isoformat()}})
        self.assertEqual(collect.ports_for_ip(b, now), ({}, False))
        IpAddress.objects.create(address='93.184.216.35').ports.add(Port.objects.get(number=6379))
        self.assertEqual(collect.ports_for_ip(b, now), ({6379: ['naabu']}, False))  # naabu alone: never complete


class RunTest(TestCase):
    def setUp(self):
        from unittest import mock
        from startScan.models import IpAddress
        vetted = mock.patch('limes.checks.run.safe_fetch.resolve_vetted', return_value=('93.184.216.34', None))
        vetted.start()
        self.addCleanup(vetted.stop)
        self.project = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.root = Asset.objects.create(project=self.project, kind='root_domain', value='x.com', scope_tier='owned_root')
        self.host = Asset.objects.create(project=self.project, kind='hostname', value='a.x.com', scope_tier='owned_host')
        for i, a in enumerate((self.root, self.host)):
            ip = IpAddress.objects.create(address=f'93.184.216.{10 + i}')
            a.ip_addresses.add(ip)
        self.calls = []
        self.hsts = False

    def observers(self):
        def http(host, ident):
            self.calls.append(host)
            h = {'strict-transport-security': 'max-age=1'} if self.hsts else {}
            return {'https': {'status': 200, 'url': f'https://{host}/', 'headers': h, 'cookies': []},
                    'http': {'status': 301, 'location': f'https://{host}/'}}

        def tls(host):
            return {'cert': {'not_after': timezone.now() + timezone.timedelta(days=90), 'expired': False,
                             'hostname_ok': True, 'trusted': True},
                    'legacy': {'TLSv1': False, 'TLSv1_1': False}}
        return {'http': http, 'tls': tls,
                'mail_dns': lambda root: ({'txt': ['v=spf1 -all'], 'dmarc': ['v=DMARC1; p=reject'], 'mx': []},
                                          {'ds': False, 'caa': True}),
                'ports': lambda asset, now: ({}, False)}

    def test_writes_one_row_per_check_and_updates_in_place(self):
        from limes.checks import run
        out = run.run_checks(self.project, self.root, observers=self.observers())
        self.assertEqual(out['failed'], 0)
        ids = lambda a, p: set(a.risk_checks.filter(check_id__startswith=p).values_list('check_id', flat=True))
        for a in (self.root, self.host):
            self.assertEqual(len(ids(a, 'web.')), 8)
            self.assertEqual(len(ids(a, 'tls.')), 5)
        self.assertEqual(len(ids(self.root, 'email.')), 5)
        self.assertEqual(len(ids(self.root, 'dns.')), 2)
        self.assertEqual(ids(self.host, 'email.') | ids(self.host, 'dns.'), set())
        row = self.host.risk_checks.get(check_id='web.hsts_missing')
        self.assertEqual((row.status, row.severity), ('fail', 2))
        first, checked = row.first_seen, row.last_checked
        self.hsts = True
        run.run_checks(self.project, self.root, observers=self.observers())
        row2 = self.host.risk_checks.get(check_id='web.hsts_missing')
        self.assertEqual((row2.id, row2.status, row2.first_seen), (row.id, 'pass', first))
        self.assertGreater(row2.last_checked, checked)
        self.assertEqual(self.host.risk_checks.filter(check_id='web.hsts_missing').count(), 1)

    def test_refused_host_is_never_contacted(self):
        from unittest import mock
        from limes.checks import run
        real = scope_may_contact()

        def refuse(project, targets):
            allowed, refused = real(project, targets)
            return ([t for t in allowed if t != 'a.x.com'], refused + [('a.x.com', 'test')])
        with mock.patch('limes.scope.may_contact', refuse):
            run.run_checks(self.project, self.root, observers=self.observers())
        self.assertNotIn('a.x.com', self.calls)
        self.assertEqual(self.host.risk_checks.count(), 0)
        self.assertTrue(self.root.risk_checks.filter(check_id__startswith='web.').exists())

    def test_cap_checks_oldest_first(self):
        from unittest import mock
        from limes.checks import run
        from startScan.models import IpAddress
        self.root.ip_addresses.clear()  # root refused (unresolved): only the hosts compete
        self.host.delete()
        day = timezone.timedelta(days=1)
        for name, age in (('b.x.com', 1), ('c.x.com', 3), ('z.x.com', None)):
            a = Asset.objects.create(project=self.project, kind='hostname', value=name, scope_tier='owned_host')
            a.ip_addresses.add(IpAddress.objects.create(address='93.184.216.30'))
            if age:
                RiskCheck.objects.create(asset=a, check_id='web.hsts_missing', status='pass', severity=2,
                                         last_checked=timezone.now() - age * day)
        with mock.patch.object(run, 'MAX_HOSTS', 2):
            run.run_checks(self.project, self.root, observers=self.observers())
        self.assertEqual(self.calls, ['z.x.com', 'c.x.com'])

    def test_non_owned_root_gets_no_rows(self):
        from limes.checks import run
        self.root.scope_tier = 'candidate'
        self.root.save()
        self.assertEqual(run.run_checks(self.project, self.root, observers=self.observers()),
                         {'checked': 0, 'failed': 0})
        self.assertEqual(RiskCheck.objects.count(), 0)

    def test_budget_overrun_stops_after_current_host(self):
        import itertools
        from limes.checks import run
        ticks = itertools.chain([0, 100], itertools.repeat(3000))
        out = run.run_checks(self.project, self.root, observers=self.observers(), clock=lambda: next(ticks))
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(out['failed'], 0)

    def test_only_owned_assets_under_this_root(self):
        from limes.checks import run
        from startScan.models import IpAddress
        for kind_tier, v in (('candidate', 'c.x.com'), ('co_brand', 'd.x.com'), ('owned_host', 'e.y.com')):
            a = Asset.objects.create(project=self.project, kind='hostname', value=v, scope_tier=kind_tier)
            a.ip_addresses.add(IpAddress.objects.create(address='93.184.216.99'))
        run.run_checks(self.project, self.root, observers=self.observers())
        self.assertEqual(sorted(self.calls), ['a.x.com', 'x.com'])
        self.assertEqual(RiskCheck.objects.filter(asset__value__in=['c.x.com', 'd.x.com', 'e.y.com']).count(), 0)

    def test_owned_ips_checked_once_for_first_root_only(self):
        from limes.checks import run
        ip = Asset.objects.create(project=self.project, kind='ip', value='93.184.216.50', scope_tier='owned_host')
        second = Asset.objects.create(project=self.project, kind='root_domain', value='y.com', scope_tier='owned_root')
        run.run_checks(self.project, second, observers=self.observers())
        self.assertEqual(ip.risk_checks.count(), 0)
        run.run_checks(self.project, self.root, observers=self.observers())
        self.assertEqual(ip.risk_checks.count(), 14)
        self.assertEqual({r.status for r in ip.risk_checks.all()}, {'error'})


def scope_may_contact():
    from limes import scope
    return scope.may_contact


class StageTest(TestCase):
    def setUp(self):
        from unittest import mock
        from limes.celery_custom_task import LimesTask
        p = mock.patch.object(LimesTask, 'notify')
        p.start()
        self.addCleanup(p.stop)
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())

    def _ctx(self, tier):
        import tempfile
        from scanEngine.models import EngineType
        from startScan.models import ScanHistory
        from targetApp.models import Domain
        domain = Domain.objects.create(name='x.com', project=self.p, insert_date=timezone.now())
        Asset.objects.create(project=self.p, kind='root_domain', value='x.com', scope_tier=tier)
        eng = EngineType.objects.create(engine_name='e', yaml_configuration='{}')
        scan = ScanHistory.objects.create(scan_type=eng, domain=domain, start_scan_date=timezone.now(),
                                          results_dir=tempfile.mkdtemp())
        return {'scan_history_id': scan.id, 'results_dir': scan.results_dir, 'track': False}

    def test_workflow_places_risk_checks(self):
        from limes.tasks import control

        def names(sig):
            tasks = getattr(sig, 'tasks', None)
            return [sig.task.rsplit('.', 1)[-1]] if tasks is None else [n for t in tasks for n in names(t)]
        self.assertEqual(names(control.build_workflow({}, 'asm')),
                         ['subdomain_discovery', 'passive_intel', 'risk_checks', 'screenshot'])
        full = names(control.build_workflow({}, 'full'))
        self.assertEqual(full[full.index('port_scan') + 1], 'risk_checks')

    def test_runs_for_owned_root(self):
        from unittest import mock
        from limes.tasks import stages
        with mock.patch('limes.checks.run.run_checks', return_value={'checked': 2, 'failed': 1}) as m:
            out = stages.risk_checks(ctx=self._ctx('owned_root'))
        self.assertEqual(out, {'checked': 2, 'failed': 1})
        self.assertEqual(m.call_args[0][1].value, 'x.com')

    def _engine_ctx(self):
        # a real engine whose YAML lists neither stage, tracked as in a real scan
        from scanEngine.models import EngineType
        from startScan.asset_models import ScanRun
        ctx = self._ctx('owned_root')
        del ctx['track']
        eng = EngineType.objects.create(engine_name='real', yaml_configuration='port_scan: {}\n')
        root = Asset.objects.get(project=self.p, value='x.com')
        run = ScanRun.objects.create(project=self.p, root_asset=root, start_scan_date=timezone.now())
        ctx.update(engine_id=eng.id, scan_run_id=run.id)
        return ctx, run

    def test_risk_checks_runs_when_engine_does_not_list_it(self):
        from unittest import mock
        from limes.tasks import stages
        ctx, run = self._engine_ctx()
        with mock.patch('limes.checks.run.run_checks', return_value={'checked': 1, 'failed': 0}) as m:
            out = stages.risk_checks(ctx=ctx)
        m.assert_called_once()
        self.assertEqual(out, {'checked': 1, 'failed': 0})
        self.assertEqual(list(run.jobs.values_list('stage', flat=True)), ['probe'])

    def test_passive_intel_runs_when_engine_does_not_list_it(self):
        from unittest import mock
        from limes.tasks import stages
        ctx, _run = self._engine_ctx()
        names = ['limes.tasks.intel.run_crtsh', 'limes.tasks.intel.run_internetdb', 'limes.tasks.intel.run_ripestat',
                 'limes.tasks.attribution.collect_dns', 'limes.tasks.attribution.score_project',
                 'limes.tasks.attribution.verify_delegations', 'limes.tasks.attribution.apply_decisions']
        with mock.patch('limes.tasks.resolution.resolve_root', return_value=0):
            patches = [mock.patch(n, return_value={}) for n in names]
            mocks = [p.start() for p in patches]
            try:
                stages.passive_intel(ctx=ctx)
            finally:
                for p in patches:
                    p.stop()
        mocks[0].assert_called_once()

    def test_other_stages_stay_gated_by_engine(self):
        from unittest import mock
        from limes.tasks import stages
        ctx, _run = self._engine_ctx()
        with mock.patch.object(stages.screenshot, 'run') as m:
            self.assertIsNone(stages.screenshot(ctx=ctx))
        m.assert_not_called()

    def test_crash_is_not_reported_as_success(self):
        from unittest import mock
        from limes.tasks import stages
        from limes.definitions import FAILED_TASK
        with mock.patch('limes.checks.run.run_checks', side_effect=RuntimeError('boom')):
            stages.risk_checks(ctx=self._ctx('owned_root'))
        self.assertEqual(stages.risk_checks.status, FAILED_TASK)
        self.assertIn('boom', stages.risk_checks.error)

    def test_skipped_unless_owned_root(self):
        from unittest import mock
        from limes.tasks import stages
        with mock.patch('limes.checks.run.run_checks') as m:
            out = stages.risk_checks(ctx=self._ctx('discovered'))
        self.assertEqual(out, {})
        m.assert_not_called()


class ScoreV2Test(TestCase):
    def setUp(self):
        from datetime import timedelta
        from limes.definitions import SUCCESS_TASK
        from scanEngine.models import EngineType
        from startScan.models import ScanActivity, ScanHistory
        from targetApp.models import Domain
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.now = timezone.now()
        self.root = self.asset('root_domain', 'x.com', 'owned_root')
        self.host = self.asset('hostname', 'a.x.com')
        self.timedelta = timedelta
        domain = Domain.objects.create(project=self.p, name='x.com', insert_date=self.now)
        eng = EngineType.objects.create(engine_name='e', yaml_configuration='{}')
        self.scan = ScanHistory.objects.create(domain=domain, scan_type=eng, start_scan_date=self.now)
        ScanActivity.objects.create(scan_of=self.scan, name='vulnerability_scan', title='v', time=self.now,
                                    status=SUCCESS_TASK)

    def asset(self, kind, value, tier='owned_host'):
        return Asset.objects.create(project=self.p, kind=kind, value=value, scope_tier=tier)

    def check(self, asset, check_id, status='fail', sev=2, ago=None):
        RiskCheck.objects.create(asset=asset, check_id=check_id, status=status, severity=sev,
                                 last_checked=self.now - (ago or self.timedelta()))

    def breakdown(self, asset):
        from limes import scoring
        return scoring.asset_breakdown(asset)

    def test_failed_check_costs_points(self):
        from startScan.models import ScanHistory
        ScanHistory.objects.all().delete()  # no vulnerability baseline
        self.check(self.host, 'web.hsts_missing')
        b = self.breakdown(self.host)
        self.assertEqual((b['score'], b['assessed']), (925, True))

    def test_ceiling_applies_to_checks(self):
        self.check(self.host, 'tls.cert_expired', sev=3)
        self.assertEqual(self.breakdown(self.host)['score'], 799)

    def test_root_and_ip_results_are_not_inherited(self):
        ip = self.asset('ip', '203.0.113.9')
        self.check(self.root, 'email.dmarc_missing')
        self.check(ip, 'net.exposed_redis', sev=3)
        self.assertEqual(self.breakdown(self.root)['score'], 925)
        self.assertEqual(self.breakdown(self.host)['score'], 950)
        self.assertEqual(self.breakdown(ip)['score'], 799)

    def test_stale_error_and_na_never_score(self):
        from startScan.models import ScanHistory
        ScanHistory.objects.all().delete()
        other = self.asset('hostname', 'b.x.com')
        self.check(self.host, 'web.hsts_missing', ago=self.timedelta(days=31))
        self.check(self.root, 'web.csp_missing', status='error', sev=1)
        self.check(other, 'web.csp_missing', status='not_applicable', sev=1)
        from limes import scoring
        self.assertEqual(self.breakdown(self.host)['assessed'], False)
        self.assertEqual(self.breakdown(self.root)['assessed'], False)
        self.assertEqual(scoring.project_score(self.p)['score'], None)
        self.check(self.host, 'web.csp_missing', status='pass', sev=1)
        b = self.breakdown(self.host)
        self.assertEqual((b['score'], b['assessed']), (950, True))

    def test_checks_and_findings_add_up(self):
        from startScan.models import Vulnerability
        Vulnerability.objects.create(scan_history=self.scan, asset=self.host, name='n', template_id='t1',
                                     severity=3, http_url='https://h/', open_status=True)
        self.check(self.host, 'web.csp_missing', sev=1)
        b = self.breakdown(self.host)
        self.assertEqual(b['score'], min(950 - 80 - 5, 799))
        self.assertEqual(sorted(r['kind'] for r in b['penalties']), ['check', 'finding'])

    def test_check_coverage(self):
        from limes import scoring
        self.check(self.host, 'web.csp_missing', status='pass', sev=1)
        self.check(self.root, 'web.csp_missing', status='error', sev=1)
        self.assertEqual(scoring.project_score(self.p)['check_coverage'], 0.5)
        self.assertEqual(scoring.VERSION, 'limes-score-v3')
