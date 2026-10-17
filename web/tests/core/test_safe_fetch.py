import datetime
import functools
import os
import socket
import ssl
import tempfile
import threading
from unittest import mock

import dns.resolver
import requests
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from dashboard.models import Project
from startScan.models import Asset, RiskCheck

PUBLIC = '93.184.216.34'


def stub(answers):
    """Resolver keyed by (name, rdtype): a list, a callable (call number -> list) or an exception class.
    Anything not listed is NXDOMAIN. Records every query."""
    calls = []

    def resolve(name, rdtype):
        calls.append((name, rdtype))
        found = answers.get((name, rdtype), dns.resolver.NXDOMAIN)
        if callable(found) and not isinstance(found, type):
            return found(sum(1 for c in calls if c == (name, rdtype)))
        if isinstance(found, type):
            raise found()
        return list(found)
    resolve.calls = calls
    return resolve


class _Resp:
    def __init__(self, status=200, headers=None):
        self.status_code, self.headers = status, headers or {}
        self.raw = type('Raw', (), {'headers': type('H', (), {'getlist': lambda s, k: []})()})()

    def close(self):
        pass


class FakeSession:
    """requests.Session stand-in: records mounts and every request; answers from `route(url)`."""
    made = []

    def __init__(self, route=None):
        self.route = route or (lambda url: _Resp(200))
        self.mounts, self.requests, self.trust_env = {}, [], True
        FakeSession.made.append(self)

    def mount(self, prefix, adapter):
        self.mounts[prefix] = adapter

    def get(self, url, **kw):
        self.requests.append((url, kw))
        return self.route(url)


class FakeTls:
    """create_connection + context_factory stand-ins: record the dialled address and the SNI."""
    def __init__(self):
        self.dialled, self.sni = [], []

    def create_connection(self, addr, timeout=None):
        self.dialled.append(addr)
        return _Ctx(None)

    def context(self, legacy=None):
        fake = self

        class Context:
            verify_mode, check_hostname = ssl.CERT_REQUIRED, True

            def wrap_socket(self, sock, server_hostname=None):
                fake.sni.append(server_hostname)
                return _Ctx({'notAfter': 'Jun  1 12:00:00 2099 GMT'})
        return Context()


class _Ctx:
    def __init__(self, cert):
        self.cert = cert

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def getpeercert(self):
        return self.cert

    def settimeout(self, t):
        pass


class ResolveVettedTest(SimpleTestCase):
    def vet(self, host, answers):
        from limes import safe_fetch
        return safe_fetch.resolve_vetted(host, resolve=stub(answers))

    def test_any_private_answer_refused(self):
        h = 'a.example.com'
        ip, reason = self.vet(h, {(h, 'A'): ['10.0.0.1'], (h, 'AAAA'): []})
        self.assertIsNone(ip)
        self.assertIn('private address', reason)
        self.assertNotIn('10.0.0.1', reason)  # the class is named, the internal address is not repeated
        ip, reason = self.vet(h, {(h, 'A'): [PUBLIC, '10.0.0.1'], (h, 'AAAA'): []})
        self.assertEqual((ip, 'private address' in reason, '10.0.0.1' in reason), (None, True, False))
        self.assertIn('loopback', self.vet(h, {(h, 'A'): ['127.0.0.1'], (h, 'AAAA'): []})[1])
        self.assertIn('link-local', self.vet(h, {(h, 'A'): ['169.254.169.254'], (h, 'AAAA'): []})[1])
        self.assertIn('multicast', self.vet(h, {(h, 'A'): ['224.0.0.1'], (h, 'AAAA'): []})[1])
        ip, reason = self.vet(h, {(h, 'A'): [PUBLIC], (h, 'AAAA'): ['fd00::1']})
        self.assertEqual((ip, 'private address' in reason, 'fd00::1' in reason), (None, True, False))
        self.assertIsNone(self.vet(h, {(h, 'A'): [PUBLIC], (h, 'AAAA'): ['fec0::1']})[0])  # site-local
        self.assertIsNone(self.vet(h, {(h, 'A'): [], (h, 'AAAA'): ['::1.2.3.4']})[0])  # IPv4-compatible
        # dual stack: the IPv4 answer is pinned whatever order the answers come in (IPv6 often has no route)
        self.assertEqual(self.vet(h, {(h, 'A'): [PUBLIC], (h, 'AAAA'): ['2606:2800:220:1::1']}), (PUBLIC, None))
        self.assertEqual(self.vet(h, {(h, 'A'): [PUBLIC], (h, 'AAAA'): []}), (PUBLIC, None))
        self.assertEqual(self.vet(h, {(h, 'A'): [], (h, 'AAAA'): ['2606:2800:220:1::1']}),
                         ('2606:2800:220:1::1', None))
        for answers in ({}, {(h, 'A'): [], (h, 'AAAA'): []}, {(h, 'A'): [PUBLIC], (h, 'AAAA'): dns.resolver.NoNameservers},
                        {(h, 'A'): dns.resolver.LifetimeTimeout}, {(h, 'A'): ['not-an-ip'], (h, 'AAAA'): []}):
            ip, reason = self.vet(h, answers)
            self.assertIsNone(ip, answers)
            self.assertTrue(reason, answers)
        for name in ('localhost', 'printer.local', 'db.internal', 'nas.home.arpa', 'intranet', 'x.localhost.'):
            from limes import safe_fetch
            r = stub({(name, 'A'): [PUBLIC]})
            ip, reason = safe_fetch.resolve_vetted(name, resolve=r)
            self.assertEqual((ip, r.calls), (None, []), name)
            self.assertTrue(reason)
        r = stub({})
        from limes import safe_fetch
        self.assertEqual(safe_fetch.resolve_vetted(PUBLIC, resolve=r), (PUBLIC, None))
        self.assertIsNone(safe_fetch.resolve_vetted('10.0.0.1', resolve=r)[0])
        self.assertIsNone(safe_fetch.resolve_vetted('::ffff:127.0.0.1', resolve=r)[0])
        self.assertEqual(r.calls, [])


class PinnedGetTest(SimpleTestCase):
    def setUp(self):
        FakeSession.made = []

    def ident(self):
        from limes.identity import ScanIdentity
        return ScanIdentity(headers=[])

    def test_pinned_get_refuses_other_hosts_and_caps_redirects(self):
        from limes import safe_fetch
        from limes.checks import collect
        get = safe_fetch.pinned_get('h.example.com', PUBLIC, session_factory=FakeSession)
        for url in ('https://evil.example/', 'https://u@h.example.com/', 'https://h.example.com\\@evil.example/',
                    'ftp://h.example.com/', 'https://h.example.com.evil.example/'):
            with self.assertRaises(requests.exceptions.InvalidURL, msg=url):
                get(url)
        for off in (False, 0, '', None):
            with self.assertRaises(ValueError, msg=repr(off)):
                get('https://h.example.com/', verify=off)
        self.assertEqual(FakeSession.made[0].requests, [])

        def away(url):
            return _Resp(302, {'Location': 'https://evil.example/'}) if url.startswith('https') else _Resp(200)
        obs = collect.observe_http('h.example.com', self.ident(),
                                   get=safe_fetch.pinned_get('h.example.com', PUBLIC, session_factory=lambda: FakeSession(away)))
        self.assertEqual(obs['https']['status'], 302)
        sent = FakeSession.made[-1].requests
        self.assertEqual([u for u, _ in sent], [f'https://{PUBLIC}/', f'http://{PUBLIC}/'])

        def loop(url):
            n = int(url.rsplit('/', 1)[-1] or 0)
            return _Resp(301, {'Location': f'/{n + 1}'})
        obs = collect.observe_http('h.example.com', self.ident(),
                                   get=safe_fetch.pinned_get('h.example.com', PUBLIC, session_factory=lambda: FakeSession(loop)))
        session = FakeSession.made[-1]
        https = [(u, kw) for u, kw in session.requests if u.startswith('https')]
        self.assertEqual([u for u, _ in https], [f'https://{PUBLIC}/', f'https://{PUBLIC}/1', f'https://{PUBLIC}/2',
                                                 f'https://{PUBLIC}/3'])  # 1 + MAX_REDIRECTS, then stop
        self.assertEqual(obs['https']['url'], 'https://h.example.com/3')
        for _, kw in session.requests:
            self.assertEqual(kw['headers']['Host'], 'h.example.com')
            self.assertIs(kw['allow_redirects'], False)
        self.assertFalse(session.trust_env)  # no env proxies or .netrc credentials
        pool = session.mounts['https://'].poolmanager.connection_pool_kw
        self.assertEqual((pool['server_hostname'], pool['assert_hostname']), ('h.example.com', 'h.example.com'))
        safe_fetch.pinned_get('h.example.com', PUBLIC, session_factory=FakeSession)('https://h.example.com/', allow_redirects=True)
        self.assertIs(FakeSession.made[-1].requests[0][1]['allow_redirects'], False)

    def test_ipv6_is_bracketed(self):
        from limes import safe_fetch
        safe_fetch.pinned_get('h.example.com', '2606:2800:220:1::1', session_factory=FakeSession)('https://h.example.com/a?b=1')
        self.assertEqual(FakeSession.made[-1].requests[0][0], 'https://[2606:2800:220:1::1]/a?b=1')


class RebindingTest(TestCase):
    """The resolver answers public first, then private (DNS rebinding): only the vetted public IP is ever dialled."""
    def setUp(self):
        cache.clear()
        FakeSession.made = []
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.host = Asset.objects.create(project=self.p, kind='hostname', value='a.example.com', scope_tier='owned_host')
        self.tls = FakeTls()
        from limes import safe_fetch
        real_get, real_tls = safe_fetch.pinned_get, safe_fetch.pinned_tls_connect
        for name, fn in (('pinned_get', functools.partial(real_get, session_factory=FakeSession)),
                         ('pinned_tls_connect', functools.partial(real_tls, create_connection=self.tls.create_connection,
                                                                  context_factory=self.tls.context))):
            p = mock.patch.object(safe_fetch, name, fn)
            p.start()
            self.addCleanup(p.stop)
        h = 'a.example.com'
        self.resolve = stub({(h, 'A'): lambda n: [PUBLIC] if n == 1 else ['10.0.0.1'], (h, 'AAAA'): [],
                             (h, 'CNAME'): dns.resolver.NoAnswer})

    def assert_only_public(self):
        a_queries = [c for c in self.resolve.calls if c[1] == 'A']
        self.assertEqual(len(a_queries), 1, self.resolve.calls)
        urls = [u for s in FakeSession.made for u, _ in s.requests]
        self.assertTrue(urls)
        self.assertTrue(all(u.split('/')[2] == PUBLIC for u in urls), urls)
        self.assertTrue(all(kw['headers']['Host'] == 'a.example.com' for s in FakeSession.made for _, kw in s.requests))
        self.assertTrue(self.tls.dialled)
        self.assertEqual(set(self.tls.dialled), {(PUBLIC, 443)})
        self.assertEqual(set(self.tls.sni), {'a.example.com'})

    def test_rebinding_uses_vetted_ip(self):
        from limes import monitor
        out = monitor.check_asset(self.host, resolve=self.resolve, get=lambda url, provider: (404, None))
        self.assert_only_public()
        self.assertEqual(out['status'], 'ok')
        self.assertTrue(RiskCheck.objects.filter(asset=self.host, check_id__startswith='tls.').exists())
        self.assertEqual(list(self.host.ip_addresses.values_list('address', flat=True)), [PUBLIC])  # recorded = vetted

    def test_dual_stack_host_is_observed_on_ipv4(self):
        from limes import monitor
        h = 'a.example.com'
        resolve = stub({(h, 'AAAA'): ['2606:2800:220:1::1'], (h, 'A'): [PUBLIC], (h, 'CNAME'): dns.resolver.NoAnswer})
        out = monitor.check_asset(self.host, resolve=resolve, get=lambda url, provider: (404, None))
        self.assertEqual(out['status'], 'ok')
        self.assertEqual(set(self.tls.dialled), {(PUBLIC, 443)})  # never the IPv6 address, which has no route here
        self.assertEqual({u.split('/')[2] for s in FakeSession.made for u, _ in s.requests}, {PUBLIC})
        self.assertTrue(out['active'])  # a real observation, not 'nothing listening'
        self.assertEqual(RiskCheck.objects.get(asset=self.host, check_id='tls.cert_expired').status, 'pass')

    def test_scan_path_resolves_once_and_pins(self):
        from limes.checks import run
        root = Asset.objects.create(project=self.p, kind='root_domain', value='example.com', scope_tier='owned_root')
        Asset.objects.filter(pk=self.host.pk).update(parent=root)
        from startScan.models import IpAddress
        self.host.ip_addresses.add(IpAddress.objects.create(address=PUBLIC))
        resolve = self.resolve
        from limes import safe_fetch
        real = safe_fetch.resolve_vetted
        with mock.patch.object(safe_fetch, 'resolve_vetted',
                               lambda host, **kw: real(host, resolve=resolve) if host == 'a.example.com'
                               else (None, 'test: not this host')):
            run.run_checks(self.p, root, observers={'mail_dns': lambda r: ({'txt': [], 'dmarc': [], 'mx': []},
                                                                           {'ds': False, 'caa': False})})
        self.assert_only_public()
        self.assertFalse(root.risk_checks.filter(check_id__startswith='web.').exists())  # refused: no rows


class _Server:
    """A local HTTP(S) server on 127.0.0.1 answering 200 to every request; records Host headers."""
    def __init__(self, context=None, set_cookie=False):
        self.context, self.hosts, self.errors, self.cookies, self.set_cookie = context, [], [], [], set_cookie
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            try:
                conn.settimeout(5)
                if self.context:
                    conn = self.context.wrap_socket(conn, server_side=True)
                data = b''
                while b'\r\n\r\n' not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                for line in data.split(b'\r\n'):
                    if line.lower().startswith(b'host:'):
                        self.hosts.append(line[5:].strip().decode())
                    if line.lower().startswith(b'cookie:'):
                        self.cookies.append(line[7:].strip().decode())
                if data:
                    cookie = b'Set-Cookie: s=1; Path=/\r\n' if self.set_cookie else b''
                    conn.sendall(b'HTTP/1.1 200 OK\r\n' + cookie + b'Content-Length: 0\r\nConnection: close\r\n\r\n')
            except (OSError, ssl.SSLError) as e:  # the client refused our certificate: expected in the mismatch case
                self.errors.append(e)
            finally:
                conn.close()

    def close(self):
        self.stop.set()
        self.thread.join(5)
        self.sock.close()


def _ca_and_leaf(tmp, name):
    """A throwaway CA and a leaf for `name`, written as PEM files. Returns (ca_path, cert_path, key_path)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Limes Test CA')])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
          .not_valid_after(now + datetime.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                       key_encipherment=False, data_encipherment=False, key_agreement=False,
                                       encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca_name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    paths = [os.path.join(tmp, f) for f in ('ca.pem', 'leaf.pem', 'leaf.key')]
    for path, data in zip(paths, (ca.public_bytes(serialization.Encoding.PEM), leaf.public_bytes(serialization.Encoding.PEM),
                                  leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()))):
        with open(path, 'wb') as f:
            f.write(data)
    return paths


class PinnedTlsRealTest(SimpleTestCase):
    """Real handshakes against a local server: the connection goes to the vetted IP, yet the certificate is still
    verified against the HOSTNAME. A certificate for another name, from a CA the client trusts, must fail."""
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.ca, cert, key = _ca_and_leaf(tmp.name, 'good.test')
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(cert, key)
        self.tls = _Server(server_ctx)
        self.addCleanup(self.tls.close)
        self.dialled = []

    def create_connection(self, addr, timeout=None):
        self.dialled.append(addr)
        return socket.create_connection(('127.0.0.1', self.tls.port), timeout=timeout)  # 443 is privileged locally

    def trusting(self, legacy=None):
        return ssl.create_default_context(cafile=self.ca)

    def test_pinned_tls_checks_the_hostname_not_the_ip(self):
        from limes import safe_fetch
        connect = safe_fetch.pinned_tls_connect('127.0.0.1', create_connection=self.create_connection,
                                                context_factory=self.trusting)
        peer = connect('good.test')
        self.assertIn(('DNS', 'good.test'), peer['subjectAltName'])
        with self.assertRaises(ssl.SSLCertVerificationError) as e:
            connect('other.test')
        self.assertEqual(e.exception.verify_code, 62)  # hostname mismatch: the chain itself was trusted
        self.assertIn('other.test', str(e.exception))
        self.assertEqual(self.dialled, [('127.0.0.1', 443)] * 2)
        # with the default trust store the test CA is unknown: untrusted, never silently accepted
        with self.assertRaises(ssl.SSLCertVerificationError) as e:
            safe_fetch.pinned_tls_connect('127.0.0.1', create_connection=self.create_connection)('good.test')
        self.assertNotEqual(e.exception.verify_code, 62)

    def test_pinned_get_checks_the_hostname_not_the_ip(self):
        from limes import safe_fetch
        ok = safe_fetch.pinned_get('good.test', '127.0.0.1')(f'https://good.test:{self.tls.port}/', verify=self.ca, timeout=5)
        self.assertEqual(ok.status_code, 200)
        ok.close()
        self.assertEqual(self.tls.hosts, [f'good.test:{self.tls.port}'])
        with self.assertRaises(requests.exceptions.SSLError) as e:
            safe_fetch.pinned_get('other.test', '127.0.0.1')(f'https://other.test:{self.tls.port}/', verify=self.ca, timeout=5)
        self.assertIn('other.test', str(e.exception))
        plain = _Server()
        self.addCleanup(plain.close)
        r = safe_fetch.pinned_get('good.test', '127.0.0.1')(f'http://good.test:{plain.port}/', timeout=5)
        self.assertEqual(r.status_code, 200)
        r.close()
        self.assertEqual(plain.hosts, [f'good.test:{plain.port}'])

    def test_pinned_session_never_replays_cookies(self):
        """One pinned session serves every hop and the cleartext probe: a cookie set over https (perhaps in answer
        to the project's secret headers) must never be sent again, least of all in cleartext."""
        from limes import safe_fetch
        plain = _Server(set_cookie=True)
        self.addCleanup(plain.close)
        get = safe_fetch.pinned_get('good.test', '127.0.0.1')
        for _ in range(2):
            r = get(f'http://good.test:{plain.port}/', timeout=5)
            self.assertEqual(r.headers.get('Set-Cookie'), 's=1; Path=/')
            r.close()
        self.assertEqual((len(plain.hosts), plain.cookies), (2, []))


class Clock:
    def __init__(self, t=0.0):
        self.t = t

    def __call__(self):
        return self.t


class Drip:
    """A socket that answers one byte per recv and costs 4 s of the injected clock each time: never a full line."""
    def __init__(self, clock):
        self.clock, self.timeouts, self.sent, self.calls = clock, [], b'', 0

    def settimeout(self, t):
        self.timeouts.append(t)

    def sendall(self, data):
        self.sent += bytes(data)

    def send(self, data):
        self.sent += bytes(data)
        return len(data)

    def recv_into(self, buf, nbytes=0):
        self.calls += 1
        if self.calls > 1000:
            raise AssertionError('the deadline never fired')
        self.clock.t += 4
        buf[0:1] = b'x'
        return 1

    def close(self):
        pass

    def shutdown(self, how):
        pass

    def setsockopt(self, *a):
        pass


class DeadlineTest(SimpleTestCase):
    """A host dripping one byte every 4 s must not keep a check alive: the deadline is total, never reset."""
    def test_drip_does_not_reset_the_deadline(self):
        from limes import safe_fetch
        clock = Clock()
        drip = Drip(clock)
        f = safe_fetch._DeadlineSocket(drip, safe_fetch.Deadline(30, clock)).makefile('rb')
        with self.assertRaises(TimeoutError):
            f.readline()
        self.assertEqual((drip.calls, clock.t), (8, 32))  # 8 x 4 s; the last recv was armed with the 2 s left
        self.assertEqual(drip.timeouts, [5, 5, 5, 5, 5, 5, 5, 2])

    def test_pinned_get_through_requests_stops_at_the_deadline(self):
        from limes import safe_fetch
        from limes.checks import collect
        from limes.identity import ScanIdentity
        clock = Clock()
        dialled = []

        def connect(addr, timeout=None, *a, **kw):
            dialled.append((addr, timeout))
            if addr[1] != 80:
                raise ConnectionRefusedError()
            return Drip(clock)
        with mock.patch('urllib3.util.connection.create_connection', connect):
            obs = collect.observe_http('h.example.com', ScanIdentity(headers=[]), get=safe_fetch.pinned_get(
                'h.example.com', PUBLIC, deadline=safe_fetch.Deadline(30, clock)))
        self.assertEqual(obs['https'], None)  # refused on 443
        self.assertEqual(obs['http'], 'error')  # the drip timed out: unknown, never a pass
        self.assertEqual(clock.t, 32)
        self.assertEqual([a for a, _ in dialled], [(PUBLIC, 443), (PUBLIC, 80)])
        self.assertTrue(all(t <= 5 for _, t in dialled))

    def test_pinned_tls_connect_honours_the_deadline(self):
        from limes import safe_fetch
        clock, seen = Clock(), []

        def connect(addr, timeout=None):
            seen.append(timeout)
            raise ConnectionRefusedError()
        tls = safe_fetch.pinned_tls_connect(PUBLIC, create_connection=connect, deadline=safe_fetch.Deadline(30, clock))
        clock.t = 27
        with self.assertRaises(ConnectionRefusedError):
            tls('h.example.com')
        self.assertEqual(seen, [3])  # min(5 s, time left)
        clock.t = 31
        with self.assertRaises(TimeoutError):
            tls('h.example.com')
        self.assertEqual(seen, [3])  # past the deadline: never dialled
