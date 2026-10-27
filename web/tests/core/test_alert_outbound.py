import dns.resolver
import requests
from django.test import SimpleTestCase

from limes.alerts import outbound

PUBLIC = '93.184.216.34'


def resolver(answers):
    def resolve(name, rdtype):
        found = answers.get((name, rdtype))
        if found is None:
            raise dns.resolver.NXDOMAIN()
        return list(found)
    return resolve


class FakeResponse:
    def __init__(self, status=200, body=None):
        self.status_code, self._body = status, body or {}

    def json(self):
        return self._body


class FakeSession:
    calls = []
    status = 200

    def __init__(self):
        self.cookies = None
        self.trust_env = True

    def mount(self, *a):
        pass

    def post(self, url, **kw):
        FakeSession.calls.append(('post', url, kw))
        return FakeResponse(FakeSession.status)

    get = post


class ValidateUrlTest(SimpleTestCase):
    def test_refused(self):
        for url in ('http://hooks.example.com/x', 'https://127.0.0.1/x', 'https://169.254.169.254/latest', 'https://10.0.0.5/',
                    'https://[::1]/x', 'https://localhost/x', 'https://user:pw@hooks.example.com/x', 'ftp://hooks.example.com/',
                    'https://hooks.example.com\\@evil/x', 'https://db.internal/x', '', 'https:///x', 'https://' + 'a' * 600 + '.com'):
            self.assertTrue(outbound.validate_url(url), url)

    def test_accepted(self):
        for url in ('https://hooks.example.com/x?y=1', 'https://acme.atlassian.net', 'https://8.8.8.8/x'):
            self.assertIsNone(outbound.validate_url(url), url)


class RequestTest(SimpleTestCase):
    def setUp(self):
        FakeSession.calls, FakeSession.status = [], 200
        self.resolve = resolver({('hooks.example.com', 'A'): [PUBLIC], ('hooks.example.com', 'AAAA'): [],
                                 ('rebind.example.com', 'A'): ['10.0.0.1'], ('rebind.example.com', 'AAAA'): [],
                                 ('meta.example.com', 'A'): ['169.254.169.254'], ('meta.example.com', 'AAAA'): []})

    def send(self, url, **kw):
        return outbound.request('post', url, data=b'{}', resolve=self.resolve, session_factory=FakeSession, **kw)

    def test_pins_to_the_vetted_ip_and_keeps_host_header(self):
        self.assertEqual(self.send('https://hooks.example.com/a?b=1').status_code, 200)
        method, url, kw = FakeSession.calls[0]
        self.assertEqual(url, f'https://{PUBLIC}/a?b=1')
        self.assertEqual(kw['headers']['Host'], 'hooks.example.com')
        self.assertFalse(kw['allow_redirects'])

    def test_refusals_never_connect(self):
        for url in ('http://hooks.example.com/x', 'https://127.0.0.1/x', 'https://169.254.169.254/x',
                    'https://rebind.example.com/x', 'https://meta.example.com/x', 'https://nx.example.com/x'):
            with self.assertRaises(outbound.OutboundError, msg=url) as cm:
                self.send(url)
            self.assertFalse(cm.exception.transient)
        self.assertEqual(FakeSession.calls, [])

    def test_error_text_does_not_carry_the_url(self):
        with self.assertRaises(outbound.OutboundError) as cm:
            self.send('https://rebind.example.com/secret-token-123')
        self.assertNotIn('secret-token-123', str(cm.exception))
        self.assertNotIn('10.0.0.1', str(cm.exception))

    def test_redirect_is_an_error_not_followed(self):
        FakeSession.status = 307
        with self.assertRaises(outbound.OutboundError):
            self.send('https://hooks.example.com/x')
        self.assertEqual(len(FakeSession.calls), 1)

    def test_status_classes(self):
        for status, transient in ((500, True), (503, True), (429, True), (400, False), (401, False), (404, False)):
            FakeSession.status = status
            with self.assertRaises(outbound.OutboundError) as cm:
                self.send('https://hooks.example.com/x')
            self.assertEqual(cm.exception.transient, transient, status)

    def test_network_failure_is_transient_and_scrubbed(self):
        class Boom(FakeSession):
            def post(self, url, **kw):
                raise requests.exceptions.ConnectionError('HTTPSConnectionPool host=hooks.example.com token=abc')
        with self.assertRaises(outbound.OutboundError) as cm:
            outbound.request('post', 'https://hooks.example.com/x', data=b'', resolve=self.resolve, session_factory=Boom)
        self.assertTrue(cm.exception.transient)
        self.assertNotIn('abc', str(cm.exception))
