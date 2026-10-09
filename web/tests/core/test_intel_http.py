from unittest import mock

import requests
from django.test import SimpleTestCase

from limes.intel import domains, http


class RegistrableTest(SimpleTestCase):
    def test_offline_and_normalized(self):
        with mock.patch('requests.sessions.Session.request', side_effect=AssertionError('network used')):
            self.assertEqual(domains.registrable('a.b.Example.CO.UK.'), 'example.co.uk')
            self.assertEqual(domains.registrable('shop.Bücher.de'), 'xn--bcher-kva.de')
        for bad in ('', None, 'localhost', 'com'):
            self.assertIsNone(domains.registrable(bad), bad)


class Resp:
    def __init__(self, status, body=None, bad_json=False):
        self.status_code, self.body, self.bad_json = status, body, bad_json

    def json(self):
        if self.bad_json:
            raise ValueError('not json')
        return self.body


class Session:
    def __init__(self, *items):
        self.items, self.calls = list(items), []

    def get(self, url, timeout=None, headers=None):
        self.calls.append((url, timeout, headers))
        item = self.items.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class GetJsonTest(SimpleTestCase):
    def setUp(self):
        http._last.clear()
        self.now, self.sleeps = [0.0], []

    def clock(self):
        return self.now[0]

    def sleep(self, s):
        self.sleeps.append(s)
        self.now[0] += s

    def get(self, session, provider='internetdb'):
        return http.get_json('https://x/', provider=provider, session=session, clock=self.clock, sleep=self.sleep)

    def test_success_uses_timeout_and_user_agent(self):
        s = Session(Resp(200, {'a': 1}))
        self.assertEqual(self.get(s), (200, {'a': 1}))
        self.assertEqual(s.calls[0][1], 30)
        self.assertEqual(s.calls[0][2]['User-Agent'], 'Limes-ASM')

    def test_retries_on_429_then_succeeds(self):
        s = Session(Resp(429), Resp(200, [1]))
        self.assertEqual(self.get(s), (200, [1]))
        self.assertEqual(len(s.calls), 2)
        self.assertIn(1, self.sleeps)  # backoff 2**0

    def test_gives_up_after_retries(self):
        s = Session(Resp(503), Resp(503), Resp(503))
        self.assertEqual(self.get(s), (None, None))
        self.assertEqual(len(s.calls), 3)

    def test_connection_errors_never_raise(self):
        err = requests.ConnectionError('down')
        self.assertEqual(self.get(Session(err, err, err)), (None, None))

    def test_404_is_returned_not_retried(self):
        s = Session(Resp(404, {'detail': 'No information available'}))
        self.assertEqual(self.get(s), (404, {'detail': 'No information available'}))
        self.assertEqual(len(s.calls), 1)

    def test_bad_json_returns_none_body(self):
        self.assertEqual(self.get(Session(Resp(200, bad_json=True))), (200, None))

    def test_min_interval_per_provider(self):
        s = Session(Resp(200, {}), Resp(200, {}))
        self.get(s, provider='crtsh')
        self.get(s, provider='crtsh')
        self.assertIn(5.0, self.sleeps)
