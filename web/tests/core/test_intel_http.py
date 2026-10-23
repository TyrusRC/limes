from datetime import date
from unittest import mock

import requests
from django.core.cache import cache
from django.test import SimpleTestCase

from limes.intel import domains, http, ratelimit


class RegistrableTest(SimpleTestCase):
    def test_offline_and_normalized(self):
        with mock.patch('requests.sessions.Session.request', side_effect=AssertionError('network used')):
            self.assertEqual(domains.registrable('a.b.Example.CO.UK.'), 'example.co.uk')
            self.assertEqual(domains.registrable('shop.Bücher.de'), 'xn--bcher-kva.de')
        for bad in ('', None, 'localhost', 'com'):
            self.assertIsNone(domains.registrable(bad), bad)

    def test_private_suffix_tenant_owns_its_own_name(self):
        self.assertEqual(domains.registrable('www.myorg.github.io'), 'myorg.github.io')
        for suffix in ('github.io', 'herokuapp.com'):
            self.assertIsNone(domains.registrable(suffix), suffix)


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

    def get(self, url, timeout=None, headers=None, allow_redirects=None):
        self.calls.append((url, timeout, headers, allow_redirects))
        item = self.items.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class GetJsonTest(SimpleTestCase):
    def setUp(self):
        cache.clear()
        self.now, self.sleeps = [0.0], []

    def clock(self):
        return self.now[0]

    def sleep(self, s):
        self.sleeps.append(s)
        self.now[0] += s

    def get(self, session, provider='internetdb'):
        return http.get_json('https://x/', provider=provider, session=session, clock=self.clock, sleep=self.sleep)

    def test_saturated_provider_returns_busy_without_sleeping(self):
        s = Session(Resp(200, {}))
        with mock.patch.object(http.ratelimit, 'reserve', return_value=None), self.assertLogs('limes.intel.http', 'WARNING'):
            self.assertEqual(self.get(s), (None, None))
        self.assertEqual((s.calls, self.sleeps), ([], []))

    def test_get_json_headers_and_max_wait(self):
        s = Session(Resp(200, {}))
        self.assertEqual(http.get_json('https://x/', provider='hibp', session=s, clock=self.clock, sleep=self.sleep,
                                       headers={'hibp-api-key': 'k'}), (200, {}))
        self.assertEqual(s.calls[0][2], {'User-Agent': 'Limes-ASM', 'hibp-api-key': 'k'})
        s = Session(Resp(200, {}))
        with mock.patch.object(http.ratelimit, 'reserve', return_value=30.0):
            self.assertEqual(http.get_json('https://x/', provider='hibp', session=s, clock=self.clock, sleep=self.sleep,
                                           max_wait=5), (None, None))
        self.assertEqual((s.calls, self.sleeps), ([], []))

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

    def test_redirects_are_not_followed(self):
        s = Session(Resp(200, {}))
        self.get(s)
        self.assertIs(s.calls[0][3], False)

    def test_redirect_returned_as_status_not_retried(self):
        s = Session(Resp(301, bad_json=True))
        self.assertEqual(self.get(s), (301, None))
        self.assertEqual(len(s.calls), 1)

    def test_bad_json_returns_none_body(self):
        self.assertEqual(self.get(Session(Resp(200, bad_json=True))), (200, None))

    def test_min_interval_per_provider(self):
        s = Session(Resp(200, {}), Resp(200, {}))
        self.get(s, provider='crtsh')
        self.get(s, provider='crtsh')
        self.assertIn(5.0, self.sleeps)


class BrokenCache:
    def add(self, *a, **k):
        raise ConnectionError('redis down')

    incr = add


class RateLimitTest(SimpleTestCase):
    def setUp(self):
        cache.clear()
        ratelimit._local.clear()

    def test_reserve_spaces_calls_across_processes(self):
        self.assertAlmostEqual(ratelimit.reserve('internetdb', 1.0, now=100.2), 0.8)
        self.assertAlmostEqual(ratelimit.reserve('internetdb', 1.0, now=100.2), 1.8)
        self.assertAlmostEqual(ratelimit.reserve('ripestat', 1.0, now=100.2), 0.8)  # providers are independent

    def test_slots_never_closer_than_interval(self):
        fire = [100.9 + ratelimit.reserve('p', 1.0, now=100.9), 101.0 + ratelimit.reserve('p', 1.0, now=101.0)]
        self.assertGreaterEqual(fire[1] - fire[0], 1.0)

    def test_saturated_returns_none(self):
        for _ in range(ratelimit.SLOTS):
            self.assertIsNotNone(ratelimit.reserve('p', 1.0, now=50.0))
        self.assertIsNone(ratelimit.reserve('p', 1.0, now=50.0))

    def test_reserve_falls_back_locally_when_cache_is_down(self):
        ratelimit._warned = False
        with self.assertLogs('limes.intel.ratelimit', 'WARNING') as logs:
            self.assertEqual(ratelimit.reserve('p', 1.0, now=10.0, cache=BrokenCache()), 0)
        self.assertIn('per-process spacing', logs.output[0])
        self.assertAlmostEqual(ratelimit.reserve('p', 1.0, now=10.2, cache=BrokenCache()), 0.8)

    def test_take_daily_and_per_tick(self):
        self.assertTrue(all(ratelimit.take_daily('internetdb', 5000, today=date(2026, 1, 1)) for _ in range(5000)))
        self.assertFalse(ratelimit.take_daily('internetdb', 5000, today=date(2026, 1, 1)))
        self.assertTrue(ratelimit.take_daily('internetdb', 5000, today=date(2026, 1, 2)))
        self.assertEqual(ratelimit.per_tick(5000), 4)
        self.assertEqual(ratelimit.per_tick(10000), 7)
        self.assertEqual(ratelimit.per_tick(1), 1)

    def test_take_daily_fails_closed_when_cache_is_down(self):
        ratelimit._warned = False
        with self.assertLogs('limes.intel.ratelimit', 'WARNING') as logs:
            self.assertFalse(ratelimit.take_daily('internetdb', 5000, cache=BrokenCache()))
        self.assertIn('failing closed', logs.output[0])
