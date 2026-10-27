import json
import logging
from unittest import mock

import requests
from django.core.cache import cache
from django.test import override_settings

from limes import code_search
from limes.intel import ratelimit
from startScan.models import RiskCheck
from tests.core.test_api_discovery import Resp
from tests.core.test_dashboard_stats import Base
from tests.core.test_safe_fetch import FakeSession, PUBLIC, stub

TOKEN = 'ghp_TESTTOKEN0123456789abcdefghijklmnop'
KEY = 'sb_secret_' + 'Ab3dEf6hIj9kLm2nOp5qRs8T'  # Supabase secret shape, the detector of checks/leak.py
LEAK = f'const url = "https://api.x.com"; const k = "{KEY}"'
SPLIT = f'url = "https://api.x.com"\nconst k = "{KEY}"'  # domain and key on different lines


def item(repo, path, *fragments):
    return {'path': path, 'repository': {'full_name': repo}, 'text_matches': [{'fragment': f} for f in fragments]}


def page(*items):
    return (200, json.dumps({'total_count': len(items), 'items': list(items)}).encode())


class Github:
    """fake allowlisted_get: serves queued pages, records URLs and headers."""
    def __init__(self, *pages):
        self.pages, self.calls = list(pages), []

    def __call__(self, url, **kw):
        assert kw.get('allow_redirects') is False
        self.calls.append((url, kw['headers']))
        return Resp(*(self.pages.pop(0) if self.pages else page()))


class HitsTest(Base):
    def test_domain_and_credential_must_share_a_line(self):
        out = code_search.hits_in([item('a/b', 'cfg.js', LEAK), item('c/d', 'x.js', SPLIT), item('e/f', 'y.js', f'k = "{KEY}"'),
                                   item('g/h', 'z.js', 'host = api.x.com no key here')], 'x.com')
        self.assertEqual(out, [{'repo': 'a/b', 'path': 'cfg.js', 'shape': 'sb_secret_…' + KEY[-4:]}])
        self.assertNotIn(KEY, repr(out))

    def test_hostile_items_are_dropped_or_clipped(self):
        bad = [item('../etc/passwd', 'a.js', LEAK), item('a b/c', 'a.js', LEAK), item('a/b', '', LEAK), 'str', None,
               {'path': 'p', 'repository': 'nope', 'text_matches': [{'fragment': LEAK}]},
               {'path': 'p', 'repository': {'full_name': 'o/r'}, 'text_matches': 'oops'},
               {'path': 'p', 'repository': {'full_name': 'o/r'}, 'text_matches': [None, {'fragment': 5}]}]
        self.assertEqual(code_search.hits_in(bad, 'x.com'), [])
        out = code_search.hits_in([item('o/r', '<img src=x onerror=1>\x00\n' + 'p' * 500, LEAK)], 'x.com')
        self.assertLessEqual(len(out[0]['path']), 200)
        self.assertNotIn('\x00', out[0]['path'])


class SearchTest(Base):
    def setUp(self):
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        patch = mock.patch.object(code_search.ratelimit, 'reserve', return_value=0.0)
        patch.start()
        self.addCleanup(patch.stop)
        self.gh = Github()

    def run_search(self, **kw):
        return code_search.discover(self.p, self.root, self.now, make_get=lambda: self.gh, sleep=lambda s: None, **kw)

    def row(self):
        return RiskCheck.objects.get(asset=self.root, check_id='leak.public_code')

    def test_off_without_a_token(self):
        with override_settings(CODE_SEARCH_TOKEN=''):
            self.assertEqual(self.run_search(), {'reason': 'no token'})
        self.assertEqual(self.gh.calls, [])
        self.assertFalse(RiskCheck.objects.filter(check_id='leak.public_code').exists())

    @override_settings(CODE_SEARCH_TOKEN=TOKEN)
    def test_hit_is_stored_as_repo_path_and_masked_shape_only(self):
        self.gh.pages = [page(item('acme/app', 'src/cfg.js', LEAK), item('acme/docs', 'README.md', 'see x.com'))]
        with self.assertLogs('limes', level=logging.DEBUG) as logs:
            logging.getLogger('limes').debug('probe')  # assertLogs needs one record
            out = self.run_search()
        self.assertEqual(out['hits'], 1)
        row = self.row()
        self.assertEqual(row.status, 'fail')
        self.assertEqual(row.evidence, {'hits': [{'repo': 'acme/app', 'path': 'src/cfg.js', 'shape': 'sb_secret_…' + KEY[-4:]}],
                                        'count': 1})
        blob = repr(row.evidence) + '\n'.join(logs.output)
        for secret in (KEY, TOKEN, 'const url', 'README'):
            self.assertNotIn(secret, blob)

    @override_settings(CODE_SEARCH_TOKEN=TOKEN)
    def test_token_only_in_the_header_and_search_is_bounded(self):
        full = page(*[item(f'o/r{i}', 'f.js', 'x.com') for i in range(code_search.PER_PAGE)])
        self.gh.pages = [full, full, full, full]
        self.run_search()
        self.assertEqual(len(self.gh.calls), code_search.MAX_PAGES)
        for url, headers in self.gh.calls:
            self.assertTrue(url.startswith('https://api.github.com/search/code?q=%22x.com%22'))
            self.assertNotIn(TOKEN, url)
            self.assertEqual(headers['Authorization'], f'Bearer {TOKEN}')
        self.assertEqual(self.row().status, 'pass')
        self.assertNotIn(TOKEN, repr(self.row().evidence))

    @override_settings(CODE_SEARCH_TOKEN=TOKEN)
    def test_refused_or_broken_search_is_an_error_never_a_pass(self):
        self.gh.pages = [(403, b'{"message":"rate limit"}')]
        self.run_search()
        self.assertEqual(self.row().status, 'error')
        self.assertEqual(len(self.gh.calls), 1)
        RiskCheck.objects.all().delete()
        self.gh.pages = [(200, b'not json')]
        self.run_search()
        self.assertEqual(self.row().status, 'error')

    @override_settings(CODE_SEARCH_TOKEN=TOKEN)
    def test_budget_fails_closed(self):
        broken = mock.Mock()
        broken.add.side_effect = ConnectionError('down')
        real = ratelimit.take_daily
        with mock.patch.object(ratelimit, 'take_daily', lambda provider, limit: real(provider, limit, cache=broken)):
            self.run_search()
        self.assertEqual(self.gh.calls, [])
        self.assertEqual(self.row().status, 'error')

    @override_settings(CODE_SEARCH_TOKEN=TOKEN)
    def test_only_the_github_api_host_can_be_fetched(self):
        session = FakeSession(lambda url: Resp(200, b'{"items": []}'))
        get = code_search.safe_fetch.allowlisted_get((code_search.HOST,), resolve=stub({('api.github.com', 'A'): [PUBLIC]}),
                                                     session_factory=lambda: session)
        for url in ('https://github.com/search', 'https://api.github.com.evil.example/', 'https://x.api.github.com/'):
            with self.assertRaises(requests.exceptions.InvalidURL):
                get(url)
        self.assertEqual(session.requests, [])
        code_search.discover(self.p, self.root, self.now, make_get=lambda: get, sleep=lambda s: None)
        self.assertEqual(len(session.requests), 1)
        self.assertIn(PUBLIC, session.requests[0][0])

    @override_settings(CODE_SEARCH_TOKEN=TOKEN)
    def test_fresh_row_and_non_roots_are_left_alone(self):
        self.run_search()
        n = len(self.gh.calls)
        self.run_search()
        self.assertEqual(len(self.gh.calls), n)
        host = self.asset('a.x.com')
        self.assertEqual(code_search.discover(self.p, host, self.now, make_get=lambda: self.gh)['reason'], 'not an owned root')
