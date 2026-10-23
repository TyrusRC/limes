import gzip
import http.server
import json
import logging
import os
import shutil
import tempfile
import threading
import time
from datetime import timedelta
from unittest import mock

from django.conf import settings
from django.core.cache import cache
from django.core.management import CommandError, call_command
from django.db import IntegrityError, transaction
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from dashboard.models import Project
from limes import celery_routing, continuous
from celery.exceptions import SoftTimeLimitExceeded

from limes.feeds import parse, sources, store, tasks
from startScan.models import Asset, DomainBreach, FeedState, Lookalike

FIX = os.path.join(os.path.dirname(__file__), 'fixtures', 'feeds')


def fixture(name):
    with open(os.path.join(FIX, name), 'rb') as f:
        return f.read()


class Resp:
    def __init__(self, status, headers, body, log=None):
        self.status_code, self.headers, self.body, self.log = status, headers or {}, body, log

    def iter_content(self, chunk_size=1):
        for i in range(0, len(self.body), chunk_size):
            if self.log is not None:
                self.log.append(i)
            yield self.body[i:i + chunk_size]

    def close(self):
        pass


class FakeSession:
    """routes: url -> (status, headers, body) or a list of them, consumed in order (the last one repeats)."""

    def __init__(self, routes):
        self.routes, self.calls, self.chunks = routes, [], []

    def get(self, url, headers=None, **kw):
        self.calls.append((url, dict(headers or {}), kw))
        r = self.routes.get(url)
        if r is None:
            raise AssertionError(f'unexpected request {url}')
        if isinstance(r, list):
            r = r.pop(0) if len(r) > 1 else r[0]
        return Resp(*r, log=self.chunks)


class ParserTests(SimpleTestCase):
    def test_parsers_on_fixtures(self):
        data, meta = parse.spamhaus_drop(fixture('drop_v4.json'))
        self.assertEqual(data, [('1.10.16.0/20', 'SBL256894'), ('1.19.0.0/16', 'SBL434604'),
                                ('2.26.75.0/24', 'SBL698389')])
        self.assertEqual((meta['rows'], meta['dropped']), (3, 0))
        self.assertEqual(meta['source_date'].isoformat(), '2026-10-23T04:44:02+00:00')
        self.assertIn('Spamhaus', meta['copyright'])
        v6, _ = parse.spamhaus_drop(fixture('drop_v6.json'))
        self.assertEqual(len(v6), 2)
        asns, meta = parse.spamhaus_asndrop(fixture('asndrop.json'))
        self.assertEqual(asns, [(245, 'EXAMPLE-AS'), (403005, 'BLATANTHOST')])
        ips, meta = parse.feodo(fixture('feodo.json'))
        self.assertEqual(ips, ['50.16.16.211'])  # 10.0.0.5 is private: dropped
        self.assertEqual(meta['dropped'], 1)
        data, meta = parse.kev(fixture('kev.json'))
        self.assertIs(data['CVE-2021-44228']['ransomware'], True)
        self.assertIs(data['CVE-2023-4966']['ransomware'], False)
        self.assertEqual(data['CVE-2021-44228']['added'].isoformat(), '2021-12-10')
        self.assertEqual(meta['rows'], 3)
        self.assertIsNotNone(meta['source_date'])
        data, meta = parse.epss(fixture('epss.csv.gz'), wanted={'CVE-2021-44228'})
        self.assertEqual(data, {'CVE-2021-44228': (0.97565, 1.0)})
        self.assertEqual(meta['rows'], 5)
        self.assertEqual(meta['model_version'], 'v2025.03.14')
        self.assertEqual(meta['source_date'].date().isoformat(), '2026-10-22')
        self.assertEqual(parse.epss(fixture('epss.csv.gz'))[0], {})
        data, meta = parse.rdap_bootstrap(fixture('iana_dns.json'))
        self.assertEqual(data, {'com': 'https://rdap.verisign.com/com/v1/', 'net': 'https://rdap.verisign.com/com/v1/'})
        self.assertEqual(meta['dropped'], 1)
        ips, meta = parse.plain_ips(fixture('blocklist.txt'))
        self.assertEqual(ips, ['203.0.114.7', '8.8.4.4'])
        self.assertEqual(meta['dropped'], 3)  # TEST-NET-2, private, garbage

    def test_hostile_feed_lines_ignored(self):
        blob = b'\n'.join([
            b'{"cidr":"0.0.0.0/0","sblid":"SBL1"}', b'{"cidr":"::/0"}', b'not json',
            b'{"cidr":"999.1.1.1/24"}', b'{"cidr":"1.2.3.0/24","sblid":"<script>"}',
            b'{"cidr":"1.2.3.0/24","sblid":"SBL1","x":"' + b'A' * 1_000_000 + b'"}',
            b'{"type":"metadata","timestamp":1792730642,"copyright":"c"}'])
        data, meta = parse.spamhaus_drop(blob)
        self.assertEqual((data, meta['rows'], meta['dropped']), ([], 0, 6))
        # private and wide-but-legal-looking entries
        data, _ = parse.spamhaus_drop(b'{"cidr":"10.0.0.0/16","sblid":"SBL5"}\n{"cidr":"4.0.0.0/7","sblid":"SBL6"}\n')
        self.assertEqual(data, [])
        data, meta = parse.kev(b'{"vulnerabilities":[{"cveID":"CVE-2021-1"},{"cveID":"cve-2021-44228 "},'
                               b'{"cveID":5},"x"]}')
        self.assertEqual(list(data), ['CVE-2021-44228'])
        self.assertEqual(meta['dropped'], 3)
        data, meta = parse.spamhaus_asndrop(b'{"asn":0}\n{"asn":4294967296}\n{"asn":"7"}\n{"asn":true}\n')
        self.assertEqual((data, meta['dropped']), ([], 4))

    def test_epss_out_of_range_and_garbage_dropped(self):
        body = gzip.compress(b'#model_version:v1,score_date:2026-10-22T00:00:00Z\ncve,epss,percentile\n'
                             b'CVE-2020-0001,1.5,0.5\nCVE-2020-0002,nan,0.5\nCVE-2020-0003,-0.1,0.5\n'
                             b'CVE-2020-0004,0.2\nnot a cve,0.1,0.1\nCVE-2020-0005,0.2,0.3\n')
        data, meta = parse.epss(body, wanted={'CVE-2020-0005', 'CVE-2020-0001'})
        self.assertEqual(data, {'CVE-2020-0005': (0.2, 0.3)})
        self.assertEqual((meta['rows'], meta['dropped']), (1, 5))

    def test_rdap_only_https_and_clean_tlds(self):
        blob = (b'{"publication":"2026-10-01T00:00:00Z","services":[[["COM","bad tld"],'
                b'["https://u:p@rdap.example/"]],[["org"],["http://a/","https://rdap.org/o"]],[["io"],["ftp://x/"]]]}')
        data, meta = parse.rdap_bootstrap(blob)
        self.assertEqual(data, {'org': 'https://rdap.org/o/'})
        self.assertEqual(meta['dropped'], 3)

    def test_v6_floor_and_mapped_and_integer_ips(self):
        data, meta = parse.spamhaus_drop(b'{"cidr":"2400::/15","sblid":"SBL1"}\n{"cidr":"2400::/16","sblid":"SBL2"}\n')
        self.assertEqual(data, [('2400::/16', 'SBL2')])
        self.assertEqual(meta['dropped'], 1)
        ips, meta = parse.feodo(b'[{"ip_address":134744072},{"ip_address":"::ffff:8.8.8.8"},'
                                b'{"ip_address":"2606:4700::1%eth0"},{"ip_address":"::ffff:10.0.0.1"}]')
        self.assertEqual((ips, meta['dropped']), (['8.8.8.8'], 3))
        ips, _ = parse.plain_ips(b'::ffff:8.8.4.4\n8.8.4.4\n')
        self.assertEqual(ips, ['8.8.4.4'])

    def test_deep_nesting_is_dropped_not_fatal(self):
        deep = b'[' * 4000 + b']' * 4000
        data, meta = parse.spamhaus_drop(deep + b'\n{"cidr":"1.19.0.0/16","sblid":"SBL4"}\n' + b'[' * 100_000)
        self.assertEqual((len(data), meta['dropped']), (1, 2))
        asns, meta = parse.spamhaus_asndrop(deep + b'\n{"asn":5}\n')
        self.assertEqual((asns, meta['dropped']), ([(5, '')], 1))

    def test_rdap_rejects_ip_literals_and_leading_dash(self):
        blob = (b'{"services":[[["com"],["https://10.0.0.1/"]],[["org"],["https://[::1]/"]],'
                b'[["-bad","good"],["https://rdap.example/"]],[["net"],["https://localhost/"]]]}')
        data, meta = parse.rdap_bootstrap(blob)
        self.assertEqual(data, {'good': 'https://rdap.example/'})
        self.assertEqual(meta['dropped'], 4)

    def test_big_lists_parse_in_linear_time(self):
        import time
        ips = '\n'.join(f'{(i >> 16) % 200 + 11}.{(i >> 8) & 255}.{i & 255}.{i % 250 + 1}' for i in range(200_000))
        t = time.monotonic()
        out, meta = parse.plain_ips(ips.encode())
        self.assertGreater(meta['rows'], 100_000)
        feo = b'[' + b','.join(b'{"ip_address":"%s"}' % x.encode() for x in ips.split('\n')[:200_000]) + b']'
        parse.feodo(feo)
        self.assertLess(time.monotonic() - t, 10)  # was ~110 s with the quadratic list scan
        junk = b'garbage\n' * 2_000_000
        self.assertEqual(parse.spamhaus_asndrop(junk)[1]['dropped'], 2_000_000)

    def test_declared_counts(self):
        _, meta = parse.spamhaus_drop(fixture('drop_v4.json'))
        self.assertEqual(meta['declared'], 3)
        self.assertIsNone(parse.spamhaus_drop(b'{"cidr":"1.19.0.0/16","sblid":"SBL4"}\n')[1]['declared'])
        self.assertEqual(parse.kev(fixture('kev.json'))[1]['declared'], 3)


def kev_blob(n, count=None, dup=0):
    vulns = [{'cveID': f'CVE-2020-{1000 + i}', 'dateAdded': '2024-01-01', 'dueDate': '2024-02-01',
              'knownRansomwareCampaignUse': 'Unknown'} for i in range(n)]
    vulns += vulns[:dup]
    doc = {'dateReleased': '2026-10-22T14:30:00.000Z', 'vulnerabilities': vulns}
    if count is not False:
        doc['count'] = len(vulns) if count is None else count
    return json.dumps(doc).encode()


class FeedFixtureCase(TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        ov = override_settings(LIMES_RESULTS=self.dir, ABUSECH_AUTH_KEY='', FEEDS_OPTIN=[], CONTINUOUS_SCANS=True)
        ov.enable()
        self.addCleanup(ov.disable)
        self.now = timezone.now()
        store._CACHE.clear()
        cache.clear()  # the daily download budget lives in the cache

    def feed(self, name):
        return sources.FEEDS[name]

    def ok(self, name, body=None, headers=None):
        return {self.feed(name).url: (200, headers or {}, body if body is not None else fixture(f'{name}.json'))}


class FetchTests(FeedFixtureCase):
    def test_conditional_get_and_not_modified(self):
        f = self.feed('kev')
        s = FakeSession({f.url: [(200, {'ETag': '"abc"', 'Last-Modified': 'Thu, 22 Oct 2026 14:00:00 GMT'},
                                  fixture('kev.json')), (304, {}, b'')]})
        self.assertEqual(store.fetch(f, self.now, s), 'ok')
        self.assertNotIn('If-None-Match', s.calls[0][1])
        good = FeedState.objects.get(name='kev').last_good_at
        before = fixture('kev.json')
        later = self.now + timedelta(days=1)
        self.assertEqual(store.fetch(f, later, s), 'not_modified')
        h = s.calls[1][1]
        self.assertEqual((h['If-None-Match'], h['If-Modified-Since']), ('"abc"', 'Thu, 22 Oct 2026 14:00:00 GMT'))
        self.assertEqual(h['User-Agent'], 'Limes-ASM')
        st = FeedState.objects.get(name='kev')
        self.assertEqual((st.last_good_at, st.status, st.fetched_at), (later, 'not_modified', later))  # 304 = confirmed fresh
        self.assertEqual(store.read('kev'), before)

    def test_zero_entry_fetch_rejected_keeps_last_good(self):
        f = self.feed('drop_v4')
        meta_only = b'{"type":"metadata","timestamp":1792730642,"copyright":"c"}\n'
        s = FakeSession({f.url: [(200, {}, fixture('drop_v4.json')), (200, {}, meta_only),
                                 (200, {}, b'<html>Service unavailable</html>')]})
        self.assertEqual(store.fetch(f, self.now, s), 'ok')
        good = store.read('drop_v4')
        self.assertEqual(store.fetch(f, self.now + timedelta(days=1), s), 'rejected')
        self.assertEqual(store.fetch(f, self.now + timedelta(days=2), s), 'rejected')
        st = FeedState.objects.get(name='drop_v4')
        self.assertEqual((st.entries, st.status, st.last_good_at), (3, 'rejected', self.now))
        self.assertEqual(store.read('drop_v4'), good)
        fe = self.feed('feodo')
        self.assertEqual(store.fetch(fe, self.now, FakeSession({fe.url: (200, {}, b'[]')})), 'ok')
        self.assertEqual(FeedState.objects.get(name='feodo').entries, 0)

    def test_size_cap_and_gzip_bomb(self):
        f = self.feed('epss')
        s = FakeSession({f.url: [(200, {}, fixture('epss.csv.gz')), (200, {}, b'x' * 4096)]})
        self.assertEqual(store.fetch(f, self.now, s), 'ok')
        good = store.read('epss')
        with mock.patch.object(store, 'MAX_BYTES', 1000):
            self.assertEqual(store.fetch(f, self.now, s), 'error')
        self.assertEqual(FeedState.objects.get(name='epss').error, 'TooLarge')
        self.assertEqual(store.read('epss'), good)
        # a gzip that inflates far past the cap is abandoned early (chunk count stays small)
        bomb = gzip.compress(b'0' * (8 * 1024 * 1024), 1)
        reads = []

        class Counting(gzip.GzipFile):
            def read(self, n=-1):
                reads.append(n)
                return super().read(n)

        s = FakeSession({f.url: (200, {}, bomb)})
        with mock.patch.object(store, 'MAX_BYTES', 1024 * 1024), mock.patch.object(parse, 'MAX_BYTES', 1024 * 1024), \
                mock.patch.object(parse.gzip, 'GzipFile', Counting):
            self.assertEqual(store.fetch(f, self.now, s), 'error')
        self.assertEqual(FeedState.objects.get(name='epss').error, 'ParseError')
        self.assertLess(len(reads), 40)  # 8 MB inflated would take ~128 reads of 64 KB
        self.assertEqual(store.read('epss'), good)
        # 51 MB of plain body (real cap) is refused too
        big = FakeSession({f.url: (200, {}, b'x' * (51 * 1024 * 1024))})
        self.assertEqual(store.fetch(f, self.now, big), 'error')
        self.assertLessEqual(len(big.chunks), store.MAX_BYTES // store.CHUNK + 1)

    def test_epss_redirect_same_host_only(self):
        f = self.feed('epss')
        dated = 'https://epss.empiricalsecurity.com/epss_scores-2026-10-22.csv.gz'
        s = FakeSession({f.url: (302, {'Location': 'epss_scores-2026-10-22.csv.gz'}, b''),
                         dated: (200, {'ETag': '"e1"'}, fixture('epss.csv.gz'))})
        self.assertEqual(store.fetch(f, self.now, s), 'ok')
        self.assertEqual([c[0] for c in s.calls], [f.url, dated])
        self.assertTrue(all(c[2].get('allow_redirects') is False for c in s.calls))
        for bad in ('https://evil.example/x', 'http://epss.empiricalsecurity.com/x', 'https://epss.empiricalsecurity.com:8443/x'):
            s = FakeSession({f.url: (302, {'Location': bad}, b'')})
            self.assertEqual(store.fetch(f, self.now, s), 'error')
            self.assertEqual(len(s.calls), 1)
        loop = FakeSession({f.url: (302, {'Location': f.url}, b'')})
        self.assertEqual(store.fetch(f, self.now, loop), 'error')
        self.assertLessEqual(len(loop.calls), 4)

    def test_error_never_logs_headers(self):
        f = self.feed('feodo')
        with override_settings(ABUSECH_AUTH_KEY='k-secret'), self.assertLogs('limes.feeds', 'DEBUG') as cm:
            logging.getLogger('limes.feeds').debug('start')
            s = FakeSession({f.url: (500, {'X-Echo': 'k-secret'}, b'k-secret oops')})
            self.assertEqual(store.fetch(f, self.now, s), 'error')
        self.assertEqual(s.calls[0][1]['Auth-Key'], 'k-secret')
        self.assertNotIn('k-secret', '\n'.join(cm.output))
        st = FeedState.objects.get(name='feodo')
        self.assertEqual(st.error, 'HTTP 500')
        self.assertTrue(any('HTTP 500' in line for line in cm.output))
        # the key goes to abuse.ch hosts only
        k = self.feed('kev')
        with override_settings(ABUSECH_AUTH_KEY='k-secret'):
            s = FakeSession(self.ok('kev'))
            store.fetch(k, self.now, s)
        self.assertNotIn('Auth-Key', s.calls[0][1])

    def test_exception_in_parser_or_transport_is_an_error_not_a_crash(self):
        f = self.feed('kev')
        self.assertEqual(store.fetch(f, self.now, FakeSession({f.url: (200, {}, b'{"vulnerabilities": [')})), 'error')
        self.assertEqual(FeedState.objects.get(name='kev').error, 'JSONDecodeError')

        class Boom:
            def get(self, *a, **k):
                import requests
                raise requests.ConnectionError('secret-host-detail')
        self.assertEqual(store.fetch(f, self.now, Boom()), 'error')
        self.assertEqual(FeedState.objects.get(name='kev').error, 'ConnectionError')

    def test_allow_empty_feeds_reject_garbage_pages(self):
        html = b'<html>\n<body>Service unavailable</body>\n</html>\n'
        for name in ('blocklist_de', 'cins'):
            f = self.feed(name)
            s = FakeSession({f.url: [(200, {}, fixture('blocklist.txt')), (200, {}, html), (200, {}, b'# nothing\n')]})
            self.assertEqual(store.fetch(f, self.now, s), 'ok')
            good = store.read(name)
            self.assertEqual(store.fetch(f, self.now, s), 'rejected', name)
            self.assertEqual(store.read(name), good)
            self.assertEqual(FeedState.objects.get(name=name).entries, 2)
            self.assertEqual(store.fetch(f, self.now, s), 'ok')  # a genuinely empty list is still fine
            self.assertEqual(FeedState.objects.get(name=name).entries, 0)

    def test_truncated_or_shrunk_copies_rejected(self):
        f = self.feed('drop_v4')
        body = fixture('drop_v4.json')
        no_trailer = b'\n'.join(body.split(b'\n')[:-2]) + b'\n'
        wrong = body.replace(b'"records":3', b'"records":9')
        s = FakeSession({f.url: [(200, {}, body), (200, {}, no_trailer), (200, {}, wrong)]})
        self.assertEqual(store.fetch(f, self.now, s), 'ok')
        self.assertEqual(store.fetch(f, self.now, s), 'rejected')
        self.assertEqual(store.fetch(f, self.now, s), 'rejected')
        self.assertEqual(store.read('drop_v4'), body)
        a = self.feed('asndrop')
        s = FakeSession({a.url: (200, {}, fixture('asndrop.json').replace(b'"records":2', b'"records":5'))})
        self.assertEqual(store.fetch(a, self.now, s), 'rejected')
        k = self.feed('kev')
        s = FakeSession({k.url: (200, {}, fixture('kev.json').replace(b'"count": 3', b'"count": 30'))})
        self.assertEqual(store.fetch(k, self.now, s), 'rejected')
        self.assertIsNone(store.read('kev'))

    def test_not_modified_counts_as_fresh(self):
        f = self.feed('kev')
        s = FakeSession({f.url: [(200, {'ETag': '"a"'}, fixture('kev.json')), (304, {}, b'')]})
        store.fetch(f, self.now, s)
        later = self.now + timedelta(days=5)
        store.fetch(f, later, s)
        st = FeedState.objects.get(name='kev')
        self.assertEqual(st.last_good_at, later)
        self.assertFalse(store.is_stale(f, st, later + timedelta(days=1)))

    def test_total_deadline_stops_a_dripping_server(self):
        f = self.feed('kev')

        class Drip(Resp):
            def iter_content(self, chunk_size=1):
                while True:
                    yield b'x'

        class S:
            def get(self, *a, **k):
                return Drip(200, {}, b'')

        ticks = iter(range(0, 10 ** 6, 29))  # each clock read is 29 s later: no real sleeping
        with mock.patch.object(store.time, 'monotonic', lambda: next(ticks)):
            self.assertEqual(store.fetch(f, self.now, S()), 'error')
        self.assertEqual(FeedState.objects.get(name='kev').error, 'Timeout')

    def test_soft_time_limit_is_not_swallowed(self):
        class S:
            def get(self, *a, **k):
                raise SoftTimeLimitExceeded()
        with self.assertRaises(SoftTimeLimitExceeded):
            store.fetch(self.feed('kev'), self.now, S())

    def test_due_and_stale(self):
        f = self.feed('drop_v4')
        st = FeedState(name='drop_v4', fetched_at=self.now - timedelta(hours=23))
        self.assertFalse(store.due(f, st, self.now))
        st.fetched_at = self.now - timedelta(hours=24)
        self.assertTrue(store.due(f, st, self.now))
        self.assertTrue(store.due(f, None, self.now))
        st.last_good_at = self.now - timedelta(hours=71)
        self.assertFalse(store.is_stale(f, st, self.now))
        st.last_good_at = self.now - timedelta(hours=73)
        self.assertTrue(store.is_stale(f, st, self.now))
        st.last_good_at = None
        self.assertTrue(store.is_stale(f, st, self.now))

    def test_load_is_memoized_and_unknown_names_refused(self):
        f = self.feed('kev')
        store.fetch(f, self.now, FakeSession(self.ok('kev')))
        a = store.load('kev')
        self.assertIs(store.load('kev')[0], a[0])
        self.assertIn('CVE-2021-44228', a[0])
        self.assertIsNone(store.load('feodo'))
        with self.assertRaises(KeyError):
            store.feed_path('../../etc/passwd')


class RefreshTests(FeedFixtureCase):
    def routes(self):
        r = {}
        for n, fx in (('drop_v4', 'drop_v4.json'), ('drop_v6', 'drop_v6.json'), ('asndrop', 'asndrop.json'),
                      ('feodo', 'feodo.json'), ('kev', 'kev.json'), ('epss', 'epss.csv.gz'),
                      ('iana_rdap', 'iana_dns.json'), ('blocklist_de', 'blocklist.txt'), ('cins', 'blocklist.txt')):
            r[sources.FEEDS[n].url] = (200, {}, fixture(fx))
        return r

    def test_refresh_respects_optin_and_lock(self):
        s = FakeSession(self.routes())
        with mock.patch.object(tasks, 'SESSION', s):
            out = tasks.refresh_feeds()
            self.assertEqual(sorted(out['fetched']), sorted(['drop_v4', 'drop_v6', 'asndrop', 'feodo', 'kev', 'epss',
                                                             'iana_rdap']))
            self.assertEqual(sorted(out['changed']), sorted(out['fetched']))
            n = len(s.calls)
            self.assertEqual(tasks.refresh_feeds()['fetched'], [])  # same hour: nothing due
            self.assertEqual(len(s.calls), n)
            with override_settings(FEEDS_OPTIN=['cins']):
                self.assertEqual(tasks.refresh_feeds()['fetched'], ['cins'])
            self.assertNotIn(sources.FEEDS['blocklist_de'].url, [c[0] for c in s.calls])
            with continuous.tick_lock('refresh_feeds') as got:
                self.assertTrue(got)
                self.assertEqual(tasks.refresh_feeds()['reason'], 'locked')
            with override_settings(CONTINUOUS_SCANS=False):
                self.assertEqual(tasks.refresh_feeds()['reason'], 'disabled')

    def test_one_download_per_day_for_daily_feeds(self):
        self.assertEqual(tasks._daily_limit(sources.FEEDS['drop_v4']), 1)
        self.assertEqual(tasks._daily_limit(sources.FEEDS['feodo']), 4)
        self.assertEqual(tasks._daily_limit(sources.FEEDS['iana_rdap']), 1)
        s = FakeSession(self.routes())
        with mock.patch.object(tasks, 'SESSION', s):
            tasks.refresh_feeds()
            FeedState.objects.update(fetched_at=self.now - timedelta(days=2))  # due again, same UTC day
            self.assertEqual(tasks.refresh_feeds()['fetched'], ['feodo'])  # the 6 h feed has 4 a day

    def test_daily_budget_caps_downloads(self):
        s = FakeSession(self.routes())
        with mock.patch.object(tasks, 'SESSION', s), mock.patch.object(tasks.ratelimit, 'take_daily', return_value=False):
            self.assertEqual(tasks.refresh_feeds()['fetched'], [])
        self.assertEqual(s.calls, [])

    def test_one_failing_feed_does_not_stop_the_others(self):
        r = self.routes()
        r[sources.FEEDS['drop_v4'].url] = (503, {}, b'')
        with mock.patch.object(tasks, 'SESSION', FakeSession(r)):
            out = tasks.refresh_feeds()
        self.assertNotIn('drop_v4', out['changed'])
        self.assertIn('kev', out['changed'])
        self.assertEqual(FeedState.objects.get(name='drop_v4').status, 'error')


class MetadataTests(SimpleTestCase):
    def test_every_feed_has_credit_and_terms(self):
        for name, f in sources.FEEDS.items():
            self.assertEqual(f.name, name)
            self.assertTrue(f.credit and f.licence, name)
            self.assertTrue(f.terms.startswith('https://'), name)
            self.assertTrue(f.url.startswith('https://'), name)
            self.assertIn(f.parser, parse.PARSERS)
        for n in ('drop_v4', 'drop_v6', 'asndrop'):
            self.assertIn('The Spamhaus Project', sources.FEEDS[n].credit)
        self.assertNotIn('sslbl', sources.FEEDS)
        self.assertEqual({n for n, f in sources.FEEDS.items() if f.optin}, {'blocklist_de', 'cins'})
        self.assertTrue(sources.FEEDS['feodo'].allow_empty)
        self.assertIn('CC0', sources.FEEDS['iana_rdap'].licence)
        self.assertEqual(sources.FEEDS['feodo'].cadence, timedelta(hours=6))
        self.assertEqual(sources.FEEDS['iana_rdap'].cadence, timedelta(days=7))
        self.assertEqual(sources.REPUTATION, ('drop_v4', 'drop_v6', 'asndrop', 'feodo', 'blocklist_de', 'cins'))

    def test_enabled(self):
        with override_settings(FEEDS_OPTIN=[]):
            self.assertTrue(sources.enabled(sources.FEEDS['kev']))
            self.assertFalse(sources.enabled(sources.FEEDS['cins']))
        with override_settings(FEEDS_OPTIN=['cins']):
            self.assertTrue(sources.enabled(sources.FEEDS['cins']))
            self.assertFalse(sources.enabled(sources.FEEDS['blocklist_de']))

    def test_beat_and_routing(self):
        self.assertEqual(settings.CELERY_BEAT_SCHEDULE['refresh-feeds'], {
            'task': 'refresh_feeds', 'schedule': 3600.0, 'options': {'expires': 3300}})
        self.assertEqual(celery_routing.TASK_PLAN['refresh_feeds'], (celery_routing.IO, 15 * celery_routing.MIN))
        self.assertIn('limes.feeds.tasks', settings.CELERY_IMPORTS)


class ModelTests(TestCase):
    def test_models_constraints(self):
        p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        root = Asset.objects.create(project=p, kind='root_domain', value='example.com')
        Lookalike.objects.create(project=p, root=root, domain='examp1e.com', unicode='examp1e.com', source='permutation')
        with self.assertRaises(IntegrityError), transaction.atomic():
            Lookalike.objects.create(project=p, root=root, domain='examp1e.com', unicode='x', source='ct')
        DomainBreach.objects.create(project=p, root=root, breach_name='B', addresses=3)
        with self.assertRaises(IntegrityError), transaction.atomic():
            DomainBreach.objects.create(project=p, root=root, breach_name='B', addresses=4)


class ShrinkRecoveryTests(FeedFixtureCase):
    def seq(self, *bodies):
        f = self.feed('kev')
        return f, FakeSession({f.url: [(200, {}, b) for b in bodies]})

    def test_identical_shrunk_copy_accepted_after_three_rejections(self):
        f, s = self.seq(kev_blob(100), *[kev_blob(20)] * 4)
        self.assertEqual(store.fetch(f, self.now, s), 'ok')
        for i in range(3):
            self.assertEqual(store.fetch(f, self.now, s), 'rejected')
        st = FeedState.objects.get(name='kev')
        self.assertEqual((st.entries, st.error, st.shrank_count), (100, 'shrank', 3))
        self.assertEqual(store.fetch(f, self.now, s), 'ok')
        st = FeedState.objects.get(name='kev')
        self.assertEqual((st.entries, st.shrank_count, st.shrank_sha256), (20, 0, ''))

    def test_a_different_copy_or_an_ok_resets_the_count(self):
        f, s = self.seq(kev_blob(100), kev_blob(20), kev_blob(20), kev_blob(21), kev_blob(21), kev_blob(21),
                        kev_blob(21), kev_blob(90), kev_blob(20))
        store.fetch(f, self.now, s)
        store.fetch(f, self.now, s)
        store.fetch(f, self.now, s)
        self.assertEqual(FeedState.objects.get(name='kev').shrank_count, 2)
        store.fetch(f, self.now, s)  # different sha: starts again at 1
        self.assertEqual(FeedState.objects.get(name='kev').shrank_count, 1)
        store.fetch(f, self.now, s)
        store.fetch(f, self.now, s)
        self.assertEqual(FeedState.objects.get(name='kev').shrank_count, 3)
        self.assertEqual(store.fetch(f, self.now, s), 'ok')  # 4th identical
        self.assertEqual(store.fetch(f, self.now, s), 'ok')  # 90 of 21 grows
        self.assertEqual(FeedState.objects.get(name='kev').shrank_count, 0)

    def test_allow_empty_feeds_are_exempt_from_the_ratio_rule(self):
        fe = self.feed('feodo')
        sixty = json.dumps([{'ip_address': f'8.8.{i // 250}.{i % 250 + 1}'} for i in range(60)]).encode()
        s = FakeSession({fe.url: [(200, {}, sixty), (200, {}, b'[]')]})
        self.assertEqual(store.fetch(fe, self.now, s), 'ok')
        self.assertEqual(store.fetch(fe, self.now, s), 'ok')
        self.assertEqual(FeedState.objects.get(name='feodo').entries, 0)

    def test_small_feeds_below_the_floor_are_exempt(self):
        f, s = self.seq(kev_blob(49), kev_blob(5))
        self.assertEqual(store.fetch(f, self.now, s), 'ok')
        self.assertEqual(store.fetch(f, self.now, s), 'ok')

    def test_force_bypasses_shrink_and_count_but_not_garbage_or_size(self):
        f, s = self.seq(kev_blob(100), kev_blob(20), kev_blob(20, count=99), b'<html>\nnope\n</html>')
        store.fetch(f, self.now, s)
        self.assertEqual(store.fetch(f, self.now, s, force=True), 'ok')
        self.assertEqual(store.fetch(f, self.now, s, force=True), 'ok')  # count mismatch skipped when forced
        self.assertEqual(store.fetch(f, self.now, s, force=True), 'error')  # not JSON at all
        with mock.patch.object(store, 'MAX_BYTES', 100):
            s2 = FakeSession({f.url: (200, {}, kev_blob(20))})
            self.assertEqual(store.fetch(f, self.now, s2, force=True), 'error')
        g = self.feed('blocklist_de')
        s3 = FakeSession({g.url: (200, {}, b'<html>\n<body>x</body>\n</html>')})
        self.assertEqual(store.fetch(g, self.now, s3, force=True), 'rejected')

    def test_kev_without_count_or_with_duplicates_is_not_locked_out(self):
        f, s = self.seq(kev_blob(10, count=False), kev_blob(10, dup=2))
        self.assertEqual(store.fetch(f, self.now, s), 'ok')
        self.assertEqual(store.fetch(f, self.now, s), 'ok')  # count 12 raw records, 10 distinct CVEs
        f, s = self.seq(kev_blob(10, count=50))
        self.assertEqual(store.fetch(f, self.now, s), 'rejected')

    def test_spamhaus_trailer_may_or_may_not_count_itself(self):
        f = self.feed('drop_v4')
        for records in (3, 4):
            FeedState.objects.all().delete()
            body = fixture('drop_v4.json').replace(b'"records":2', b'"records":%d' % records)
            body = body.replace(b'"records":3', b'"records":%d' % records)
            s = FakeSession({f.url: (200, {}, body)})
            self.assertEqual(store.fetch(f, self.now, s), 'ok', records)
        body = fixture('drop_v4.json').replace(b'"records":3', b'"records":5')
        self.assertEqual(store.fetch(f, self.now, FakeSession({f.url: (200, {}, body)})), 'rejected')

    def test_refresh_feeds_command_force(self):
        g = self.feed('kev')
        s = FakeSession({g.url: [(200, {}, kev_blob(100)), (200, {}, kev_blob(20))]})
        with mock.patch.object(tasks, 'SESSION', s):
            call_command('refresh_feeds', 'kev')
            self.assertEqual(FeedState.objects.get(name='kev').entries, 100)
            cache.clear()  # a new day's budget
            FeedState.objects.update(fetched_at=self.now - timedelta(days=2))
            with self.assertRaises(CommandError):  # shrank: non-zero exit for the operator
                call_command('refresh_feeds', 'kev')
            self.assertEqual(FeedState.objects.get(name='kev').entries, 100)
            cache.clear()
            s.routes[g.url] = [(200, {}, kev_blob(20))]
            call_command('refresh_feeds', 'kev', '--force')
        self.assertEqual(FeedState.objects.get(name='kev').entries, 20)
        with self.assertRaises(CommandError):
            call_command('refresh_feeds', 'nope')


class Drip(http.server.BaseHTTPRequestHandler):
    """Sends headers, then one byte every 0.2 s for up to 8 s. mode: length | close | chunked."""
    mode = 'length'

    def log_message(self, *a):
        pass

    def do_GET(self):
        mode = self.server.mode
        try:
            self.send_response(200)
            if mode == 'length':
                self.send_header('Content-Length', '1000000')
            elif mode == 'chunked':
                self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()
            self.wfile.flush()
            for _ in range(40):
                time.sleep(0.2)
                self.wfile.write(b'1\r\nx\r\n' if mode == 'chunked' else b'x')
                self.wfile.flush()
        except OSError:
            pass


class RealDeadlineTests(FeedFixtureCase):
    """Real sockets on 127.0.0.1: the production https-only and same-host rules stay as they are; only the
    session handed to fetch() rewrites the scheme."""

    def serve(self, mode):
        srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Drip)
        srv.daemon_threads, srv.mode = True, mode
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        self.addCleanup(srv.server_close)
        return srv

    def test_total_deadline_stops_a_blocked_read(self):
        import requests

        class HttpSession:
            def get(self, url, **kw):
                return requests.get(url.replace('https://', 'http://', 1), **kw)

        for mode in ('length', 'close', 'chunked'):
            srv = self.serve(mode)
            f = self.feed('kev')._replace(url=f'https://127.0.0.1:{srv.server_address[1]}/kev.json')
            t = time.monotonic()
            with mock.patch.object(store, 'DEADLINE', 1.0):
                status = store.fetch(f, self.now, HttpSession())
            took = time.monotonic() - t
            self.assertEqual(status, 'error', mode)
            self.assertLess(took, 2.5, mode)
            self.assertEqual(FeedState.objects.get(name='kev').error, 'Timeout', mode)
            self.assertIsNone(store.read('kev'))
            for th in [x for x in threading.enumerate() if isinstance(x, threading.Timer)]:
                th.join(1)
            self.assertEqual([x for x in threading.enumerate() if isinstance(x, threading.Timer) and x.is_alive()], [])

    def test_soft_time_limit_after_the_deadline_is_not_a_timeout(self):
        class Slow(Resp):
            def iter_content(self, chunk_size=1):
                yield b'x'
                raise SoftTimeLimitExceeded()

        class S:
            def get(self, *a, **k):
                return Slow(200, {}, b'')

        ticks = iter(range(0, 10 ** 6, 100))
        with mock.patch.object(store.time, 'monotonic', lambda: next(ticks)), \
                self.assertRaises(SoftTimeLimitExceeded):
            store.fetch(self.feed('kev'), self.now, S())
