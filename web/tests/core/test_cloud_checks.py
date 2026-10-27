from unittest import mock

import requests
from django.core.cache import cache
from django.test import SimpleTestCase, override_settings

from limes import cloud_storage, safe_fetch
from limes.checks import cloud
from limes.intel import ratelimit
from limes.checks.catalogue import PROVISIONAL
from startScan.models import RiskCheck
from tests.core.test_api_discovery import Resp
from tests.core.test_dashboard_stats import Base
from tests.core.test_safe_fetch import FakeSession, PUBLIC, stub, _Resp

S3_LIST = b'<?xml version="1.0"?><ListBucketResult><Name>x</Name><Contents><Key>secret/payroll.xlsx</Key></Contents><Contents><Key>b.txt</Key></Contents></ListBucketResult>'
AZ_LIST = b'<?xml version="1.0"?><EnumerationResults><Blobs><Blob><Name>hidden.bak</Name></Blob></Blobs></EnumerationResults>'
DENIED = b'<Error><Code>AccessDenied</Code></Error>'


class Providers:
    """fake allowlisted_get: serves a body per URL, records every URL, 404 otherwise."""
    def __init__(self, routes=None):
        self.routes, self.urls = routes or {}, []

    def __call__(self, url, **kw):
        assert kw.get('allow_redirects') is False
        self.urls.append(url)
        return Resp(*self.routes.get(url, (404, b'')))


class NamesTest(SimpleTestCase):
    def test_bounded_and_label_safe(self):
        n = cloud.names('example.com')
        self.assertLessEqual(len(n), cloud.MAX_NAMES)
        self.assertEqual(n[:3], ['example', 'example-com', 'example-backup'])
        self.assertEqual(len(set(n)), len(n))
        for bad in ('', 'ex ample.com', 'a/b.com', '-x.com', 'x_y.com', 'é.com'):
            self.assertEqual(cloud.names(bad), [], bad)

    def test_urls_stay_on_provider_hosts(self):
        for name in cloud.names('example.com'):
            for provider in cloud.PROVIDERS:
                u = cloud.url(provider, name)
                if u:
                    host = u.split('/')[2]
                    self.assertTrue(safe_fetch.host_allowed(host, cloud.ALLOW_EXACT, cloud.ALLOW_SUFFIX), u)
        self.assertIsNone(cloud.url('azure', 'ab'))  # account names are 3 to 24 letters and digits

    def test_listing_needs_proof(self):
        self.assertEqual(cloud.listing('s3', 200, S3_LIST), 2)
        self.assertEqual(cloud.listing('gcs', 200, S3_LIST), 2)
        self.assertEqual(cloud.listing('azure', 200, AZ_LIST), 1)
        self.assertIsNone(cloud.listing('s3', 403, DENIED))
        self.assertIsNone(cloud.listing('s3', 200, b'<html>welcome</html>'))
        self.assertIsNone(cloud.listing('azure', 200, S3_LIST))  # wrong provider shape
        self.assertEqual(cloud.listing('s3', 200, b'<ListBucketResult>' + b'<Key>k</Key>' * 5000), cloud.MAX_COUNT)


class AllowlistTest(SimpleTestCase):
    def get(self, session=None):
        session = session or FakeSession(lambda url: _Resp(200))
        resolve = stub({('b.s3.amazonaws.com', 'A'): [PUBLIC], ('storage.googleapis.com', 'A'): [PUBLIC],
                        ('evil.s3.amazonaws.com', 'A'): ['10.0.0.1']})
        return safe_fetch.allowlisted_get(cloud.ALLOW_EXACT, cloud.ALLOW_SUFFIX, resolve=resolve,
                                          session_factory=lambda: session), session

    def test_other_hosts_are_never_requested(self):
        get, session = self.get()
        for url in ('https://evil.example/', 'http://b.s3.amazonaws.com/', 'https://b.s3.amazonaws.com.evil.example/',
                    'https://x.y.s3.amazonaws.com/', 'https://user@b.s3.amazonaws.com/', 'https://b.s3.amazonaws.com:8443/',
                    'https://b.s3.amazonaws.com\\@evil.example/', 'https://127.0.0.1/', 'https://s3.amazonaws.com.evil.example/'):
            with self.assertRaises(requests.exceptions.InvalidURL, msg=url):
                get(url)
        self.assertEqual(session.requests, [])

    def test_vetted_ip_is_pinned_and_private_answers_refused(self):
        get, session = self.get()
        get('https://b.s3.amazonaws.com/', timeout=5, allow_redirects=True)
        self.assertEqual(len(session.requests), 1)
        self.assertIn(PUBLIC, session.requests[0][0])  # the request goes to the vetted IP
        with self.assertRaises(requests.exceptions.ConnectionError):
            get('https://evil.s3.amazonaws.com/')
        with self.assertRaises(requests.exceptions.ConnectionError):
            get('https://nothere.s3.amazonaws.com/')  # does not resolve
        self.assertEqual(len(session.requests), 1)


class SweepTest(Base):
    def setUp(self):
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        self.fake = Providers()
        patch = mock.patch.object(cloud_storage.ratelimit, 'reserve', return_value=0.0)  # no real spacing in tests
        patch.start()
        self.addCleanup(patch.stop)

    def run_sweep(self, **kw):
        return cloud_storage.discover(self.p, self.root, self.now, make_get=lambda: self.fake, sleep=lambda s: None, **kw)

    def row(self):
        return RiskCheck.objects.get(asset=self.root, check_id='cloud.open_storage')

    def test_open_buckets_flagged_with_counts_only(self):
        self.fake.routes = {'https://x-backup.s3.amazonaws.com/': (200, S3_LIST),
                            'https://storage.googleapis.com/x-data/': (200, S3_LIST),
                            'https://xassets.blob.core.windows.net/x-assets?restype=container&comp=list': (200, AZ_LIST),
                            'https://x-com.s3.amazonaws.com/': (403, DENIED)}
        out = self.run_sweep()
        row = self.row()
        self.assertEqual(row.status, 'fail')
        self.assertEqual(out['open'], 3)
        found = {(b['provider'], b['name'], b['objects']) for b in row.evidence['buckets']}
        self.assertEqual(found, {('s3', 'x-backup', 2), ('gcs', 'x-data', 2), ('azure', 'x-assets', 1)})
        blob = repr(row.evidence)
        for secret in ('payroll', 'hidden.bak', 'secret/', 'b.txt', 'ListBucketResult'):
            self.assertNotIn(secret, blob)
        self.assertEqual(row.severity, 3)

    def test_closed_buckets_pass_and_request_volume_is_bounded(self):
        self.fake.routes = {'https://x-com.s3.amazonaws.com/': (403, DENIED)}
        self.run_sweep()
        self.assertEqual(self.row().status, 'pass')
        self.assertLessEqual(len(self.fake.urls), cloud.MAX_NAMES * len(cloud.PROVIDERS))
        self.assertEqual(len(self.fake.urls), len(set(self.fake.urls)))
        self.assertTrue(all(u.startswith('https://') for u in self.fake.urls))

    def test_budget_is_failing_closed(self):
        with mock.patch.object(cloud_storage, 'DAILY_BUDGET', 5):
            self.run_sweep()
        self.assertEqual(len(self.fake.urls), 5)
        self.assertEqual(self.row().status, 'error')  # an unfinished sweep is never a pass
        cache.clear()
        self.fake.urls.clear()
        RiskCheck.objects.all().delete()
        broken = mock.Mock()
        broken.add.side_effect = ConnectionError('down')
        real = ratelimit.take_daily
        with mock.patch.object(ratelimit, 'take_daily', lambda provider, limit, *a: real(provider, limit, cache=broken)):
            self.run_sweep()
        self.assertEqual(self.fake.urls, [])
        self.assertEqual(self.row().status, 'error')

    @override_settings(CLOUD_CHECKS=False)
    def test_setting_turns_it_off(self):
        self.run_sweep()
        self.assertEqual(self.fake.urls, [])
        self.assertFalse(RiskCheck.objects.filter(check_id='cloud.open_storage').exists())

    def test_fresh_row_is_not_swept_again_but_errors_are(self):
        self.run_sweep()
        n = len(self.fake.urls)
        self.run_sweep()
        self.assertEqual(len(self.fake.urls), n)
        RiskCheck.objects.filter(check_id='cloud.open_storage').update(status='error')
        self.run_sweep()
        self.assertEqual(len(self.fake.urls), 2 * n)

    def test_oversized_body_is_cut_at_the_cap(self):
        big = b'<ListBucketResult>' + b'<Key>k</Key>' * 200000
        self.fake.routes = {'https://x-backup.s3.amazonaws.com/': (200, big)}
        seen = []
        orig = cloud_storage._read
        with mock.patch.object(cloud_storage, '_read', lambda r: seen.append(len(orig(r))) or orig(r)):
            self.run_sweep()
        self.assertEqual(seen, [cloud_storage.BODY_CAP])
        self.assertEqual(self.row().evidence['buckets'][0]['objects'], cloud.MAX_COUNT)

    def test_provisional(self):
        self.assertIn('cloud.open_storage', PROVISIONAL)
