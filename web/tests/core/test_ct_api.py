import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import timedelta
from unittest import mock

import requests
from django.conf import settings
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone
from django_redis import get_redis_connection

from dashboard.models import Project
from limes import celery_routing
from limes.ct import api, health
from startScan.models import Asset, CertSighting, ChangeEvent

KEY = 'sk-test-SECRET'


class Resp:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code, self.headers = status, headers or {}
        self.raw = json.dumps(body if body is not None else []).encode()
        self.closed = False

    def iter_content(self, chunk_size=1):
        for i in range(0, len(self.raw), chunk_size):
            yield self.raw[i:i + chunk_size]

    def close(self):
        self.closed = True


class Session:
    def __init__(self, *responses):
        self.responses, self.calls = list(responses), []

    def get(self, url, **kw):
        self.calls.append((url, kw))
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def issuance(i, tbs, names=('a.x.com',)):
    return {'id': str(i), 'tbs_sha256': tbs, 'cert_sha256': tbs, 'dns_names': list(names),
            'not_before': '2026-10-01T00:00:00Z', 'not_after': '2027-01-01T00:00:00Z', 'issuer': {'name': 'O=Let\'s Encrypt'}}


@override_settings(CERTSPOTTER_API_KEY=KEY, CONTINUOUS_SCANS=True, CT_WATCH=False, CERTSPOTTER_HOURLY_BUDGET=7)
class Base(TestCase):
    def setUp(self):
        cache.clear()
        self.r = get_redis_connection('default')
        self.wipe()
        self.addCleanup(self.wipe)
        self.now = timezone.now()
        self.p = Project.objects.create(name='p', slug='p', insert_date=self.now)
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='x.com', scope_tier='owned_root')
        d = mock.patch('limes.ct.api.deliver_immediate')
        d.start()
        self.addCleanup(d.stop)

    def wipe(self):
        for pat in ('limes:ct:*', 'limes:evq*', 'limes:tick:*'):
            for k in self.r.scan_iter(pat):
                self.r.delete(k)

    def poll(self, *responses, now=None):
        self.r.delete(api.SLOT_KEY)
        s = Session(*responses)
        with self.captureOnCommitCallbacks(execute=True):
            out = api.poll_once(now or self.now, session=s)
        return out, s

    def cursor(self, a=None):
        a = a or self.root
        a.refresh_from_db()
        return a.enrichment['certspotter']


class PollTest(Base):
    def test_no_key_no_request(self):
        s = Session()
        with override_settings(CERTSPOTTER_API_KEY=''), mock.patch('limes.ct.api.requests', s), \
                mock.patch('limes.ct.api.health.transition', return_value=None) as t:
            self.assertEqual(api.poll_ct_api(), {'transition': None, 'polled': None})
        self.assertEqual(s.calls, [])
        t.assert_called_once()

    def test_one_request_per_slot(self):
        Asset.objects.create(project=self.p, kind='root_domain', value='z.org', scope_tier='owned_root')
        s = Session(Resp(body=[]), Resp(body=[]))
        self.assertIsNotNone(api.poll_once(self.now, session=s))
        self.assertIsNone(api.poll_once(self.now, session=s))  # z.org is still due: only the slot stops it
        self.assertEqual(len(s.calls), 1)
        self.assertEqual(self.r.ttl(api.SLOT_KEY), 515)  # ceil(3600 / 7)

    def test_baseline_silent_then_events(self):
        out, s = self.poll(Resp(body=[issuance(11, '1' * 64), issuance(12, '2' * 64, ['b.x.com'])]))
        url, kw = s.calls[0]
        self.assertEqual(url, api.URL)
        self.assertEqual(kw['params'], [('domain', 'x.com'), ('include_subdomains', 'true'), ('match_wildcards', 'true'),
                                        ('expand', 'dns_names'), ('expand', 'issuer')])
        self.assertEqual(kw['headers']['Authorization'], f'Bearer {KEY}')
        self.assertFalse(kw['allow_redirects'])
        self.assertEqual(kw['timeout'], api.http.TIMEOUT)
        self.assertEqual(CertSighting.objects.filter(source='certspotter_api').count(), 2)
        self.assertEqual(ChangeEvent.objects.count(), 0)
        self.assertEqual(self.cursor()['after'], '12')
        self.assertFalse(self.cursor()['baseline_done'])
        out, s = self.poll(Resp(body=[], headers={'Retry-After': '300'}))
        self.assertEqual(s.calls[0][1]['params'][-1], ('after', '12'))
        c = self.cursor()
        self.assertTrue(c['baseline_done'])
        self.assertEqual(c['retry_at'], (self.now + timedelta(seconds=300)).isoformat())
        later = self.now + timedelta(seconds=301)
        out, s = self.poll(Resp(body=[issuance(13, '3' * 64, ['c.x.com'])]), now=later)
        self.assertEqual(ChangeEvent.objects.filter(kind='cert_new').count(), 1)
        self.assertIn(('after', '12'), s.calls[0][1]['params'])
        self.assertEqual(self.cursor()['after'], '13')

    def test_not_due_root_is_skipped(self):
        self.poll(Resp(body=[], headers={'Retry-After': '300'}))
        out, s = self.poll(now=self.now + timedelta(seconds=10))
        self.assertIsNone(out)
        self.assertEqual(s.calls, [])

    def test_rate_limited_and_errors_logged_without_key(self):
        with self.assertLogs('limes.ct.api', level='DEBUG') as logs:
            logging.getLogger('limes.ct.api').debug('start')
            self.poll(Resp(429, {'code': 'rate_limited', 'message': KEY}))
            self.assertEqual(self.cursor()['retry_at'], (self.now + timedelta(hours=1)).isoformat())
            self.root.enrichment = {}
            self.root.save()
            self.poll(requests.ConnectionError(f'boom {KEY}'))
        text = '\n'.join(r.getMessage() for r in logs.records)
        self.assertIn('ConnectionError', text)
        self.assertNotIn('SECRET', text)
        self.assertNotIn('SECRET', ' '.join(str(r.args) + str(r.exc_info) for r in logs.records))

    def test_client_error_backs_off_an_hour(self):
        self.poll(Resp(401, {'code': 'x'}))
        self.assertEqual(self.cursor()['retry_at'], (self.now + timedelta(hours=1)).isoformat())

    def test_oversize_body_is_refused(self):
        big = Resp(body=[issuance(1, '1' * 64, ['a.x.com'] + [f'h{i}.x.com' for i in range(2000)])])
        with mock.patch.object(api, 'MAX_BYTES', 1000):
            out, _ = self.poll(big)
        self.assertEqual(CertSighting.objects.count(), 0)
        self.assertTrue(big.closed)
        self.assertGreater(len(self.cursor()['retry_at']), 0)

    def test_hostile_ids_and_garbage_are_ignored(self):
        out, _ = self.poll(Resp(body=[{'id': '1; drop', 'tbs_sha256': 'zz', 'dns_names': ['a.x.com']}, 'x',
                                      issuance(5, '5' * 64)]))
        self.assertEqual(CertSighting.objects.count(), 1)
        self.assertEqual(self.cursor()['after'], '5')

    def test_api_while_watch_ok_marks_only_when_healthy(self):
        with mock.patch('limes.ct.api.health.evaluate', return_value={'state': 'healthy', 'reasons': [], 'heartbeat': {}}):
            self.poll(Resp(body=[issuance(1, '1' * 64)]))
        with mock.patch('limes.ct.api.health.evaluate', return_value={'state': 'degraded', 'reasons': ['no_heartbeat'], 'heartbeat': None}):
            self.poll(Resp(body=[issuance(2, '2' * 64)]))
        self.assertEqual(dict(CertSighting.objects.values_list('tbs_sha256', 'api_while_watch_ok')), {'1' * 64: True, '2' * 64: False})

    def test_shared_root_polled_once_ingested_per_project(self):
        o = Project.objects.create(name='o', slug='o', insert_date=self.now)
        root2 = Asset.objects.create(project=o, kind='root_domain', value='x.com', scope_tier='owned_root')
        out, s = self.poll(Resp(body=[issuance(1, '1' * 64)]))
        self.assertEqual(len(s.calls), 1)
        self.assertEqual(sorted(CertSighting.objects.values_list('project_id', flat=True)), sorted([self.p.id, o.id]))
        self.assertEqual(self.cursor()['after'], '1')
        self.assertEqual(self.cursor(root2)['after'], '1')

    def test_oldest_polled_first(self):
        z = Asset.objects.create(project=self.p, kind='root_domain', value='z.org', scope_tier='owned_root')
        self.poll(Resp(body=[]))
        out, s = self.poll(Resp(body=[]), now=self.now + timedelta(hours=2))
        self.assertEqual({dict(c[1]['params'])['domain'] for c in [s.calls[0]]}, {'z.org'})
        self.assertNotEqual(self.cursor(z).get('polled_at'), None)

    def test_beat_routing(self):
        self.assertEqual(settings.CELERY_BEAT_SCHEDULE['poll-ct-api'],
                         {'task': 'poll_ct_api', 'schedule': 60.0, 'options': {'expires': 55}})
        self.assertEqual(celery_routing.TASK_PLAN['poll_ct_api'], (celery_routing.IO, 15 * celery_routing.MIN))
        self.assertIn('limes.ct.api', settings.CELERY_IMPORTS)


def serve(handler):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            handler(self)
    srv = HTTPServer(('127.0.0.1', 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f'http://127.0.0.1:{srv.server_address[1]}/v1/issuances'


class RealNetworkTest(Base):
    def run_against(self, handler, **patches):
        srv, url = serve(handler)
        self.addCleanup(srv.shutdown)
        self.addCleanup(srv.server_close)
        self.r.delete(api.SLOT_KEY)
        with mock.patch.multiple(api, URL=url, **patches):
            with self.assertLogs('limes.ct.api', level='WARNING') as logs:
                out = api.poll_once(self.now)
        return out, '\n'.join(r.getMessage() + str(r.exc_info) for r in logs.records)

    def test_connection_dropped_mid_body_backs_off(self):
        def h(req):
            req.send_response(200)
            req.send_header('Content-Length', '1000')
            req.end_headers()
            req.wfile.write(b'[{"id"')
            req.wfile.flush()
            req.connection.close()
        out, text = self.run_against(h)
        self.assertEqual(out['status'], 'error')
        self.assertEqual(self.cursor()['retry_at'], (self.now + timedelta(seconds=900)).isoformat())
        self.assertNotIn('SECRET', text)
        self.assertNotIn('Traceback', text)

    def test_slow_drip_is_cut_at_the_deadline(self):
        def h(req):
            req.send_response(200)
            req.send_header('Content-Length', '100000')
            req.end_headers()
            try:
                for _ in range(100):
                    req.wfile.write(b' ')
                    req.wfile.flush()
                    time.sleep(0.2)
            except OSError:
                pass
        t = time.monotonic()
        out, _ = self.run_against(h, DEADLINE=1)
        self.assertLess(time.monotonic() - t, 8)
        self.assertEqual(out['status'], 'error')
        self.assertIsNotNone(self.cursor()['retry_at'])


class CursorTest(Base):
    def test_second_project_adding_a_root_does_not_silence_the_first(self):
        CertSighting.objects.create(project=self.p, tbs_sha256='1' * 64, source='certspotter_api')
        self.root.enrichment = {'certspotter': {'after': '1', 'baseline_done': True, 'polled_at': self.now.isoformat(), 'retry_at': None}}
        self.root.save()
        o = Project.objects.create(name='o', slug='o', insert_date=self.now)
        root2 = Asset.objects.create(project=o, kind='root_domain', value='x.com', scope_tier='owned_root')
        out, s = self.poll(Resp(body=[issuance(1, '1' * 64), issuance(2, '2' * 64, ['new.x.com'])]),
                           now=self.now + timedelta(hours=1))
        self.assertNotIn('after', dict(s.calls[0][1]['params']))  # the new project needs the whole history
        ev = ChangeEvent.objects.filter(kind='cert_new')
        self.assertEqual({e.project_id for e in ev}, {self.p.id})
        self.assertEqual(CertSighting.objects.filter(project=o).count(), 2)
        out, s = self.poll(Resp(body=[]), now=self.now + timedelta(hours=2))
        self.assertTrue(self.cursor(root2)['baseline_done'])
        self.assertTrue(self.cursor()['baseline_done'])

    def test_zero_issuance_root_alerts_on_its_first_cert(self):
        self.poll(Resp(body=[], headers={'Retry-After': '60'}))
        c = self.cursor()
        self.assertEqual((c['after'], c['baseline_done']), (None, True))
        self.poll(Resp(body=[issuance(7, '7' * 64, ['new.x.com'])]), now=self.now + timedelta(minutes=5))
        self.assertEqual(ChangeEvent.objects.filter(kind='cert_new').count(), 1)

    def test_failed_cert_stops_the_page_and_is_skipped_after_three(self):
        items = [issuance(1, '1' * 64), issuance(2, '2' * 64), issuance(3, '3' * 64)]
        real = api.ingest.ingest

        def flaky(record, *a, **kw):
            if record['tbs_sha256'] == '2' * 64:
                raise RuntimeError('boom')
            return real(record, *a, **kw)
        with mock.patch('limes.ct.api.ingest.ingest', side_effect=flaky):
            for n in (1, 2):
                self.poll(Resp(body=items), now=self.now + timedelta(minutes=n))
                self.assertEqual(self.cursor()['after'], '1')
                self.assertEqual(CertSighting.objects.count(), 1)
            self.poll(Resp(body=items), now=self.now + timedelta(minutes=3))
        self.assertEqual(self.cursor()['after'], '3')
        self.assertEqual(sorted(CertSighting.objects.values_list('tbs_sha256', flat=True)), ['1' * 64, '3' * 64])

    def test_page_is_capped(self):
        with mock.patch.object(api, 'PAGE_MAX', 2):
            self.poll(Resp(body=[issuance(i, str(i) * 64) for i in (1, 2, 3, 4)]))
        self.assertEqual(self.cursor()['after'], '2')
        self.assertEqual(CertSighting.objects.count(), 2)

    def test_key_is_stripped(self):
        with override_settings(CERTSPOTTER_API_KEY=f'  {KEY}\n'):
            out, s = self.poll(Resp(body=[]))
        self.assertEqual(s.calls[0][1]['headers']['Authorization'], f'Bearer {KEY}')

    def test_card_reports_unpolled_roots(self):
        Asset.objects.create(project=self.p, kind='root_domain', value='z.org', scope_tier='owned_root')
        self.poll(Resp(body=[]))
        c = api.card(self.p, self.now)
        self.assertIsNone(c['oldest_poll_age'])
        self.assertEqual(c['unpolled'], 1)

    def test_transition_runs_outside_the_fetch_lock(self):
        seen = []
        with mock.patch('limes.ct.api.health.transition',
                        side_effect=lambda now: seen.append(self.r.exists('limes:tick:poll_ct_api')) or None), \
                mock.patch('limes.ct.api.poll_once', return_value=None):
            api.poll_ct_api()
        self.assertEqual(seen, [0])
