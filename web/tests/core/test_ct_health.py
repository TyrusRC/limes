import json
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone
from django_redis import get_redis_connection

from dashboard.models import Project
from limes.ct import health, watch
from startScan.models import Asset, CertSighting, ChangeEvent

TBS = 'cd' * 32


class Base(TestCase):
    def setUp(self):
        cache.clear()
        self.r = get_redis_connection('default')
        self.wipe()
        self.addCleanup(self.wipe)
        self.now = timezone.now()
        self.p = Project.objects.create(name='p', slug='p', insert_date=self.now)

    def wipe(self):
        for pat in ('limes:ct:*', 'limes:evq*'):
            for k in self.r.scan_iter(pat):
                self.r.delete(k)

    def beat(self, age=5, **kw):
        hb = {'pid_alive': True, 'restarts_10m': 0, 'spool_depth': 0, 'last_error_at': None, 'last_error_summary': None,
              'health': 'ok', 'state': 'running', 'watchlist_size': 3, 'watchlist_dropped': 0,
              'last_match_at': None, 'at': (self.now - timedelta(seconds=age)).isoformat(), **kw}
        self.r.set(watch.HEARTBEAT, json.dumps(hb), ex=600)

    def reasons(self):
        return health.evaluate(self.now)['reasons']


@override_settings(CT_WATCH=True, CONTINUOUS_SCANS=True, CERTSPOTTER_API_KEY='')
class EvaluateTest(Base):
    def test_modes(self):
        self.assertEqual(health.mode(), 'real-time')
        with override_settings(CT_WATCH=False, CERTSPOTTER_API_KEY='k'):
            self.assertEqual(health.mode(), 'api')
        with override_settings(CT_WATCH=False):
            self.assertEqual(health.mode(), 'cadence')
        with override_settings(CT_WATCH=True, CERTSPOTTER_API_KEY='k', CONTINUOUS_SCANS=False):
            self.assertEqual(health.mode(), 'cadence')

    def test_degraded_rules(self):
        self.assertEqual(health.evaluate(self.now)['reasons'], ['no_heartbeat'])
        cases = [({'age': 400}, 'stale_heartbeat'), ({'pid_alive': False}, 'process_down'),
                 ({'restarts_10m': 4}, 'restart_storm'), ({'spool_depth': 1001}, 'spool_backlog'),
                 ({'last_error_at': (self.now - timedelta(minutes=59)).isoformat()}, 'watcher_error')]
        for kw, code in cases:
            self.beat(**kw)
            self.assertEqual((health.evaluate(self.now)['state'], self.reasons()), ('degraded', [code]), code)
        self.beat(last_error_at=(self.now - timedelta(minutes=61)).isoformat(), restarts_10m=3, spool_depth=1000)
        self.assertEqual(health.evaluate(self.now)['state'], 'healthy')
        self.beat(state='idle', pid_alive=False)
        self.assertEqual(health.evaluate(self.now)['state'], 'idle')

    def test_off_when_not_watching(self):
        with override_settings(CT_WATCH=False):
            self.assertEqual(health.evaluate(self.now)['state'], 'off')
        with override_settings(CONTINUOUS_SCANS=False):
            self.assertEqual(health.evaluate(self.now)['state'], 'off')

    def test_unreadable_heartbeat_is_not_healthy(self):
        self.r.set(watch.HEARTBEAT, 'not json')
        self.assertEqual(health.evaluate(self.now)['state'], 'degraded')
        self.r.set(watch.HEARTBEAT, json.dumps({'at': 'junk'}))
        self.assertEqual(health.evaluate(self.now)['state'], 'degraded')


@override_settings(CT_WATCH=True, CONTINUOUS_SCANS=True, CERTSPOTTER_API_KEY='k')
class TransitionTest(Base):
    def setUp(self):
        super().setUp()
        self.q = Project.objects.create(name='q', slug='q', insert_date=self.now)
        patcher = mock.patch('limes.ct.health.deliver_immediate')
        self.deliver = patcher.start()
        self.addCleanup(patcher.stop)

    def test_degraded_once_even_with_api(self):
        self.assertIsNone(health.transition(self.now))  # no heartbeat: first evaluation only stores
        self.assertEqual(ChangeEvent.objects.count(), 0)
        self.beat()
        self.assertIsNone(health.transition(self.now))
        self.assertEqual(ChangeEvent.objects.count(), 0)
        self.beat(age=999)
        self.assertEqual(health.transition(self.now), 'monitoring_degraded')
        rows = ChangeEvent.objects.filter(kind='monitoring_degraded')
        self.assertEqual({(e.project_id, e.immediate) for e in rows}, {(self.p.id, True), (self.q.id, True)})
        for e in rows:
            self.assertEqual(e.title, 'Certificate watch degraded: The watcher stopped reporting')
        self.assertEqual({c.args[0].id for c in self.deliver.call_args_list}, {self.p.id, self.q.id})
        self.assertIsNone(health.transition(self.now))
        self.assertEqual(ChangeEvent.objects.count(), 2)
        self.beat()
        self.assertEqual(health.transition(self.now), 'monitoring_restored')
        back = ChangeEvent.objects.filter(kind='monitoring_restored')
        self.assertEqual(sorted((e.project_id, e.immediate) for e in back), sorted([(self.p.id, False), (self.q.id, False)]))

    def test_restart_storm_and_recovery_emit_once(self):
        self.beat()
        health.transition(self.now)
        out = []
        for n in (5, 5, 0):
            self.beat(restarts_10m=n)
            out.append(health.transition(self.now))
        self.assertEqual(out, ['monitoring_degraded', None, 'monitoring_restored'])

    def test_idle_to_degraded_alerts_and_off_stays_silent(self):
        self.beat(state='idle')
        health.transition(self.now)
        self.beat(age=999)
        self.assertEqual(health.transition(self.now), 'monitoring_degraded')
        with override_settings(CT_WATCH=False):
            self.assertIsNone(health.transition(self.now))
        self.beat(age=999)
        self.assertIsNone(health.transition(self.now))  # off -> degraded only stores

    def test_redis_down_fails_closed(self):
        from redis.exceptions import ConnectionError as RedisConnError
        with mock.patch('limes.ct.health.get_redis_connection', side_effect=RedisConnError('x')):
            self.assertIsNone(health.transition(self.now))
            self.assertEqual(health.evaluate(self.now)['state'], 'degraded')


@override_settings(CT_WATCH=True, CONTINUOUS_SCANS=True, CERTSPOTTER_API_KEY='')
class CardTest(Base):
    def test_card_project_scoped_and_escaped(self):
        o = Project.objects.create(name='o', slug='o', insert_date=self.now)
        self.beat(last_error_summary='<img src=x onerror=alert(1)>' * 50)
        c = health.card(self.p, self.now)
        self.assertLessEqual(len(c['watch']['last_error_summary']), 300)
        self.assertIsNone(c['api'])
        day = f'{self.now:%Y%m%d}'
        self.r.lpush(f'limes:ct:lat:{day}', -5, 4)
        self.r.lpush(f'limes:ct:age:{day}', 100)
        c = health.card(self.p, self.now)
        self.assertEqual((c['latency']['t1_p50'], c['latency']['t1_upper_p50']), (0, 100))
        for proj, secs in ((self.p, 10), (o, 9000)):
            ChangeEvent.objects.create(project=proj, kind='cert_new', title='t', detail={}, created_at=self.now - timedelta(seconds=secs),
                                       notified_at=self.now)
        self.assertEqual(health.card(self.p, self.now)['latency']['t3_p50'], 10)
        old, new = self.now - timedelta(hours=2), self.now - timedelta(days=8)
        for proj, tbs, seen, src, ok, when in (
                (self.p, '1' * 64, None, 'certspotter_api', True, old), (o, '2' * 64, None, 'certspotter_api', True, old),
                (self.p, '3' * 64, self.now, 'certspotter_api', True, old), (self.p, '4' * 64, None, 'certspotter_api', False, old),
                (self.p, '5' * 64, None, 'certspotter_api', True, new), (self.p, '6' * 64, None, 'certspotter', True, old),
                (self.p, '7' * 64, None, 'certspotter_api', True, self.now - timedelta(minutes=10))):
            CertSighting.objects.create(project=proj, tbs_sha256=tbs, source=src, watch_seen_at=seen,
                                        api_while_watch_ok=ok, first_seen_at=when)
        self.assertEqual(health.card(self.p, self.now)['watch']['api_only_7d'], 1)

    def test_api_only_counts_watch_misses(self):
        CertSighting.objects.create(project=self.p, tbs_sha256=TBS, source='certspotter_api', api_while_watch_ok=True,
                                    first_seen_at=self.now - timedelta(hours=2))
        self.assertEqual(health.card(self.p, self.now)['watch']['api_only_7d'], 1)
        CertSighting.objects.update(watch_seen_at=self.now)
        self.assertEqual(health.card(self.p, self.now)['watch']['api_only_7d'], 0)

    def test_dns_and_api_blocks_and_fixed_queries(self):
        a = Asset.objects.create(project=self.p, kind='hostname', value='a.x.com', scope_tier='owned_host',
                                 cadence_tier='crown_jewel',
                                 enrichment={'dns': {'watched_at': (self.now - timedelta(seconds=90)).isoformat()}})
        Asset.objects.create(project=self.p, kind='hostname', value='b.x.com', scope_tier='owned_host', cadence_tier='crown_jewel')
        self.beat()
        with self.assertNumQueries(3):
            c = health.card(self.p, self.now)
        self.assertEqual(c['dns'], {'watched': 1, 'oldest_age': 90})
        with override_settings(CERTSPOTTER_API_KEY='k'):
            c = health.card(self.p, self.now)
        self.assertEqual((c['api']['used_this_hour'], c['api']['budget']), (0, 7))
        self.assertEqual([x['code'] for x in c['reasons']], [])
