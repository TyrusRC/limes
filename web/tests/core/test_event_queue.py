import threading
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone
from django_redis import get_redis_connection
from redis.exceptions import ConnectionError as RedisConnectionError

from dashboard.models import Project
from limes import event_queue as eq
from startScan.models import Asset
from targetApp.models import Domain


class Base(TestCase):
    def setUp(self):
        cache.clear()
        self.r = get_redis_connection('default')
        self.wipe()
        self.addCleanup(self.wipe)
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.now = timezone.now()
        self.h = self.host('h.example.com')

    def wipe(self):
        for k in self.r.scan_iter('limes:evq*'):
            self.r.delete(k)

    def host(self, value, project=None, tier='owned_host', kind='hostname', **kw):
        return Asset.objects.create(project=project or self.p, kind=kind, value=value, scope_tier=tier,
                                    cadence_tier=kw.pop('cadence_tier', 'standard'), **kw)


class EnqueueTests(Base):
    @override_settings(EVENT_COOLDOWN=0)
    def test_double_enqueue_is_one_entry(self):
        self.assertEqual(eq.enqueue(self.h, 'manual', now=self.now), 'queued')
        self.assertEqual(eq.enqueue(self.h, 'manual', now=self.now), 'dup')
        self.assertEqual(self.r.zcard(eq.QUEUE), 1)
        got = eq.claim_due(self.now, 10)
        self.assertEqual([(a, r) for a, r, _ in got], [(self.h.id, 'manual')])
        self.assertAlmostEqual(got[0][2], self.now.timestamp(), delta=2)
        self.assertEqual(eq.claim_due(self.now, 10), [])

    @override_settings(EVENT_COOLDOWN=0)
    def test_pending_recheck_keeps_its_reason_but_may_come_earlier(self):
        eq.enqueue(self.h, 'ct_recheck_24h', delay=23 * 3600, now=self.now)
        self.assertEqual(eq.enqueue(self.h, 'manual', now=self.now), 'dup')
        (aid, reason, due), = eq.claim_due(self.now, 10)
        self.assertEqual((aid, reason), (self.h.id, 'ct_recheck_24h'))
        self.assertAlmostEqual(due, self.now.timestamp(), delta=2)
        eq.enqueue(self.h, 'manual', now=self.now)  # a plain entry is still overwritten by an earlier one
        eq.enqueue(self.h, 'exposed', now=self.now - timedelta(seconds=5))
        self.assertEqual(eq.claim_due(self.now, 10)[0][1], 'exposed')

    def test_cooldown(self):
        self.assertEqual(eq.enqueue(self.h, 'manual', now=self.now), 'queued')
        self.assertEqual(eq.enqueue(self.h, 'manual', now=self.now), 'cooled')
        self.assertEqual(eq.snapshot(self.now)['counts']['cooled'], 1)
        self.assertEqual(eq.enqueue(self.h, 'ct_recheck_1h', now=self.now), 'dup')

    @override_settings(EVENT_QUEUE_MAX=2)
    def test_overflow_counted_and_cooldown_released(self):
        hs = [self.h, self.host('b.example.com'), self.host('c.example.com')]
        self.assertEqual([eq.enqueue(a, 'manual', now=self.now) for a in hs], ['queued', 'queued', 'overflow'])
        self.assertFalse(self.r.exists(eq.cool_key(hs[2].id)))
        self.assertEqual(eq.snapshot(self.now)['counts']['overflow'], 1)

    @override_settings(EVENT_BURST=3)
    def test_burst_cap_per_project(self):
        hs = [self.host(f'h{i}.example.com') for i in range(5)]
        out = [eq.enqueue(a, 'manual', now=self.now) for a in hs]
        self.assertEqual((out.count('queued'), out.count('burst')), (3, 2))
        self.assertFalse(self.r.exists(eq.cool_key(hs[4].id)))
        o = Project.objects.create(name='o', slug='o', insert_date=timezone.now())
        self.assertEqual(eq.enqueue(self.host('x.other.com', project=o), 'manual', now=self.now), 'queued')

    def test_delayed_item_not_claimed_early(self):
        eq.enqueue(self.h, 'ct_recheck_1h', delay=3600, now=self.now)
        self.assertEqual(eq.claim_due(self.now, 10), [])
        self.assertEqual(eq.due_count(self.now), 0)
        self.assertEqual(eq.snapshot(self.now)['depth'], 1)
        later = self.now + timedelta(seconds=3601)
        self.assertEqual([a for a, _, _ in eq.claim_due(later, 10)], [self.h.id])

    @override_settings(EVENT_COOLDOWN=0)
    def test_earlier_request_moves_delayed_item_forward(self):
        eq.enqueue(self.h, 'ct_recheck_1h', delay=3600, now=self.now)
        self.assertEqual(eq.enqueue(self.h, 'ct_cert', now=self.now), 'dup')
        got = eq.claim_due(self.now, 10)
        self.assertEqual([(a, r) for a, r, _ in got], [(self.h.id, 'ct_recheck_1h')])  # moved up, reason kept

    @override_settings(EVENT_COOLDOWN=0)
    def test_later_request_keeps_earlier_entry(self):
        eq.enqueue(self.h, 'ct_cert', now=self.now)
        self.assertEqual(eq.enqueue(self.h, 'ct_recheck_1h', delay=3600, now=self.now), 'dup')
        self.assertEqual([r for _, r, _ in eq.claim_due(self.now, 10)], ['ct_cert'])

    def test_stopped_rejected_or_covered_skipped(self):
        self.assertEqual(eq.enqueue(self.host('a.example.com', cadence_tier='off'), 'manual'), 'skipped')
        self.assertEqual(eq.enqueue(self.host('b.example.com', tier='rejected'), 'manual'), 'skipped')
        self.assertEqual(eq.enqueue(self.host('c.example.com', tier='candidate'), 'manual'), 'skipped')
        root = self.host('covered.com', tier='owned_root', kind='root_domain')
        Domain.objects.create(name='covered.com', project=self.p, insert_date=timezone.now())
        self.assertEqual(eq.enqueue(root, 'manual'), 'skipped')
        for flag in ('CONTINUOUS_SCANS', 'EVENT_CHECKS'):
            with override_settings(**{flag: False}):
                self.assertEqual(eq.enqueue(self.h, 'manual'), 'off')
        self.assertEqual(list(self.r.scan_iter('limes:evq:cool*')), [])
        self.assertEqual(self.r.zcard(eq.QUEUE), 0)

    def test_redis_down_fails_soft(self):
        with mock.patch('limes.event_queue.get_redis_connection', side_effect=RedisConnectionError('boom h.example.com')), \
                self.assertLogs('limes.event_queue', 'WARNING') as logs:
            self.assertEqual(eq.enqueue(self.h, 'manual'), 'error')
            self.assertEqual(eq.claim_due(self.now, 5), [])
            self.assertEqual(eq.due_count(self.now), 0)
        text = '\n'.join(logs.output)
        self.assertIn('ConnectionError', text)
        self.assertNotIn('h.example.com', text)

    def test_unknown_reason_raises(self):
        with self.assertRaises(ValueError):
            eq.enqueue(self.h, 'nope')

    def test_percentile_integer_edge(self):
        v = list(range(1, 101))
        self.assertEqual(eq.percentile(v, 0.07), 7)  # float ceil(100 * 0.07) would give 8
        self.assertEqual(eq.percentile(v, 1.0), 100)

    def test_percentile(self):
        v = list(range(1, 101))
        self.assertEqual((eq.percentile(v, 0.5), eq.percentile(v, 0.95)), (50, 95))
        self.assertIsNone(eq.percentile([], 0.5))

    def test_negative_latency_clamped_and_counted_as_skew(self):
        eq.record_latency(-5, now=self.now)
        eq.record_latency(7, now=self.now)
        s = eq.snapshot(self.now)
        self.assertEqual(sorted(s['latency']), [0, 7])
        self.assertEqual(s['counts']['skew'], 1)

    def test_every_key_is_bounded(self):
        eq.enqueue(self.h, 'manual', now=self.now)
        eq.claim_due(self.now, 5)
        eq.record_latency(3, now=self.now)
        keys = [k.decode() for k in self.r.scan_iter('limes:evq*')]
        self.assertTrue(keys)
        for k in keys:
            if k not in (eq.QUEUE, eq.WHY):
                self.assertGreater(self.r.ttl(k), 0, k)


class RaceAndFailureTests(Base):
    def push(self, i, reason='manual', pid=None, delay=0):
        return eq._push(get_redis_connection('default'), i, pid or self.p.id, reason, self.now, delay)

    def test_claim_error_loses_nothing(self):
        self.push(1)
        self.push(2)
        real = get_redis_connection('default')
        with mock.patch('limes.event_queue.get_redis_connection') as g:
            g.return_value.register_script.return_value.side_effect = RedisConnectionError('x')
            self.assertEqual(eq.claim_due(self.now, 10), [])
        self.assertEqual(real.zcard(eq.QUEUE), 2)
        self.assertEqual(len(eq.claim_due(self.now, 10)), 2)

    def test_claim_returns_reason_and_leaves_no_orphans(self):
        self.push(1, 'ct_new')
        self.assertEqual([(a, r) for a, r, _ in eq.claim_due(self.now, 10)], [(1, 'ct_new')])
        self.assertEqual(self.r.hlen(eq.WHY), 0)

    def _threads(self, fns):
        errs = []

        def run(f):
            try:
                f()
            except Exception as e:  # noqa: BLE001
                errs.append(e)
        ts = [threading.Thread(target=run, args=(f,)) for f in fns]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(errs, [])

    def test_claim_enqueue_race_never_yields_empty_reason(self):
        got = []

        def claimer():
            for _ in range(200):
                got.extend(eq.claim_due(self.now, 50))

        def pusher():
            for _ in range(200):
                for i in range(1, 6):
                    self.push(i, 'ct_cert')
        self._threads([claimer, pusher, pusher])
        got.extend(eq.claim_due(self.now, 50))
        self.assertTrue(got)
        self.assertTrue(all(r == 'ct_cert' and at > 0 for _, r, at in got), got[:3])
        self.assertEqual(self.r.hlen(eq.WHY), 0)

    def test_two_claimers_never_share_an_item(self):
        for i in range(1, 201):
            self.push(i)
        a, b = [], []
        self._threads([lambda: [a.extend(eq.claim_due(self.now, 7)) for _ in range(40)],
                       lambda: [b.extend(eq.claim_due(self.now, 7)) for _ in range(40)]])
        ids = [x[0] for x in a + b]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(ids), 200)

    @override_settings(EVENT_QUEUE_MAX=10, EVENT_BURST=1000)
    def test_concurrent_enqueuers_never_exceed_cap(self):
        out = []
        self._threads([lambda k=k: out.extend(self.push(k * 100 + i) for i in range(30)) for k in range(6)])
        self.assertEqual(self.r.zcard(eq.QUEUE), 10)
        self.assertEqual(out.count('queued'), 10)

    def test_cooldown_released_when_redis_fails_after_connect(self):
        real = get_redis_connection('default')
        with mock.patch('limes.event_queue._push', side_effect=RedisConnectionError('x')):
            self.assertEqual(eq.enqueue(self.h, 'manual', now=self.now), 'error')
        self.assertFalse(real.exists(eq.cool_key(self.h.id)))

    @override_settings(EVENT_BURST=2, EVENT_COOLDOWN=0)
    def test_rechecks_do_not_starve_ct_new(self):
        for i in range(5):
            self.assertEqual(self.push(i, 'ct_recheck_1h', delay=3600), 'queued')
        self.assertEqual([self.push(10 + i, 'ct_new') for i in range(3)], ['queued', 'queued', 'burst'])

    @override_settings(EVENT_BURST=2, EVENT_COOLDOWN=0)
    def test_dup_and_overflow_do_not_charge_burst(self):
        self.assertEqual(self.push(1), 'queued')
        self.assertEqual([self.push(1) for _ in range(3)], ['dup'] * 3)
        self.assertEqual(self.push(2), 'queued')
        with override_settings(EVENT_QUEUE_MAX=2):
            self.assertEqual(self.push(3), 'overflow')
        self.assertEqual(self.push(3), 'burst')

    def test_delayed_item_latency_is_not_inflated(self):
        self.push(1, 'ct_recheck_1h', delay=3600)
        (_, _, at), = eq.claim_due(self.now + timedelta(seconds=3601), 5)
        self.assertAlmostEqual(self.now.timestamp() + 3600, at, delta=1)

    def test_non_finite_latency_ignored(self):
        for v in (float('nan'), float('inf')):
            eq.record_latency(v, now=self.now)
        self.assertEqual(eq.snapshot(self.now)['latency'], [])
