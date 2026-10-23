import itertools
from datetime import timedelta
from unittest import mock

import dns.resolver
from django.conf import settings
from django.test import override_settings
from django.utils import timezone
from django_redis import get_redis_connection
from rest_framework.test import APIClient

from limes import event_queue as eq, monitor
from limes.alerts import events
from limes.alerts.issues import sync_issues
from limes.continuous import IN_PROGRESS
from startScan.models import Asset, ChangeEvent, IpAddress, ScanHistory, TrackedIssue
from scanEngine.models import EngineType
from targetApp.models import Domain
from tests.core.test_monitor import Base as MonitorBase, Get, public
from tests.core.test_safe_fetch import PUBLIC, stub

HOUR = timedelta(hours=1)


class Base(MonitorBase):
    def setUp(self):
        super().setUp()
        self.r = get_redis_connection('default')
        self.wipe()
        self.addCleanup(self.wipe)

    def wipe(self):
        for k in self.r.scan_iter('limes:evq*'):
            self.r.delete(k)
        self.r.delete('limes:tick:monitor_assets', monitor.FULL_TICK_KEY)

    def host(self, value, **kw):
        kw.setdefault('last_resolved_at', self.now - HOUR)
        return self.asset('hostname', value, cadence_tier=kw.pop('cadence_tier', 'standard'), **kw)


class DrainTest(Base):
    def test_queued_asset_checked_first_and_latency_recorded(self):
        h = self.host('h.x.com')
        self.assertEqual(eq.enqueue(h, 'manual'), 'queued')
        with mock.patch.object(monitor, 'check_asset', return_value={'status': 'ok', 'project_id': self.p.id}) as ck:
            out = monitor.monitor_assets()
        self.assertEqual(out, {'checked': 1})
        self.assertEqual((ck.call_args.args[0].pk, ck.call_args.kwargs['reason']), (h.pk, 'manual'))
        snap = eq.snapshot(timezone.now())
        self.assertEqual(snap['counts']['checked'], 1)
        self.assertEqual(len(snap['latency']), 1)

    def test_cadence_still_gets_half_the_tick(self):
        hosts = [self.host(f'q{i}.x.com') for i in range(12)]
        for h in hosts:
            eq.enqueue(h, 'manual')
        scores = {h.id: self.r.zscore(eq.QUEUE, str(h.id)) for h in hosts}
        due = [self.host(f'd{i}.x.com', last_resolved_at=None) for i in range(5)]
        clock = itertools.count(0, 1)
        seen = []

        def fake_check(asset, **kw):
            seen.append((asset.value, kw.get('reason')))
            for _ in range(10):
                next(clock)
            return {'status': 'ok', 'project_id': self.p.id}
        with mock.patch.object(monitor, 'check_asset', side_effect=fake_check), \
                mock.patch.object(monitor.time, 'monotonic', side_effect=lambda: next(clock)):
            monitor.monitor_assets()
        events_done = [s for s in seen if s[1] == 'manual']
        self.assertEqual(len(events_done), 3)
        self.assertGreaterEqual(len([s for s in seen if s[1] is None]), 2)
        left = {int(m): s for m, s in self.r.zrange(eq.QUEUE, 0, -1, withscores=True)}
        self.assertEqual(len(left), 9)
        for k, s in left.items():
            self.assertEqual(s, scores[k])

    def test_failed_check_is_counted_as_error_not_skipped(self):
        eq.enqueue(self.host('h.x.com'), 'manual')
        with mock.patch.object(monitor, 'check_asset', side_effect=RuntimeError('boom')):
            monitor.monitor_assets()
        counts = eq.snapshot(timezone.now())['counts']
        self.assertEqual((counts.get('error'), counts.get('skipped'), len(eq.snapshot(timezone.now())['latency'])),
                         (1, None, 0))

    def test_events_only_idle_and_locked(self):
        h = self.host('h.x.com')
        with mock.patch.object(monitor, 'tick_lock') as spy:
            self.assertEqual(monitor.monitor_assets(events_only=True), {'checked': 0, 'reason': 'idle'})
        spy.assert_not_called()
        eq.enqueue(h, 'manual')
        lock = self.r.lock('limes:tick:monitor_assets', timeout=30, blocking=False)
        self.assertTrue(lock.acquire())
        self.addCleanup(lambda: lock.owned() and lock.release())
        self.assertEqual(monitor.monitor_assets(events_only=True), {'checked': 0, 'reason': 'locked'})
        self.assertEqual(self.r.zcard(eq.QUEUE), 1)

    def test_events_only_skips_cadence(self):
        self.host('d.x.com', last_resolved_at=None)
        h = self.host('h.x.com')
        eq.enqueue(h, 'manual')
        with mock.patch.object(monitor, 'check_asset', return_value={'status': 'ok', 'project_id': self.p.id}) as ck, \
                mock.patch.object(monitor, 'dns_watch') as dw:
            self.assertEqual(monitor.monitor_assets(events_only=True), {'checked': 1})
        self.assertEqual(ck.call_count, 1)
        dw.assert_not_called()

    def test_covered_by_scan_in_progress(self):
        root = self.asset('root_domain', 'x.com', tier='owned_root')
        h = self.host('h.x.com', parent=root)
        d = Domain.objects.create(name='x.com', project=self.p, insert_date=timezone.now())
        ScanHistory.objects.create(domain=d, scan_type=EngineType.objects.create(engine_name='e', yaml_configuration='{}'),
                                   scan_status=IN_PROGRESS[0], start_scan_date=timezone.now())
        eq.enqueue(h, 'manual')
        with mock.patch.object(monitor, 'check_asset') as ck:
            monitor.monitor_assets()
        ck.assert_not_called()
        snap = eq.snapshot(timezone.now())
        self.assertEqual(snap['counts']['covered'], 1)
        self.assertEqual(snap['depth'], 0)

    def test_stopped_mid_queue_untouched(self):
        h = self.host('h.x.com')
        eq.enqueue(h, 'manual')
        Asset.objects.filter(pk=h.pk).update(cadence_tier='off')
        get = Get()
        with mock.patch.object(monitor.collect, '_resolve', stub(public('h.x.com'))), \
                mock.patch.object(monitor.http, 'get_json', get):
            monitor.monitor_assets()
        self.assertEqual((self.calls, get.calls), ([], []))
        self.assertEqual(eq.snapshot(timezone.now())['counts']['skipped'], 1)

    def test_lock_outage_fails_closed(self):
        from redis.exceptions import ConnectionError as RedisConnectionError
        self.host('d.x.com', last_resolved_at=None)
        with mock.patch('limes.continuous.get_redis_connection', side_effect=RedisConnectionError('x')), \
                mock.patch.object(monitor, 'check_asset') as ck:
            self.assertEqual(monitor.monitor_assets(), {'checked': 0, 'reason': 'locked'})
        ck.assert_not_called()

    def test_queue_outage_degrades_to_cadence(self):
        self.host('d.x.com', last_resolved_at=None)
        from redis.exceptions import ConnectionError as RedisConnectionError
        with mock.patch.object(eq, 'get_redis_connection', side_effect=RedisConnectionError('x')), \
                mock.patch.object(monitor, 'check_asset', return_value={'status': 'ok', 'project_id': self.p.id}) as ck:
            self.assertEqual(monitor.monitor_assets(), {'checked': 1})
        self.assertEqual(ck.call_args.kwargs.get('reason'), None)


class FullTickFairnessTest(Base):
    def at(self, ts):
        return mock.patch.object(monitor.timezone, 'now', return_value=timezone.datetime.fromtimestamp(ts, timezone.utc))

    def test_drain_yields_when_the_full_tick_is_due_soon(self):
        h = self.host('h.x.com')
        eq.enqueue(h, 'manual')
        t0 = 1_900_000_000.0
        ok = {'status': 'ok', 'project_id': self.p.id}
        with mock.patch.object(monitor, 'check_asset', return_value=ok) as ck:
            with self.at(t0):
                self.assertEqual(monitor.monitor_assets(events_only=True), {'checked': 1})  # no full tick seen yet
            eq.enqueue(self.host('i.x.com'), 'manual')
            monitor.stamp_full_tick(t0)
            with self.at(t0 + 40):
                self.assertEqual(monitor.monitor_assets(events_only=True), {'checked': 0, 'reason': 'yield'})
            with self.at(t0 + 10):
                self.assertEqual(monitor.monitor_assets(events_only=True), {'checked': 1})
        self.assertEqual(ck.call_count, 2)

    def test_full_tick_runs_every_minute_under_a_permanent_queue(self):
        # two contenders: a drain every 15 s holds the lock for the event share once it runs, the full tick fires on
        # the minute and is locked out while a drain holds the lock
        held_until, full, base = 0.0, 0, 1_900_000_000.0
        for step in range(40):
            t = base + step * 15
            if step % 4 == 0:
                if t >= held_until:
                    full += 1
                    monitor.stamp_full_tick(t)
                    held_until = t + 5  # a quiet full tick
            elif not monitor.drain_yields(t) and t >= held_until:
                held_until = t + monitor.TICK_BUDGET.total_seconds() * settings.EVENT_SHARE
        self.assertEqual(full, 10)


class CtRecheckTest(Base):
    def claim_and_check(self, answers, now, get=None):
        got = eq.claim_due(now, 10)
        self.assertEqual(len(got), 1)
        a = Asset.objects.get(pk=got[0][0])
        self.check(a, answers, get=get, now=now, reason=got[0][1])
        return got[0][1]

    def test_precert_rechecks_twice_then_stops(self):
        h = self.host('n.x.com', last_resolved_at=None)
        t0 = self.now
        monitor.mark_pending(h, 'ct_new')  # what enqueue does before the item is queued
        self.check(h, {}, now=t0, reason='ct_new')
        ev = ChangeEvent.objects.get(kind='asset_new')
        self.assertEqual((ev.immediate, ev.detail['ports']), (False, []))
        score = self.r.zscore(eq.QUEUE, str(h.id))
        self.assertAlmostEqual(score, t0.timestamp() + 3600, delta=5)
        t1 = t0 + timedelta(seconds=3601)
        self.assertEqual(self.claim_and_check({}, t1), 'ct_recheck_1h')
        score = self.r.zscore(eq.QUEUE, str(h.id))
        self.assertAlmostEqual(score, t1.timestamp() + 23 * 3600, delta=5)
        t2 = t1 + timedelta(hours=23, seconds=1)
        self.assertEqual(self.claim_and_check({}, t2), 'ct_recheck_24h')
        self.assertEqual(self.r.zcard(eq.QUEUE), 0)
        self.assertEqual(ChangeEvent.objects.filter(kind='asset_new').count(), 1)

    def test_pending_ct_intent_survives_a_lost_item(self):
        h = self.host('n.x.com', last_resolved_at=None)
        eq.enqueue(h, 'ct_new')
        eq.claim_due(self.now + timedelta(seconds=5), 10)  # claimed, then the check never ran (covered drop, crash, soft limit)
        self.assertEqual(self.reload(h).enrichment['monitor']['pending'], 'ct_new')
        self.check(h, {}, now=self.now, reason='manual')  # any later check honours it
        self.assertEqual(ChangeEvent.objects.filter(kind='asset_new', asset=h).count(), 1)
        self.assertNotIn('pending', self.reload(h).enrichment['monitor'])
        self.assertEqual(eq.claim_due(self.now + timedelta(hours=2), 10)[0][1], 'ct_recheck_1h')
        self.check(h, {}, now=self.now)  # nothing pending now: no second event
        self.assertEqual(ChangeEvent.objects.filter(kind='asset_new', asset=h).count(), 1)

    @override_settings(EVENT_QUEUE_MAX=1)
    def test_pending_ct_intent_survives_a_refused_enqueue(self):
        eq.enqueue(self.host('a.x.com'), 'manual')
        h = self.host('n.x.com', last_resolved_at=None)
        self.assertEqual(eq.enqueue(h, 'ct_new'), 'overflow')
        self.check(h, public('n.x.com'), now=self.now)  # the cadence check picks it up
        self.assertEqual(ChangeEvent.objects.filter(kind='asset_new', asset=h).count(), 1)

    def test_covered_drop_keeps_pending(self):
        root = self.asset('root_domain', 'x.com', tier='owned_root')
        h = self.host('n.x.com', parent=root)
        d = Domain.objects.create(name='x.com', project=self.p, insert_date=timezone.now())
        ScanHistory.objects.create(domain=d, scan_type=EngineType.objects.create(engine_name='e', yaml_configuration='{}'),
                                   scan_status=IN_PROGRESS[0], start_scan_date=timezone.now())
        eq.enqueue(h, 'ct_new')
        monitor.monitor_assets()
        self.assertEqual(self.reload(h).enrichment['monitor']['pending'], 'ct_new')

    def test_cadence_pass_and_queued_item_record_one_asset_new(self):
        hosts = [self.host(f'n{i}.x.com', last_resolved_at=None) for i in range(5)]
        for h in hosts:
            eq.enqueue(h, 'ct_new')
        for h in hosts:
            self.check(h, public(h.value), now=self.now)  # the cadence pass gets there first
        for aid, why, _ in eq.claim_due(self.now + timedelta(seconds=5), 100):
            self.check(Asset.objects.get(pk=aid), public(Asset.objects.get(pk=aid).value), now=self.now, reason=why)
        self.assertEqual(ChangeEvent.objects.filter(kind='asset_new').count(), 5)

    def test_resolving_recheck_queues_no_more(self):
        h = self.host('n.x.com', last_resolved_at=None)
        monitor.mark_pending(h, 'ct_new')  # what enqueue does before the item is queued
        self.check(h, {}, now=self.now, reason='ct_new')
        t1 = self.now + timedelta(seconds=3601)
        self.claim_and_check(public('n.x.com'), t1)
        self.assertEqual(self.r.zcard(eq.QUEUE), 0)

    def test_ct_new_with_exposed_service_is_immediate(self):
        self.asset('ip', PUBLIC)
        h = self.host('n.x.com', last_resolved_at=None)
        monitor.mark_pending(h, 'ct_new')  # what enqueue does before the item is queued
        self.check(h, public('n.x.com'), get=Get({PUBLIC: {'ports': [3389]}}), reason='ct_new')
        ev = ChangeEvent.objects.get(kind='asset_new', asset=h)
        self.assertTrue(ev.immediate)
        self.assertEqual(self.reload(h).enrichment['monitor']['enqueued_reason'], 'ct_new')


class TriggerTest(Base):
    def test_record_asset_new_enqueues(self):
        h = self.host('h.x.com')
        with self.captureOnCommitCallbacks(execute=True):
            events.record_asset_new(self.p, h, enqueue=False)
        self.assertEqual(self.r.zcard(eq.QUEUE), 0)
        with self.captureOnCommitCallbacks(execute=True):
            events.record_asset_new(self.p, h)
        self.assertEqual(self.r.zcard(eq.QUEUE), 1)

    def api(self, user=None):
        from django.contrib.auth.models import User
        from django.contrib.auth.signals import user_logged_in
        from dashboard.views import on_user_logged_in
        from rolepermissions.roles import assign_role
        u = User.objects.create_user('adm', password='p')
        assign_role(u, 'sys_admin')
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        c = APIClient()
        c.force_login(u)
        return c

    def test_add_and_confirm_queue_manual(self):
        c = self.api()
        with self.captureOnCommitCallbacks(execute=True), mock.patch('dashboard.stats.invalidate'):
            c.post('/api/add/assets/', {'project': 'p', 'text': 'a.x.com\n9.9.9.9', 'tier': 'owned_host'}, format='json')
        ids = {Asset.objects.get(project=self.p, value=v).id for v in ('a.x.com', '9.9.9.9')}
        self.assertEqual({int(m) for m in self.r.zrange(eq.QUEUE, 0, -1)}, ids)
        cand = self.asset('hostname', 'c.x.com', tier='candidate')
        with self.captureOnCommitCallbacks(execute=True), mock.patch('dashboard.stats.invalidate'):
            c.post('/api/action/asset/confirm/', {'project': 'p', 'asset_id': cand.id, 'tier': 'owned_host'}, format='json')
        self.assertIsNotNone(self.r.zscore(eq.QUEUE, str(cand.id)))

    def test_exposed_issue_queues_hosts_of_the_ip(self):
        ip = self.asset('ip', PUBLIC)
        link = IpAddress.objects.create(address=PUBLIC)
        hosts = []
        for i in range(25):
            h = self.host(f'h{i}.x.com')
            h.ip_addresses.add(link)
            hosts.append(h)
        Asset.objects.filter(pk=hosts[0].pk).update(state='retired')
        with mock.patch('limes.scoring.current_issues', return_value=({}, {ip.id})):
            sync_issues(self.p)  # first sync: silent baseline, marks the ip bucket synced
        with mock.patch('limes.scoring.current_issues',
                        return_value=({ip.id: {'net.exposed_rdp': 4}}, {ip.id})), \
                self.captureOnCommitCallbacks(execute=True):
            sync_issues(self.p)
        self.assertEqual(TrackedIssue.objects.filter(key='net.exposed_rdp').count(), 1)
        queued = [int(m) for m in self.r.zrange(eq.QUEUE, 0, -1)]
        self.assertEqual(len(queued), 20)
        self.assertTrue(set(queued) <= {h.id for h in hosts[1:]})  # a retired host is not queued
        self.assertEqual(self.r.hget(eq.WHY, str(queued[0])).decode().split('|')[0], 'exposed')


class DnsWatchTest(Base):
    def cj(self, value, age=16, **kw):
        stamp = (self.now - timedelta(minutes=age)).isoformat()
        return self.host(value, cadence_tier='crown_jewel',
                         enrichment={'dns': {'a': ['1.2.3.4'], 'aaaa': [], 'cname': [], 'watched_at': stamp}}, **kw)

    def watch(self, answers, **kw):
        resolve = stub(answers)
        n = monitor.dns_watch(self.now, 1e18, resolve=resolve, **kw)
        return n, resolve.calls

    def test_dns_watch_crown_jewels_only(self):
        h = self.cj('h.x.com')
        std = self.host('s.x.com')
        n, calls = self.watch({('h.x.com', 'A'): ['5.6.7.8'], ('h.x.com', 'AAAA'): [], ('h.x.com', 'CNAME'): dns.resolver.NoAnswer})
        self.assertEqual((n, calls), (1, [('h.x.com', 'A'), ('h.x.com', 'AAAA'), ('h.x.com', 'CNAME')]))
        self.assertEqual(self.calls, [])
        self.assertEqual(ChangeEvent.objects.filter(kind='dns_changed', asset=h).count(), 1)
        self.assertEqual(self.r.hget(eq.WHY, str(h.id)).decode().split('|')[0], 'dns_change')
        self.assertNotIn('dns', self.reload(std).enrichment or {})
        # just watched: not due again
        self.assertEqual(self.watch({})[0], 0)

    def test_error_lookup_skips_asset(self):
        h = self.cj('h.x.com')
        n, _ = self.watch({('h.x.com', 'A'): dns.resolver.NoNameservers})
        self.assertEqual(n, 0)
        self.assertFalse(ChangeEvent.objects.exists())
        self.assertGreater(self.reload(h).enrichment['dns']['watched_at'], (self.now - timedelta(minutes=1)).isoformat())
        self.assertEqual(self.watch({('h.x.com', 'A'): dns.resolver.NoNameservers})[0], 0)  # stamped: not retried

    @override_settings(DNS_WATCH_PER_TICK=1)
    def test_per_tick_oldest_first(self):
        old, new = self.cj('o.x.com', age=60), self.cj('n.x.com', age=20)
        n, calls = self.watch({})
        self.assertEqual((n, {c[0] for c in calls}), (1, {'o.x.com'}))

    @override_settings(DNS_WATCH_INTERVAL=0)
    def test_off(self):
        self.cj('h.x.com')
        self.assertEqual(self.watch({}), (0, []))
