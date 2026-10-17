import functools
import itertools
from datetime import timedelta
from unittest import mock

import dns.resolver
from django.conf import settings
from django.core.cache import cache
from django.db import connections
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from dashboard.models import Project
from limes import celery_routing, monitor
from startScan.models import Asset, ChangeEvent, RiskCheck, TrackedIssue
from tests.core.test_safe_fetch import PUBLIC, stub

DAY = timedelta(days=1)


class Get:
    """get_json stand-in for InternetDB: {ip: body}; missing = 404; status forces a provider failure."""
    def __init__(self, idb=None, status=None):
        self.idb, self.status, self.calls = idb or {}, status, []

    def __call__(self, url, *, provider):
        self.calls.append((provider, url))
        if self.status is not None:
            return self.status, None
        ip = url.rsplit('/', 1)[1]
        if ip in self.idb:
            return 200, {'ip': ip, **self.idb[ip]}
        return 404, {'detail': 'No information available'}


def observers(calls, expired=False):
    def http(host, ident):
        calls.append(('http', host))
        return {'host': host, 'https': {'status': 200, 'url': f'https://{host}/', 'cookies': [],
                                        'headers': {'strict-transport-security': 'max-age=1'}},
                'http': {'status': 301, 'location': f'https://{host}/'}}

    def tls(host):
        calls.append(('tls', host))
        if expired:
            return {'cert': {'not_after': None, 'expired': True, 'hostname_ok': True, 'trusted': True},
                    'legacy': {'TLSv1': False, 'TLSv1_1': False}}
        return {'cert': {'not_after': timezone.now() + 90 * DAY, 'expired': False, 'hostname_ok': True, 'trusted': True},
                'legacy': {'TLSv1': False, 'TLSv1_1': False}}
    return {'http': http, 'tls': tls}


def public(name, extra=None):
    return {(name, 'A'): [PUBLIC], (name, 'AAAA'): [], (name, 'CNAME'): dns.resolver.NoAnswer, **(extra or {})}


class Base(TestCase):
    def setUp(self):
        cache.clear()
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.now = timezone.now()
        self.calls = []

    def asset(self, kind, value, tier='owned_host', **kw):
        return Asset.objects.create(project=self.p, kind=kind, value=value, scope_tier=tier, **kw)

    def check(self, a, answers=None, get=None, now=None, **kw):
        return monitor.check_asset(a, now=now or self.now, resolve=stub(answers or {}), get=get or Get(),
                                   observers=kw.pop('obs', observers(self.calls)), **kw)

    def reload(self, a):
        a.refresh_from_db()
        return a


class CheckTest(Base):
    def test_refused_host_never_contacted(self):
        h = self.asset('hostname', 'a.other.com')
        self.check(h, {('a.other.com', 'A'): ['10.0.0.1'], ('a.other.com', 'AAAA'): []})
        self.assertEqual(self.calls, [])
        h = self.reload(h)
        self.assertEqual(h.enrichment['monitor']['status'], 'refused')
        self.assertIn('10.0.0.1', h.enrichment['monitor']['reason'])
        self.assertEqual(RiskCheck.objects.count(), 0)
        self.assertEqual(h.last_resolved_at, self.now)
        mixed = self.asset('hostname', 'b.other.com')
        self.check(mixed, {('b.other.com', 'A'): [PUBLIC, '10.0.0.1'], ('b.other.com', 'AAAA'): []})
        self.assertEqual((self.calls, self.reload(mixed).enrichment['monitor']['status']), ([], 'refused'))
        self.assertEqual(RiskCheck.objects.count(), 0)

    def test_monitor_records_lifecycle_and_issues(self):
        from limes import scoring
        gone = self.asset('hostname', 'gone.other.com')
        for i in range(3):
            self.check(gone, {}, now=self.now + i * 31 * DAY)
            self.assertEqual(self.reload(gone).enrichment['monitor']['status'], 'unresolved')
        self.assertEqual(self.reload(gone).state, 'missing')
        self.check(gone, public('gone.other.com'))
        self.assertEqual(self.reload(gone).state, 'active')  # a sighting revives it
        h = self.asset('hostname', 'web.other.com')
        real = monitor.check_asset
        with mock.patch.object(monitor, 'check_asset', functools.partial(
                real, resolve=stub(public('web.other.com')), get=Get(), observers=observers(self.calls, expired=True))), \
                mock.patch('limes.monitor.deliver_immediate') as deliver:
            out = monitor.monitor_assets()
        self.assertEqual(out['checked'], 1)  # gone was checked moments ago: not due
        deliver.assert_called_once()
        self.assertTrue(RiskCheck.objects.filter(asset=h, check_id='tls.cert_expired', status='fail').exists())
        self.assertTrue(TrackedIssue.objects.filter(asset=h, key='tls.cert_expired').exists())
        self.assertGreaterEqual(scoring.project_score(self.p)['asset_count'], 1)
        self.assertIn(h.id, scoring.assessed_assets(self.p))

    def test_ip_lifecycle(self):
        ip = self.asset('ip', PUBLIC)
        ptr = '34.216.184.93.in-addr.arpa.'
        self.check(ip, {}, get=Get(status=503))  # provider down: no evidence either way
        self.assertEqual(self.reload(ip).missed_count, 0)
        with mock.patch('limes.monitor.ratelimit.take_daily', return_value=False):
            self.check(ip, {}, get=Get())  # budget spent: no change, nothing fetched
        self.assertEqual(self.reload(ip).missed_count, 0)
        self.assertEqual(self.reload(ip).last_resolved_at, self.now)
        self.check(ip, {}, get=Get())  # no InternetDB data, no PTR: a miss
        self.assertEqual(self.reload(ip).missed_count, 1)
        self.check(ip, {(ptr, 'PTR'): ['host.other.com.']}, get=Get(), now=self.now + 2 * DAY)
        self.assertEqual(self.reload(ip).missed_count, 0)
        self.assertEqual(self.reload(ip).risk_checks.filter(check_id__startswith='net.').count(), 14)
        self.assertEqual(self.calls, [])  # an IP gets only the database-backed network checks

    def test_new_ip_from_resolution_emits_asset_new(self):
        root = self.asset('root_domain', 'x.com', tier='owned_root')
        self.asset('cidr', '93.184.216.0/24')
        h = self.asset('hostname', 'a.x.com', parent=root)
        answers = {('a.x.com', 'A'): [PUBLIC, '8.8.8.8'], ('a.x.com', 'AAAA'): [], ('a.x.com', 'CNAME'): dns.resolver.NoAnswer}
        get = Get({PUBLIC: {'ports': [3389], 'hostnames': ['www.x.com', 'cdn.other.net']}})
        self.check(h, answers, get=get)
        new = list(ChangeEvent.objects.filter(kind='asset_new').values_list('title', flat=True))
        self.assertEqual(sorted(new), [f'New hostname www.x.com', f'New ip {PUBLIC} exposes rdp'])
        self.assertEqual(Asset.objects.get(value='8.8.8.8').scope_tier, 'dependency')
        self.assertEqual(Asset.objects.get(value='other.net').scope_tier, 'candidate')
        self.assertEqual([p for p, _ in get.calls], ['internetdb'])  # the dependency IP is never looked up
        self.check(h, answers, get=get, now=self.now + 2 * DAY)
        self.assertEqual(ChangeEvent.objects.filter(kind='asset_new').count(), 2)  # nothing new the second time
        self.assertTrue(self.reload(h).enrichment['monitor']['active'])  # open port: active

    def test_root_without_scan_target_is_monitored(self):
        from targetApp.models import Domain
        other = Project.objects.create(name='q', slug='q', insert_date=timezone.now())
        Domain.objects.create(name='shared.com', project=other, insert_date=timezone.now())
        Domain.objects.create(name='scanned.com', project=self.p, insert_date=timezone.now())
        own = self.asset('root_domain', 'own.com')
        shared = self.asset('root_domain', 'shared.com', tier='owned_root')
        scanned = self.asset('root_domain', 'scanned.com', tier='owned_root')
        self.assertEqual(set(monitor.monitored(self.p)), {own, shared})
        self.assertNotIn(scanned, monitor.monitored())
        for root in (own, shared):
            name = root.value
            self.check(root, public(name, {(name, 'MX'): ['10 mx.' + name + '.'], (name, 'TXT'): ['v=spf1 -all']}))
            ids = set(root.risk_checks.values_list('check_id', flat=True))
            self.assertTrue({'email.spf_missing', 'dns.caa_missing', 'web.hsts_missing', 'tls.cert_expired'} <= ids, ids)
            self.assertTrue(self.reload(root).enrichment['monitor']['active'])  # MX: active

    def test_tls_handshake_alone_counts_as_active(self):
        h = self.asset('hostname', 'tls.other.com')
        obs = observers(self.calls, expired=True)
        obs['http'] = lambda host, ident: {'host': host, 'https': 'error', 'http': None}  # bad cert: requests errors
        self.check(h, public('tls.other.com'), obs=obs)
        self.assertTrue(self.reload(h).enrichment['monitor']['active'])
        quiet = self.asset('hostname', 'quiet.other.com')
        obs = {'http': lambda host, ident: {'host': host, 'https': None, 'http': None},
               'tls': lambda host: {'cert': None, 'legacy': {}}}
        self.check(quiet, public('quiet.other.com'), obs=obs)
        self.assertFalse(self.reload(quiet).enrichment['monitor']['active'])

    def test_stopped_or_rejected_untouched(self):
        h = self.asset('hostname', 'a.other.com')
        rejected = self.asset('hostname', 'b.other.com', tier='rejected')
        cand = self.asset('ip', PUBLIC, tier='candidate')
        due = monitor.due_assets(self.now)
        self.assertEqual(due, [h])
        Asset.objects.filter(pk=h.pk).update(cadence_tier='off')  # stopped after it was picked
        r = stub(public('a.other.com'))
        for a in (due[0], rejected, cand):
            out = monitor.check_asset(a, now=self.now, resolve=r, get=Get(), observers=observers(self.calls))
            self.assertEqual(out['status'], 'skipped')
            self.assertIsNone(self.reload(a).last_resolved_at)
        self.assertEqual((r.calls, self.calls), ([], []))


class DueTest(Base):
    def test_activity_rule_and_explicit_cadence(self):
        busy = self.asset('ip', PUBLIC)
        quiet = self.asset('ip', '93.184.216.35')
        self.check(busy, {}, get=Get({PUBLIC: {'ports': [443], 'hostnames': []}}))
        self.check(quiet, {}, get=Get())
        self.assertTrue(self.reload(busy).enrichment['monitor']['active'])
        self.assertFalse(self.reload(quiet).enrichment['monitor']['active'])
        self.assertEqual(monitor.effective_interval(self.reload(busy)), monitor.ACTIVE_INTERVAL)
        self.assertEqual(monitor.effective_interval(self.reload(quiet)), monitor.INACTIVE_INTERVAL)
        self.assertEqual(monitor.due_assets(self.now + 23 * timedelta(hours=1)), [])
        self.assertEqual(monitor.due_assets(self.now + 25 * timedelta(hours=1)), [busy])
        self.assertEqual(monitor.due_assets(self.now + 29 * DAY), [busy])
        self.assertEqual(monitor.due_assets(self.now + 31 * DAY), [busy, quiet])  # oldest first: same stamp, by id
        explicit = self.reload(quiet)
        explicit.cadence_tier, explicit.enrichment = 'standard', {**explicit.enrichment, 'cadence_explicit': True}
        explicit.save()
        self.assertEqual(monitor.effective_interval(explicit), timedelta(days=7))
        self.assertIn(explicit, monitor.due_assets(self.now + 8 * DAY))
        Asset.objects.filter(pk=busy.pk).update(cadence_tier='off')
        self.assertIsNone(monitor.effective_interval(self.reload(busy)))
        self.assertNotIn(busy, monitor.due_assets(self.now + 365 * DAY))
        never = self.asset('hostname', 'new.other.com')
        self.assertEqual(monitor.due_assets(self.now + 31 * DAY)[0], never)  # never checked goes first

    def test_covered_by_root_scan_not_due(self):
        from limes.definitions import RUNNING_TASK
        from scanEngine.models import EngineType
        from startScan.models import ScanHistory
        from targetApp.models import Domain
        root = self.asset('root_domain', 'x.com', tier='owned_root')
        domain = Domain.objects.create(name='x.com', project=self.p, insert_date=timezone.now())
        recent = self.asset('hostname', 'a.x.com', parent=root, last_resolved_at=self.now - timedelta(hours=1))
        self.asset('hostname', 'b.x.com', parent=root)
        outside = self.asset('hostname', 'c.other.com')
        self.assertNotIn(recent, monitor.due_assets(self.now))
        ScanHistory.objects.create(domain=domain, scan_type=EngineType.objects.create(engine_name='e', yaml_configuration='{}'),
                                   scan_status=RUNNING_TASK, start_scan_date=self.now)
        self.assertEqual(monitor.due_assets(self.now), [outside])  # b.x.com waits for the scan in progress

    def test_limit(self):
        for i in range(3):
            self.asset('hostname', f'h{i}.other.com')
        self.assertEqual(len(monitor.due_assets(self.now, limit=2)), 2)


class TickTest(Base):
    def test_concurrent_tick_is_locked(self):
        self.asset('hostname', 'a.other.com')
        other = connections['default'].copy()  # a second session, like a parallel worker
        try:
            with other.cursor() as c:
                c.execute('SELECT pg_advisory_lock(%s)', [monitor.MONITOR_LOCK])
            with mock.patch.object(monitor, 'check_asset') as check:
                self.assertEqual(monitor.monitor_assets(), {'checked': 0, 'reason': 'locked'})
            check.assert_not_called()
        finally:
            with other.cursor() as c:
                c.execute('SELECT pg_advisory_unlock(%s)', [monitor.MONITOR_LOCK])
            other.close()
        with override_settings(CONTINUOUS_SCANS=False), mock.patch.object(monitor, 'check_asset') as check:
            self.assertEqual(monitor.monitor_assets(), {'checked': 0, 'reason': 'disabled'})
        check.assert_not_called()

    def test_tick_budget_stops_between_assets(self):
        for i in range(3):
            self.asset('hostname', f'h{i}.other.com')
        ticks = itertools.chain([0, 0], itertools.repeat(100))
        with mock.patch.object(monitor, 'check_asset', return_value={'status': 'ok'}) as check, \
                mock.patch('limes.monitor.time.monotonic', lambda: next(ticks)), \
                mock.patch('limes.monitor.deliver_immediate'):
            out = monitor.monitor_assets()
        self.assertEqual((out['checked'], check.call_count), (1, 1))


class BeatTest(SimpleTestCase):
    def test_beat_and_routing(self):
        entry = settings.CELERY_BEAT_SCHEDULE['monitor-assets']
        self.assertEqual((entry['task'], entry['schedule'], entry['options']), ('monitor_assets', 60.0, {'expires': 55}))
        self.assertEqual(celery_routing.TASK_PLAN['monitor_assets'], (celery_routing.IO, 15 * celery_routing.MIN))
        self.assertIn('limes.monitor', settings.CELERY_IMPORTS)
        self.assertEqual((monitor.MAX_PER_TICK, monitor.TICK_BUDGET, monitor.MONITOR_LOCK),
                         (20, timedelta(seconds=50), 0x4C494D47))
