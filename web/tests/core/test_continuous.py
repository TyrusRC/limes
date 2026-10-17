from datetime import timedelta
from unittest import mock

from django.test import TestCase, override_settings
from django.utils import timezone

from dashboard.models import Project
from limes import continuous
from limes.definitions import FAILED_TASK, INITIATED_TASK, LIVE_SCAN, RUNNING_TASK, SUCCESS_TASK
from scanEngine.models import EngineType
from startScan.models import Asset, ScanHistory
from targetApp.models import Domain


class Base(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.engine = EngineType.objects.create(engine_name='default', yaml_configuration='{}', default_engine=True)
        for target in ('limes.continuous.initiate_scan.apply_async', 'limes.continuous.create_scan_object'):
            p = mock.patch(target)
            setattr(self, 'apply_async' if 'apply' in target else 'create', p.start())
            self.addCleanup(p.stop)
        self.create.side_effect = self.fake_create
        self.now = timezone.now()

    def fake_create(self, host_id, engine_id, initiated_by_id=None):
        # what create_scan_object writes synchronously: an INITIATED ScanHistory
        return ScanHistory.objects.create(domain_id=host_id, scan_type_id=engine_id, scan_status=INITIATED_TASK,
                                          start_scan_date=timezone.now()).id

    def root(self, value, tier='standard', scope='owned_root', domain=True):
        if domain:
            Domain.objects.create(project=self.p, name=value, insert_date=timezone.now())
        return Asset.objects.create(project=self.p, kind='root_domain', value=value, scope_tier=scope, cadence_tier=tier)

    def scanned(self, value, ago, status=SUCCESS_TASK):
        ScanHistory.objects.create(domain=Domain.objects.get(name=value), scan_type=self.engine, scan_status=status,
                                   start_scan_date=self.now - ago)

    def due(self):
        return [a.value for a in continuous.due_roots(self.now)]


class StartAsmScanTest(Base):
    def test_system_start(self):
        a = self.root('x.com')
        self.assertEqual(continuous.start_asm_scan(a), (True, 'ASM scan started for x.com'))
        kw = self.apply_async.call_args.kwargs['kwargs']
        self.assertEqual((kw['scan_type'], kw['initiated_by_id'], kw['scan_mode']), (LIVE_SCAN, None, 'asm'))


class DueRootsTest(Base):
    def test_project_filter_leaves_other_projects_out(self):
        self.root('mine.com')
        other = Project.objects.create(name='o', slug='o', insert_date=timezone.now())
        Domain.objects.create(project=other, name='theirs.com', insert_date=timezone.now())
        Asset.objects.create(project=other, kind='root_domain', value='theirs.com', scope_tier='owned_root', cadence_tier='standard')
        self.assertEqual(sorted(self.due()), ['mine.com', 'theirs.com'])
        self.assertEqual([a.value for a in continuous.due_roots(self.now, project=self.p)], ['mine.com'])

    def test_never_scanned_root_is_due(self):
        self.root('new.com')
        self.assertEqual(self.due(), ['new.com'])

    def test_each_tier_waits_its_interval(self):
        for tier, interval in (('crown_jewel', timedelta(hours=24)), ('standard', timedelta(days=7)),
                               ('inactive', timedelta(days=30))):
            self.root(f'{tier}-fresh.com', tier)
            self.scanned(f'{tier}-fresh.com', interval - timedelta(minutes=5))
            self.root(f'{tier}-old.com', tier)
            self.scanned(f'{tier}-old.com', interval + timedelta(minutes=5))
        self.assertEqual(sorted(self.due()), ['crown_jewel-old.com', 'inactive-old.com', 'standard-old.com'])

    def test_off_is_never_due(self):
        self.root('off.com', 'off')
        self.assertEqual(self.due(), [])

    def test_scan_in_progress_blocks_root(self):
        for status, value in ((INITIATED_TASK, 'queued.com'), (RUNNING_TASK, 'running.com')):
            self.root(value)
            self.scanned(value, timedelta(days=60), status=status)
        self.assertEqual(self.due(), [])

    def test_failed_scan_counts_from_its_start(self):
        self.root('recent-fail.com')
        self.scanned('recent-fail.com', timedelta(hours=1), status=FAILED_TASK)
        self.root('old-fail.com')
        self.scanned('old-fail.com', timedelta(days=8), status=FAILED_TASK)
        self.assertEqual(self.due(), ['old-fail.com'])

    def test_only_owned_roots_with_a_domain(self):
        for scope in ('candidate', 'co_brand', 'rejected', 'dependency'):
            self.root(f'{scope}.com', scope=scope)
        self.root('nodomain.com', domain=False)
        self.assertEqual(self.due(), [])

    def test_never_scanned_first_then_most_overdue(self):
        self.root('a-old.com')
        self.scanned('a-old.com', timedelta(days=20))
        self.root('b-older.com')
        self.scanned('b-older.com', timedelta(days=40))
        self.root('c-never.com')
        self.assertEqual(self.due(), ['c-never.com', 'b-older.com', 'a-old.com'])


class DispatchTest(Base):
    def test_dispatches_one_per_tick_as_system_scan(self):
        self.root('a.com')
        self.root('b.com')
        self.assertEqual(continuous.dispatch_due_scans(), {'dispatched': 1, 'skipped': 0})
        kw = self.apply_async.call_args.kwargs['kwargs']
        self.assertEqual((kw['initiated_by_id'], kw['scan_mode']), (None, 'asm'))

    def test_scan_reuses_the_row_dispatch_created(self):
        # initiate_scan creates a second ScanHistory for SCHEDULED_SCAN and orphans ours in INITIATED,
        # which then holds an in-flight slot until the reaper: the scan must reuse the row we wrote
        mock.patch.stopall()  # the real create_scan_object this time
        with mock.patch('limes.continuous.initiate_scan.apply_async') as apply_async:
            self.root('a.com')
            continuous.dispatch_due_scans()
        kw = apply_async.call_args.kwargs['kwargs']
        rows = list(ScanHistory.objects.filter(domain__name='a.com').values_list('id', flat=True))
        self.assertEqual(rows, [kw['scan_history_id']])
        self.assertEqual(kw['scan_type'], LIVE_SCAN)  # LIVE_SCAN: initiate_scan uses scan_history_id as given

    def test_concurrent_tick_does_not_dispatch(self):
        from django.db import connections
        self.root('a.com')
        other = connections['default'].copy()  # a second session, like a parallel worker
        try:
            with other.cursor() as c:
                c.execute('SELECT pg_advisory_lock(%s)', [continuous.DISPATCH_LOCK])
            self.assertEqual(continuous.dispatch_due_scans(), {'dispatched': 0, 'skipped': 0, 'reason': 'locked'})
            self.apply_async.assert_not_called()
        finally:
            # unlock explicitly: Postgres frees a closed session's locks asynchronously, so a bare close races
            with other.cursor() as c:
                c.execute('SELECT pg_advisory_unlock(%s)', [continuous.DISPATCH_LOCK])
            other.close()
        self.assertEqual(continuous.dispatch_due_scans()['dispatched'], 1)

    def test_next_tick_never_redispatches_the_same_root(self):
        self.root('a.com')
        self.root('b.com')
        continuous.dispatch_due_scans()
        continuous.dispatch_due_scans()
        domains = [c.kwargs['kwargs']['domain_id'] for c in self.apply_async.call_args_list]
        self.assertEqual(len(domains), len(set(domains)))
        self.assertEqual(continuous.dispatch_due_scans(), {'dispatched': 0, 'skipped': 0})  # 2 in flight now

    def test_waits_while_two_scans_run(self):
        self.root('busy1.com')
        self.root('busy2.com')
        self.scanned('busy1.com', timedelta(minutes=1), status=RUNNING_TASK)
        self.scanned('busy2.com', timedelta(minutes=1), status=INITIATED_TASK)
        self.root('due.com')
        self.assertEqual(continuous.dispatch_due_scans(), {'dispatched': 0, 'skipped': 0})
        self.apply_async.assert_not_called()

    def test_unstartable_root_is_skipped_and_next_tried(self):
        self.root('a-bad.com')
        self.root('b-good.com')
        with mock.patch.object(continuous, 'start_asm_scan', side_effect=[(False, 'no engine'), (True, 'ok')]) as start:
            self.assertEqual(continuous.dispatch_due_scans(), {'dispatched': 1, 'skipped': 1})
        self.assertEqual([c.args[0].value for c in start.call_args_list], ['a-bad.com', 'b-good.com'])

    @override_settings(CONTINUOUS_SCANS=False)
    def test_kill_switch(self):
        self.root('a.com')
        self.assertEqual(continuous.dispatch_due_scans(), {'dispatched': 0, 'reason': 'disabled'})
        self.apply_async.assert_not_called()

    def test_off_tier_still_allows_manual_start(self):
        a = self.root('off.com', 'off')
        self.assertEqual(continuous.start_asm_scan(a),
                         (True, 'ASM scan started for off.com'))


class AgingTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.now = timezone.now()

    def asset(self, value, state, days):
        return Asset.objects.create(project=self.p, kind='hostname', value=value, scope_tier='owned_host', state=state,
                                    last_seen=self.now - timedelta(days=days))

    def state(self, a):
        a.refresh_from_db()
        return a.state

    def test_thresholds(self):
        m29, m31 = self.asset('m29', 'missing', 29), self.asset('m31', 'missing', 31)
        s89, s91 = self.asset('s89', 'stale', 89), self.asset('s91', 'stale', 91)
        self.assertEqual(continuous.age_assets(), {'stale': 1, 'retired': 1})
        self.assertEqual([self.state(a) for a in (m29, m31, s89, s91)], ['missing', 'stale', 'stale', 'retired'])

    def test_active_never_ages(self):
        active = self.asset('a', 'active', 400)
        continuous.age_assets()
        self.assertEqual(self.state(active), 'active')

    def test_sighting_revives_stale_and_retired(self):
        for state in ('missing', 'stale', 'retired'):
            a = self.asset(state, state, 200)
            a.mark_missing_or_seen(True)
            self.assertEqual(self.state(a), 'active', state)
