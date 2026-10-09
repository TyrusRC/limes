import tempfile
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.celery import app as celery_app
from limes.celery_custom_task import LimesTask
from limes.definitions import FAILED_TASK, SUCCESS_TASK
from limes.tasks import control
from limes.tasks.inventory import upsert_root_asset
from startScan.asset_models import ScanJob, ScanRun
from scanEngine.models import EngineType
from startScan.models import ScanActivity, ScanHistory
from targetApp.models import Domain


class ScanRunBookkeepingTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.domain = Domain.objects.create(name='example.com', project=self.p, insert_date=timezone.now())
        eng = EngineType.objects.create(engine_name='e', yaml_configuration='')
        self.scan = ScanHistory.objects.create(
            scan_type=eng, domain=self.domain, start_scan_date=timezone.now(), results_dir=tempfile.mkdtemp())

    def test_start_scan_run_sets_ctx(self):
        ctx = {}
        run = control.start_scan_run(self.domain, self.scan, 'full', ctx)
        self.assertEqual(ctx['scan_run_id'], run.id)
        self.assertEqual(run.project, self.p)
        self.assertEqual(run.root_asset.value, 'example.com')
        self.assertEqual(run.mode, 'full')

    def test_no_project_skips(self):
        self.domain.project = None
        ctx = {}
        self.assertIsNone(control.start_scan_run(self.domain, self.scan, 'full', ctx))
        self.assertNotIn('scan_run_id', ctx)

    def _run_stage(self, name, ctx, fail=False):
        class T(LimesTask):
            def run(self, *a, **kw):
                if fail:
                    raise ValueError('boom')
                return 'ok'
        T.name = name
        task = T()
        task.bind(celery_app)
        with mock.patch.object(LimesTask, 'notify'):
            return task(ctx=ctx)

    def test_stage_creates_and_finishes_scan_job(self):
        ctx = {'scan_history_id': self.scan.id, 'results_dir': self.scan.results_dir}
        run = control.start_scan_run(self.domain, self.scan, 'full', ctx)
        self._run_stage('subdomain_discovery', ctx)
        job = ScanJob.objects.get(run=run)
        self.assertEqual(job.stage, 'discovery')
        self.assertEqual(job.asset_id, run.root_asset_id)
        self.assertEqual(job.status, SUCCESS_TASK)
        self.assertIsNotNone(job.finished)

    def test_failed_stage_marks_job_failed(self):
        ctx = {'scan_history_id': self.scan.id, 'results_dir': self.scan.results_dir}
        run = control.start_scan_run(self.domain, self.scan, 'full', ctx)
        self._run_stage('subdomain_discovery', ctx, fail=True)
        self.assertEqual(ScanJob.objects.get(run=run).status, FAILED_TASK)

    def test_cache_hit_finalizes_scan_job(self):
        ctx = {'scan_history_id': self.scan.id, 'results_dir': self.scan.results_dir}
        run = control.start_scan_run(self.domain, self.scan, 'full', ctx)
        fake_cache = mock.Mock()
        fake_cache.get.return_value = b'"cached"'
        with mock.patch('limes.celery_custom_task.LIMES_CACHE_ENABLED', True), \
                mock.patch('limes.celery_custom_task.cache', fake_cache):
            out = self._run_stage('subdomain_discovery', ctx)
        self.assertEqual(out, 'cached')
        job = ScanJob.objects.get(run=run)
        self.assertIsNotNone(job.finished)
        self.assertEqual(job.status, SUCCESS_TASK)

    def test_job_create_failure_does_not_fail_stage(self):
        ctx = {'scan_history_id': self.scan.id, 'results_dir': self.scan.results_dir}
        control.start_scan_run(self.domain, self.scan, 'full', ctx)
        with mock.patch.object(LimesTask, 'create_scan_job', side_effect=RuntimeError('db')):
            self.assertEqual(self._run_stage('subdomain_discovery', ctx), 'ok')

    def test_no_run_id_or_unknown_task_creates_no_job(self):
        ctx = {'scan_history_id': self.scan.id, 'results_dir': self.scan.results_dir}
        self._run_stage('subdomain_discovery', ctx)
        run = control.start_scan_run(self.domain, self.scan, 'full', {})
        ctx['scan_run_id'] = run.id
        self._run_stage('not_a_stage', ctx)
        self.assertEqual(ScanJob.objects.count(), 0)

    def _report(self, failed):
        ctx = {'scan_history_id': self.scan.id}
        run = control.start_scan_run(self.domain, self.scan, 'full', ctx)
        if failed:
            ScanActivity.objects.create(name='x', title='x', time=timezone.now(),
                                        status=FAILED_TASK, scan_of=self.scan)
        with mock.patch.object(control, 'send_scan_notif'):
            control.report.run(ctx=ctx)
        run.refresh_from_db()
        return run

    def test_report_sets_run_status(self):
        run = self._report(False)
        self.assertEqual(run.status, SUCCESS_TASK)
        self.assertIsNotNone(run.stop_scan_date)

    def test_report_marks_failed(self):
        self.assertEqual(self._report(True).status, FAILED_TASK)


def _task_names(sig):
    names = set()
    for t in getattr(sig, 'tasks', None) or [sig]:
        if hasattr(t, 'tasks'):
            names |= _task_names(t)
        else:
            names.add(t.task.rsplit('.', 1)[-1])
    return names


class WorkflowSplitTest(TestCase):
    def test_asm_chain_is_passive_only(self):
        self.assertEqual(_task_names(control.build_workflow({}, 'asm')),
                         {'subdomain_discovery', 'passive_intel', 'screenshot'})

    def test_full_chain_has_all_stages(self):
        self.assertEqual(_task_names(control.build_workflow({}, 'full')),
                         {'subdomain_discovery', 'passive_intel', 'port_scan', 'fetch_url',
                          'vulnerability_scan', 'screenshot', 'code_audit'})


class LifecycleViaReportTest(TestCase):
    def test_report_marks_unseen_missing_after_three_runs(self):
        from datetime import timedelta
        from startScan.asset_models import Asset
        p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        domain = Domain.objects.create(name='example.com', project=p, insert_date=timezone.now())
        eng = EngineType.objects.create(engine_name='e', yaml_configuration='')
        scan = ScanHistory.objects.create(
            scan_type=eng, domain=domain, start_scan_date=timezone.now(), results_dir=tempfile.mkdtemp())
        ctx = {'scan_history_id': scan.id}
        run = control.start_scan_run(domain, scan, 'asm', ctx)
        old = run.start_scan_date - timedelta(days=1)
        stale = Asset.objects.create(project=p, kind='hostname', value='old.example.com',
                                     parent=run.root_asset, last_seen=old, scope_tier='owned_host')
        fresh = Asset.objects.create(project=p, kind='hostname', value='new.example.com',
                                     parent=run.root_asset, last_seen=run.start_scan_date,
                                     scope_tier='owned_host')
        for _ in range(3):
            with mock.patch.object(control, 'send_scan_notif'):
                control.report.run(ctx=ctx)
        stale.refresh_from_db(); fresh.refresh_from_db()
        self.assertEqual(stale.state, 'missing')
        self.assertEqual(fresh.state, 'active')


class LifecycleGuardsTest(TestCase):
    def _setup(self):
        from datetime import timedelta
        p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        domain = Domain.objects.create(name='example.com', project=p, insert_date=timezone.now())
        eng = EngineType.objects.create(engine_name='e', yaml_configuration='')
        scan = ScanHistory.objects.create(
            scan_type=eng, domain=domain, start_scan_date=timezone.now(), results_dir=tempfile.mkdtemp())
        ctx = {'scan_history_id': scan.id}
        run = control.start_scan_run(domain, scan, 'asm', ctx)
        return p, scan, ctx, run, run.start_scan_date - timedelta(days=1)

    def test_failed_scan_does_not_age_hosts(self):
        from startScan.asset_models import Asset
        p, scan, ctx, run, old = self._setup()
        a = Asset.objects.create(project=p, kind='hostname', value='old.example.com',
                                 parent=run.root_asset, last_seen=old, scope_tier='owned_host')
        ScanActivity.objects.create(name='x', title='x', time=timezone.now(),
                                    status=FAILED_TASK, scan_of=scan)
        with mock.patch.object(control, 'send_scan_notif'):
            control.report.run(ctx=ctx)
        run.refresh_from_db(); a.refresh_from_db()
        self.assertEqual(run.status, FAILED_TASK)
        self.assertEqual((a.missed_count, a.state), (0, 'active'))

    def test_lifecycle_skips_non_owned_scope(self):
        from limes.tasks.inventory import finalize_lifecycle
        from startScan.asset_models import Asset
        p, scan, ctx, run, old = self._setup()
        a = Asset.objects.create(project=p, kind='hostname', value='cb.example.com',
                                 parent=run.root_asset, last_seen=old, scope_tier='co_brand')
        finalize_lifecycle(run)
        a.refresh_from_db()
        self.assertEqual((a.missed_count, a.state), (0, 'active'))
