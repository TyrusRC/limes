import tempfile
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.celery_custom_task import LimesTask
from limes.tasks import control, stages
from scanEngine.models import EngineType
from startScan.models import Asset, ScanHistory
from targetApp.models import Domain


def _names(sig):
    tasks = getattr(sig, 'tasks', None)
    if tasks is None:
        return [sig.task.rsplit('.', 1)[-1]]
    out = []
    for t in tasks:
        out += _names(t)
    return out


class PassiveIntelStageTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.domain = Domain.objects.create(name='example.com', project=self.p, insert_date=timezone.now())
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='example.com', scope_tier='owned_root')
        eng = EngineType.objects.create(engine_name='e', yaml_configuration='{}')
        self.scan = ScanHistory.objects.create(scan_type=eng, domain=self.domain, start_scan_date=timezone.now(),
                                               results_dir=tempfile.mkdtemp())
        self.ctx = {'scan_history_id': self.scan.id, 'results_dir': self.scan.results_dir, 'track': False}
        p = mock.patch.object(LimesTask, 'notify')
        p.start()
        self.addCleanup(p.stop)

    def patched(self, **overrides):
        mocks = {
            'run_crtsh': mock.patch('limes.tasks.intel.run_crtsh', return_value={'hostnames': 1, 'candidates': 1}),
            'resolve_root': mock.patch('limes.tasks.resolution.resolve_root', return_value=3),
            'run_internetdb': mock.patch('limes.tasks.intel.run_internetdb', return_value={'internetdb_enriched': 2, 'candidates': 0}),
            'run_ripestat': mock.patch('limes.tasks.intel.run_ripestat', return_value={'ripestat_enriched': 2}),
        }
        mocks.update(overrides)
        return {k: p.start() for k, p in mocks.items()}

    def tearDown(self):
        mock.patch.stopall()

    def test_runs_providers_and_resolves_between(self):
        m = self.patched()
        stages.passive_intel(ctx=dict(self.ctx))
        for name in ('run_crtsh', 'resolve_root', 'run_internetdb', 'run_ripestat'):
            m[name].assert_called_once()

    def test_one_failing_provider_does_not_stop_others(self):
        m = self.patched(run_crtsh=mock.patch('limes.tasks.intel.run_crtsh', side_effect=RuntimeError('crt.sh down')))
        stages.passive_intel(ctx=dict(self.ctx))
        m['run_internetdb'].assert_called_once()
        m['run_ripestat'].assert_called_once()

    def test_non_owned_root_is_never_expanded(self):
        self.root.scope_tier = 'candidate'
        self.root.save()
        m = self.patched()
        stages.passive_intel(ctx=dict(self.ctx))
        for name in ('run_crtsh', 'run_internetdb', 'run_ripestat'):
            m[name].assert_not_called()

    def test_passive_intel_runs_right_after_discovery(self):
        for mode in ('asm', 'full'):
            names = _names(control.build_workflow({}, mode))
            self.assertEqual(names[:2], ['subdomain_discovery', 'passive_intel'], mode)
