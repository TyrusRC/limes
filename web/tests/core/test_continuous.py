from datetime import timedelta
from unittest import mock

from django.test import TestCase, override_settings
from django.utils import timezone

from dashboard.models import Project
from limes import continuous
from limes.definitions import FAILED_TASK, INITIATED_TASK, RUNNING_TASK, SCHEDULED_SCAN, SUCCESS_TASK
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
    def test_scheduled_system_start(self):
        a = self.root('x.com')
        self.assertEqual(continuous.start_asm_scan(a, scan_type=SCHEDULED_SCAN), (True, 'ASM scan started for x.com'))
        kw = self.apply_async.call_args.kwargs['kwargs']
        self.assertEqual((kw['scan_type'], kw['initiated_by_id'], kw['scan_mode']), (SCHEDULED_SCAN, None, 'asm'))
