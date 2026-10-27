import importlib

from django.apps import apps as django_apps
from django.test import TestCase

from startScan.models import Vulnerability

mig = importlib.import_module('startScan.migrations.0032_vulnerability_source_assay_to_vigil')


class RenameSourceTest(TestCase):
    def test_old_source_rewritten_others_untouched(self):
        old = Vulnerability.objects.create(name='a', severity=0, source=mig.OLD)
        other = Vulnerability.objects.create(name='b', severity=0, source='mantis')
        none = Vulnerability.objects.create(name='c', severity=0, source=None)
        mig.rename_source(django_apps, None)
        mig.rename_source(django_apps, None)  # idempotent
        self.assertEqual(Vulnerability.objects.get(pk=old.pk).source, 'vigil')
        self.assertEqual(Vulnerability.objects.get(pk=other.pk).source, 'mantis')
        self.assertIsNone(Vulnerability.objects.get(pk=none.pk).source)
