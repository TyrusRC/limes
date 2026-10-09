import importlib

from django.apps import apps as django_apps
from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from startScan.models import Asset

migration = importlib.import_module('startScan.migrations.0012_demote_auto_owned_ips')


class DemoteAutoOwnedIpsTest(TestCase):
    def test_only_machine_created_undecided_ips_outside_owned_space(self):
        p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        u = User.objects.create_user('u')
        Asset.objects.create(project=p, kind='cidr', value='203.0.114.0/24', scope_tier='owned_host')
        mk = lambda v, **kw: Asset.objects.create(project=p, kind='ip', value=v, scope_tier='owned_host', **kw)
        probe = mk('104.16.1.1', sources=[{'source': 'probe', 'evidence': 'host:a'}])
        backfill = mk('104.16.1.2')                                            # A0 back-fill: no sources
        manual = mk('104.16.1.3', added_by=u)
        reasoned = mk('104.16.1.4', decision_reason='our colo')
        in_cidr = mk('203.0.114.5', sources=[{'source': 'probe', 'evidence': 'host:b'}])
        other_src = mk('104.16.1.6', sources=[{'source': 'manual', 'evidence': 'x'}])
        migration.demote_auto_owned_ips(django_apps, None)
        tiers = {a.value: a.scope_tier for a in Asset.objects.filter(kind='ip')}
        self.assertEqual(tiers, {'104.16.1.1': 'dependency', '104.16.1.2': 'dependency',
                                 '104.16.1.3': 'owned_host', '104.16.1.4': 'owned_host',
                                 '203.0.114.5': 'owned_host', '104.16.1.6': 'owned_host'})
