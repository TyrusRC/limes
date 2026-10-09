from types import SimpleNamespace
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.tasks import inventory, resolution
from startScan.models import Asset


class CandidateTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())

    def test_new_value_is_candidate_with_evidence(self):
        a = inventory.upsert_candidate(self.p, 'root_domain', 'Partner-Co.com.', 'crtsh', 'cert:1')
        self.assertEqual((a.value, a.scope_tier), ('partner-co.com', 'candidate'))
        self.assertEqual(a.sources[0]['evidence'], 'cert:1')

    def test_existing_tiers_never_change(self):
        for value, tier in (('own.com', 'owned_root'), ('nope.com', 'rejected')):
            Asset.objects.create(project=self.p, kind='root_domain', value=value, scope_tier=tier)
            a = inventory.upsert_candidate(self.p, 'root_domain', value, 'crtsh', 'cert:2')
            self.assertEqual(a.scope_tier, tier)
            self.assertEqual(a.sources[-1]['source'], 'crtsh')

    def test_existing_asset_save_only_touches_sources(self):
        # A concurrent Confirm/Reject must not be overwritten with a stale tier.
        Asset.objects.create(project=self.p, kind='root_domain', value='own.com', scope_tier='owned_root')
        with mock.patch.object(Asset, 'save', autospec=True, side_effect=Asset.save) as save:
            inventory.upsert_candidate(self.p, 'root_domain', 'own.com', 'crtsh', 'cert:3')
        self.assertEqual(save.call_args.kwargs.get('update_fields'), ['sources'])

    def test_existing_hostname_save_only_touches_sources_and_parent(self):
        # crt.sh upserts hostnames in bulk; a concurrent Confirm/Reject must not be reverted.
        Asset.objects.create(project=self.p, kind='hostname', value='a.own.com', scope_tier='owned_host')
        with mock.patch.object(Asset, 'save', autospec=True, side_effect=Asset.save) as save:
            inventory.upsert_hostname_asset(self.p, 'a.own.com', source='crtsh', evidence='cert:4')
        self.assertEqual(save.call_args_list[0].kwargs.get('update_fields'), ['sources', 'parent'])

    def test_owned_root_values(self):
        Asset.objects.create(project=self.p, kind='root_domain', value='own.com', scope_tier='owned_root')
        Asset.objects.create(project=self.p, kind='root_domain', value='cand.com', scope_tier='candidate')
        self.assertEqual(inventory.owned_root_values(self.p), {'own.com'})

    def test_enrichment_defaults_to_dict(self):
        a = Asset.objects.create(project=self.p, kind='ip', value='8.8.8.8', scope_tier='dependency')
        a.refresh_from_db()
        self.assertEqual(a.enrichment, {})


class RootForDomainTest(TestCase):
    def test_lookup(self):
        p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        root = Asset.objects.create(project=p, kind='root_domain', value='example.com', scope_tier='owned_root')
        self.assertEqual(resolution.root_for_domain(SimpleNamespace(project=p, name='Example.com.')), (p, root))
        self.assertEqual(resolution.root_for_domain(SimpleNamespace(project=None, name='example.com')), (None, None))
        self.assertEqual(resolution.root_for_domain(SimpleNamespace(project=p, name='other.com')), (p, None))
