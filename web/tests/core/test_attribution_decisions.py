from datetime import timedelta
from io import StringIO
from unittest import mock

from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone

from dashboard.models import Project
from limes.tasks import attribution, inventory
from startScan.models import Asset, AssetFact


class DecisionBase(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='example.com', scope_tier='owned_root')
        Asset.objects.create(project=self.p, kind='ip', value='203.0.114.7', scope_tier='owned_host')
        inventory.record_fact(self.root, 'cert', '102', 'crtsh')
        p = mock.patch('dashboard.stats.invalidate')
        self.inv = p.start()
        self.addCleanup(p.stop)

    def cand(self, value, *facts):
        a = Asset.objects.create(project=self.p, kind='root_domain', value=value, scope_tier='candidate')
        for kind, val, src in facts:
            inventory.record_fact(a, kind, val, src)
        return a

    def delegate(self, a, value='ns1.example.com'):
        inventory.record_fact(a, 'delegation', value, 'parent')

    def run_all(self):
        attribution.score_project(self.p)
        return attribution.apply_decisions(self.p)

    def tier(self, a):
        a.refresh_from_db()
        return a.scope_tier


@override_settings(ATTRIBUTION_AUTO_CONFIRM=False)
class DisabledAutoConfirmTest(DecisionBase):
    """Default: NS control is spoofable through a recursive resolver, so nothing changes tier."""

    def test_qualifying_candidate_is_only_flagged(self):
        a = self.cand('ours.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        self.delegate(a)
        self.assertEqual(self.run_all(), {'auto_confirmed': 0, 'would_auto_confirm': 1})
        self.assertEqual(self.tier(a), 'candidate')
        self.assertTrue(a.confidence_detail['would_auto_confirm'])
        self.assertFalse(a.decision_reason)
        self.assertEqual([s['source'] for s in a.sources if s['source'] == 'attribution'], [])
        self.inv.assert_not_called()

    def test_non_qualifying_candidate_has_no_flag(self):
        a = self.cand('nsonly.net', ('ns', 'ns1.example.com', 'dns'))
        self.assertEqual(self.run_all(), {'auto_confirmed': 0, 'would_auto_confirm': 0})
        a.refresh_from_db()
        self.assertNotIn('would_auto_confirm', a.confidence_detail)

    def test_rescore_clears_a_stale_flag(self):
        a = self.cand('ours.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        self.delegate(a)
        self.run_all()
        AssetFact.objects.filter(asset=a, kind='cert').delete()
        self.run_all()
        a.refresh_from_db()
        self.assertNotIn('would_auto_confirm', a.confidence_detail)


@override_settings(ATTRIBUTION_AUTO_CONFIRM=True)
class DecisionTest(DecisionBase):
    def test_working_ns_control_plus_cert_auto_confirms(self):
        a = self.cand('ours.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        self.delegate(a)
        self.assertEqual(self.run_all(), {'auto_confirmed': 1, 'would_auto_confirm': 0})
        self.assertEqual(self.tier(a), 'owned_root')
        self.assertIn('auto-confirmed (attribution-v1)', a.decision_reason)
        self.assertIn('ns1.example.com', a.decision_reason)
        self.assertIn('delegation verified at parent', a.decision_reason)
        self.assertIsNone(a.added_by)
        self.assertEqual(a.sources[-1]['source'], 'attribution')
        self.inv.assert_called_once_with(self.p.id)

    def test_ns_control_without_corroboration_stays_candidate(self):
        a = self.cand('nsonly.net', ('ns', 'ns1.example.com', 'dns'))
        self.run_all()
        self.assertEqual(self.tier(a), 'candidate')

    def test_spoofed_dns_evidence_never_auto_confirms(self):
        # MX at our mail host + A at our IP + cert co-tenancy: high score, no NS control
        a = self.cand('spoof.net', ('mx', 'mail.example.com', 'dns'), ('ip', '203.0.114.7', 'dns'), ('cert', '102', 'crtsh'))
        # NS at our host but only alongside a DNS-sourced ip (attacker-controlled A record)
        b = self.cand('spoof2.net', ('ns', 'ns1.example.com', 'dns'), ('ip', '203.0.114.7', 'dns'))
        self.run_all()
        self.assertEqual((self.tier(a), self.tier(b)), ('candidate', 'candidate'))

    def test_ns_control_plus_internetdb_ip_only_never_qualifies(self):
        a = self.cand('pointed.net', ('ns', 'ns1.example.com', 'dns'), ('ip', '203.0.114.7', 'internetdb'))
        self.assertEqual(self.run_all(), {'auto_confirmed': 0, 'would_auto_confirm': 0})
        self.assertEqual(self.tier(a), 'candidate')

    def test_high_score_without_control_stays_candidate(self):
        a = self.cand('rich.net', ('mx', 'mail.example.com', 'dns'), ('ip', '203.0.114.7', 'internetdb'),
                      ('cert', '102', 'crtsh'))
        self.run_all()
        a.refresh_from_db()
        self.assertGreaterEqual(a.confidence, 0.9)
        self.assertEqual(a.scope_tier, 'candidate')

    def test_concurrent_rejection_wins(self):
        a = self.cand('race.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        attribution.score_project(self.p)
        Asset.objects.filter(pk=a.pk).update(scope_tier='rejected')  # human decision lands first
        self.assertEqual(attribution.apply_decisions(self.p), {'auto_confirmed': 0, 'would_auto_confirm': 0})
        self.assertEqual(self.tier(a), 'rejected')

    def test_rescore_command_scores_only_by_default(self):
        a = self.cand('cmd.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        out = StringIO()
        call_command('rescore_assets', 'p', stdout=out)
        self.assertEqual(self.tier(a), 'candidate')
        self.assertGreaterEqual(a.confidence, 0.9)
        self.assertEqual(out.getvalue().strip(), 'scored=1')

    def test_rescore_command_decides_on_request(self):
        a = self.cand('cmd.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        self.delegate(a)
        out = StringIO()
        call_command('rescore_assets', 'p', '--decide', stdout=out)
        self.assertEqual(self.tier(a), 'owned_root')
        self.assertIn('auto_confirmed=1', out.getvalue())

    def test_stale_ns_facts_never_auto_confirm(self):
        a = self.cand('stale.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        self.delegate(a)
        AssetFact.objects.filter(asset=a, kind='ns').update(last_seen=timezone.now() - timedelta(hours=25))
        self.assertEqual(self.run_all(), {'auto_confirmed': 0, 'would_auto_confirm': 0})
        self.assertEqual(self.tier(a), 'candidate')
        AssetFact.objects.filter(asset=a, kind='ns').update(last_seen=timezone.now() - timedelta(hours=1))
        self.assertEqual(attribution.apply_decisions(self.p), {'auto_confirmed': 1, 'would_auto_confirm': 0})

    def test_ns_facts_deleted_after_scoring_never_confirm(self):
        a = self.cand('gone.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        attribution.score_project(self.p)
        AssetFact.objects.filter(asset=a, kind='ns').delete()
        self.assertEqual(attribution.apply_decisions(self.p), {'auto_confirmed': 0, 'would_auto_confirm': 0})
        self.assertEqual(self.tier(a), 'candidate')

    def test_ns_facts_replaced_after_scoring_never_confirm(self):
        a = self.cand('moved.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        attribution.score_project(self.p)
        AssetFact.objects.filter(asset=a, kind='ns').delete()
        inventory.record_fact(a, 'ns', 'ns1.other.net', 'dns')
        self.assertEqual(attribution.apply_decisions(self.p), {'auto_confirmed': 0, 'would_auto_confirm': 0})
        self.assertEqual(self.tier(a), 'candidate')

    def test_concurrent_source_provenance_is_kept(self):
        a = self.cand('prov.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        self.delegate(a)
        attribution.score_project(self.p)
        Asset.objects.filter(pk=a.pk).update(sources=[{'source': 'manual', 'evidence': 'x'}])
        attribution.apply_decisions(self.p)
        a.refresh_from_db()
        self.assertEqual([s['source'] for s in a.sources], ['manual', 'attribution'])

    def test_qualifying_without_verified_delegation_stays_candidate(self):
        a = self.cand('unverified.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        self.assertEqual(self.run_all(), {'auto_confirmed': 0, 'would_auto_confirm': 0})
        self.assertEqual(self.tier(a), 'candidate')
        self.assertNotIn('would_auto_confirm', a.confidence_detail)

    def test_stale_delegation_never_confirms(self):
        a = self.cand('old.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        self.delegate(a)
        AssetFact.objects.filter(asset=a, kind='delegation').update(last_seen=timezone.now() - timedelta(hours=25))
        self.assertEqual(self.run_all(), {'auto_confirmed': 0, 'would_auto_confirm': 0})
        self.assertEqual(self.tier(a), 'candidate')

    def test_delegation_for_another_ns_set_never_confirms(self):
        a = self.cand('other.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        self.delegate(a, 'ns1.example.com, ns9.example.com')
        self.assertEqual(self.run_all(), {'auto_confirmed': 0, 'would_auto_confirm': 0})
        self.assertEqual(self.tier(a), 'candidate')


class VerifyDelegationsTest(DecisionBase):
    def qualifying(self, value):
        return self.cand(value, ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))

    def verify(self, *_):
        return True, 'delegation verified at a.gtld-servers.net'

    def test_success_records_fact_and_status(self):
        a = self.qualifying('ours.net')
        attribution.score_project(self.p)
        calls = []
        out = attribution.verify_delegations(self.p, verify=lambda d, ns: calls.append((d, list(ns))) or self.verify())
        self.assertEqual(out, {'verified': 1, 'unverified': 0})
        self.assertEqual(calls, [('ours.net', ['ns1.example.com'])])
        fact = AssetFact.objects.get(asset=a, kind='delegation')
        self.assertEqual((fact.value, fact.source), ('ns1.example.com', 'parent'))
        a.refresh_from_db()
        self.assertEqual(a.confidence_detail['delegation']['ok'], True)
        self.assertEqual(a.confidence_detail['delegation']['reason'], 'delegation verified at a.gtld-servers.net')

    def test_failure_deletes_fact_and_records_reason(self):
        a = self.qualifying('ours.net')
        self.delegate(a)
        attribution.score_project(self.p)
        out = attribution.verify_delegations(self.p, verify=lambda d, ns: (False, 'not authoritative'))
        self.assertEqual(out, {'verified': 0, 'unverified': 1})
        self.assertFalse(AssetFact.objects.filter(asset=a, kind='delegation').exists())
        a.refresh_from_db()
        self.assertEqual(a.confidence_detail['delegation']['reason'], 'not authoritative')

    def test_non_qualifying_candidates_are_never_checked(self):
        self.cand('nsonly.net', ('ns', 'ns1.example.com', 'dns'))  # no corroboration
        attribution.score_project(self.p)
        out = attribution.verify_delegations(self.p, verify=lambda d, ns: self.fail('checked'))
        self.assertEqual(out, {'verified': 0, 'unverified': 0})

    def test_cap_checks_highest_confidence_first(self):
        low, high = self.qualifying('low.net'), self.qualifying('high.net')
        attribution.score_project(self.p)
        Asset.objects.filter(pk=low.pk).update(confidence=0.91)
        seen = []
        with mock.patch.object(attribution, 'MAX_VERIFY', 1):
            attribution.verify_delegations(self.p, verify=lambda d, ns: seen.append(d) or self.verify())
        self.assertEqual(seen, ['high.net'])

    def test_human_decision_during_verification_wins(self):
        a = self.qualifying('race.net')
        attribution.score_project(self.p)

        def verify(d, ns):
            Asset.objects.filter(pk=a.pk).update(scope_tier='rejected')
            return self.verify()

        attribution.verify_delegations(self.p, verify=verify)
        a.refresh_from_db()
        self.assertEqual(a.scope_tier, 'rejected')
        self.assertNotIn('delegation', a.confidence_detail)

    def test_rescore_keeps_last_delegation_status(self):
        a = self.qualifying('ours.net')
        attribution.score_project(self.p)
        attribution.verify_delegations(self.p, verify=self.verify)
        attribution.score_project(self.p)
        a.refresh_from_db()
        self.assertTrue(a.confidence_detail['delegation']['ok'])
