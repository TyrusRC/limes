from datetime import timedelta
from io import StringIO
from unittest import mock

from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.tasks import attribution, inventory
from startScan.models import Asset, AssetFact


class DecisionTest(TestCase):
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

    def run_all(self):
        attribution.score_project(self.p)
        return attribution.apply_decisions(self.p)

    def tier(self, a):
        a.refresh_from_db()
        return a.scope_tier

    def test_working_ns_control_plus_cert_auto_confirms(self):
        a = self.cand('ours.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        self.assertEqual(self.run_all(), {'auto_confirmed': 1})
        self.assertEqual(self.tier(a), 'owned_root')
        self.assertIn('auto-confirmed (attribution-v1)', a.decision_reason)
        self.assertIn('ns1.example.com', a.decision_reason)
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
        self.assertEqual(attribution.apply_decisions(self.p), {'auto_confirmed': 0})
        self.assertEqual(self.tier(a), 'rejected')

    def test_rescore_command(self):
        a = self.cand('cmd.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        out = StringIO()
        call_command('rescore_assets', 'p', stdout=out)
        self.assertEqual(self.tier(a), 'owned_root')
        self.assertIn('scored', out.getvalue())

    def test_stale_ns_facts_never_auto_confirm(self):
        a = self.cand('stale.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        AssetFact.objects.filter(asset=a, kind='ns').update(last_seen=timezone.now() - timedelta(hours=25))
        self.assertEqual(self.run_all(), {'auto_confirmed': 0})
        self.assertEqual(self.tier(a), 'candidate')
        AssetFact.objects.filter(asset=a, kind='ns').update(last_seen=timezone.now() - timedelta(hours=1))
        self.assertEqual(attribution.apply_decisions(self.p), {'auto_confirmed': 1})
