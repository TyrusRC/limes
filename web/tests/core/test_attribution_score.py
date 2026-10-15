from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.tasks import attribution, inventory
from startScan.models import Asset


class BrandTokensTest(SimpleTestCase):
    def test_whole_label_tokens(self):
        self.assertIn('acme', attribution.brand_tokens('acme-shop.com'))
        self.assertNotIn('acme', attribution.brand_tokens('acmesoft.com'))
        self.assertEqual(attribution.brand_tokens('shop.acme.co.uk'), {'shop', 'acme'})


class ScoreTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now(), brand_keywords=['acme', 'ab'])
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='example.com', scope_tier='owned_root')
        self.own_ip = Asset.objects.create(project=self.p, kind='ip', value='203.0.114.7', scope_tier='owned_host')
        inventory.record_fact(self.root, 'cert', '102', 'crtsh')

    def cand(self, value, *facts):
        a = Asset.objects.create(project=self.p, kind='root_domain', value=value, scope_tier='candidate')
        for kind, val, src in facts:
            inventory.record_fact(a, kind, val, src)
        return a

    def score(self, a):
        attribution.score_project(self.p)
        a.refresh_from_db()
        return a.confidence, {c['kind']: c for c in a.confidence_detail['contributions']}

    def test_each_weight_alone(self):
        cases = [
            (('ns', 'ns1.example.com', 'dns'), 0.95), (('mx', 'mail.example.com', 'dns'), 0.60),
            (('ip', '203.0.114.7', 'internetdb'), 0.60), (('cert', '102', 'crtsh'), 0.50),
        ]
        for i, (fact, expected) in enumerate(cases):
            a = self.cand(f'c{i}.net', fact)
            self.assertAlmostEqual(self.score(a)[0], expected, places=4, msg=fact)

    def test_noisy_or_and_flags(self):
        a = self.cand('both.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        score, by = self.score(a)
        self.assertAlmostEqual(score, 1 - (1 - 0.95) * (1 - 0.5), places=4)
        self.assertTrue(by['ns']['control'])
        self.assertTrue(by['cert']['corroborates'])
        self.assertEqual(by['ns']['via'], 'example.com')

    def test_ns_control_needs_every_ns_under_owned_root(self):
        a = self.cand('mixed.net', ('ns', 'ns1.example.com', 'dns'), ('ns', 'ns1.provider.net', 'dns'))
        self.assertIsNone(self.score(a)[1].get('ns'))

    def test_dns_sourced_ip_scores_but_never_corroborates(self):
        a = self.cand('pointed.net', ('ip', '203.0.114.7', 'dns'))
        score, by = self.score(a)
        self.assertAlmostEqual(score, 0.60, places=4)
        self.assertFalse(by['ip']['corroborates'])

    def test_internetdb_ip_scores_but_never_corroborates(self):
        # InternetDB hostnames include any domain whose A record points at the IP: attacker-influenced
        a = self.cand('shodan.net', ('ip', '203.0.114.7', 'internetdb'))
        score, by = self.score(a)
        self.assertAlmostEqual(score, 0.60, places=4)
        self.assertFalse(by['ip']['corroborates'])

    def test_auto_confirmed_assets_are_never_evidence(self):
        # an auto-confirmed root must not vouch for the next candidate (no chaining)
        auto = Asset.objects.create(project=self.p, kind='root_domain', value='chained.net', scope_tier='owned_root',
                                    sources=[{'source': 'crtsh', 'evidence': 'x'},
                                             {'source': 'attribution', 'evidence': 'auto-confirmed'}])
        inventory.record_fact(auto, 'cert', '900', 'crtsh')
        Asset.objects.create(project=self.p, kind='ip', value='203.0.114.9', scope_tier='owned_host',
                             sources=[{'source': 'attribution', 'evidence': 'auto-confirmed'}])
        a = self.cand('next.net', ('ns', 'ns1.chained.net', 'dns'), ('mx', 'mx.chained.net', 'dns'),
                      ('cert', '900', 'crtsh'), ('ip', '203.0.114.9', 'internetdb'))
        score, by = self.score(a)
        self.assertEqual(by, {})
        self.assertAlmostEqual(score or 0.0, 0.0, places=4)

    def test_brand_whole_label_and_short_keywords_ignored(self):
        self.assertAlmostEqual(self.score(self.cand('acme-store.net'))[0], 0.30, places=4)
        self.assertAlmostEqual(self.score(self.cand('acmesoft.net'))[0] or 0.0, 0.0, places=4)
        self.assertAlmostEqual(self.score(self.cand('ab-shop.net'))[0] or 0.0, 0.0, places=4)  # 'ab' < 4 chars

    def test_hop2_half_weight_only_through_reviewable_candidate(self):
        strong = self.cand('strong.net', ('cert', '102', 'crtsh'), ('mx', 'mail.example.com', 'dns'))  # 0.8 hop-1
        linked = self.cand('linked.net', ('cert', '555', 'crtsh'))
        inventory.record_fact(strong, 'cert', '555', 'crtsh')
        weak = self.cand('weak.net', ('cert', '777', 'crtsh'))
        unlinked = self.cand('unlinked.net', ('cert', '777', 'crtsh'))
        attribution.score_project(self.p)
        linked.refresh_from_db(); unlinked.refresh_from_db()
        self.assertAlmostEqual(linked.confidence, 0.25, places=4)
        self.assertEqual(linked.confidence_detail['contributions'][0]['hop'], 2)
        self.assertEqual(linked.confidence_detail['contributions'][0]['via'], 'strong.net')
        self.assertAlmostEqual(unlinked.confidence or 0.0, 0.0, places=4)  # weak.net scores 0 at hop 1

    def test_hop2_ignores_dns_sourced_facts(self):
        # A records are set by whoever owns the name: sharing one proves nothing
        strong = self.cand('strong.net', ('cert', '102', 'crtsh'), ('mx', 'mail.example.com', 'dns'),
                           ('ip', '198.51.100.20', 'dns'))
        follower = self.cand('follower.net', ('ip', '198.51.100.20', 'dns'))
        # nor may a candidate's own A record ride on a provider-reported fact of another
        inventory.record_fact(strong, 'ip', '198.51.100.30', 'internetdb')
        rider = self.cand('rider.net', ('ip', '198.51.100.30', 'dns'))
        attribution.score_project(self.p)
        follower.refresh_from_db(); rider.refresh_from_db()
        self.assertEqual(follower.confidence_detail['contributions'], [])
        self.assertEqual(rider.confidence_detail['contributions'], [])

    def test_hop2_via_is_lowest_id_reviewable_candidate(self):
        first = self.cand('zzz.net', ('cert', '102', 'crtsh'), ('cert', '555', 'crtsh'))
        self.cand('aaa.net', ('cert', '102', 'crtsh'), ('cert', '555', 'crtsh'))
        linked = self.cand('linked.net', ('cert', '555', 'crtsh'))
        attribution.score_project(self.p)
        linked.refresh_from_db()
        self.assertEqual(linked.confidence_detail['contributions'][0]['via'], first.value)

    def test_decided_assets_never_scored(self):
        rej = Asset.objects.create(project=self.p, kind='root_domain', value='nope.net', scope_tier='rejected')
        inventory.record_fact(rej, 'cert', '102', 'crtsh')
        attribution.score_project(self.p)
        rej.refresh_from_db(); self.root.refresh_from_db()
        self.assertIsNone(rej.confidence)
        self.assertIsNone(self.root.confidence)

    def test_candidate_rejected_mid_scoring_is_not_written(self):
        a = self.cand('race.net', ('cert', '102', 'crtsh'))

        def reject_then_empty(*args, **kwargs):
            Asset.objects.filter(pk=a.pk).update(scope_tier='rejected')
            return []

        with mock.patch('limes.tasks.attribution._hop1', side_effect=reject_then_empty):
            self.assertEqual(attribution.score_project(self.p), {'scored': 0})
        a.refresh_from_db()
        self.assertIsNone(a.confidence)
