from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from dashboard import activity
from dashboard.stats import _risky_assets
from dashboard.views import on_user_logged_in
from limes import scoring, waivers
from limes.alerts.issues import sync_issues
from limes.checks.catalogue import CHECKS, PROVISIONAL
from startScan.models import Asset, TrackedIssue
from tests.core.test_category_scores import CategoryBase

IDS = {'rep.listed_drop': 'reputation', 'rep.listed_asndrop': 'reputation', 'rep.listed_c2': 'reputation',
       'rep.listed_attacker': 'reputation', 'rep.dnsbl_listed': 'reputation', 'net.exposed_ollama': 'network',
       'net.exposed_openai_api': 'network', 'net.exposed_triton': 'network', 'net.exposed_gradio': 'network',
       'net.exposed_jupyter': 'network', 'net.exposed_ray': 'network', 'leak.supabase_secret_key': 'data_leakage',
       'leak.hibp_breach': 'data_leakage',
       'api.exposed_docs': 'web', 'api.no_auth_declared': 'web', 'api.unauthenticated_access': 'web'}
ORIGINAL = ('web', 'tls', 'email', 'dns', 'network', 'vulnerabilities')


class ProvisionalTest(CategoryBase):
    def owned(self, kind, value):
        return Asset.objects.create(project=self.p, kind=kind, value=value, scope_tier='owned_host')

    def add_provisional(self, ip, cidr):
        self.check(ip, 'rep.listed_c2', 'fail')
        self.check(self.a, 'net.exposed_jupyter', 'fail')
        self.check(Asset.objects.get(value='b.x.com'), 'leak.supabase_secret_key', 'fail')
        self.check(cidr, 'rep.listed_drop', 'fail')
        return ip, cidr

    def test_points_and_ids(self):
        self.assertEqual(PROVISIONAL, set(IDS))
        self.assertEqual(scoring.points('rep.listed_c2', 4), 0)
        self.assertEqual(scoring.points('net.exposed_rdp', 3), 80)
        self.assertEqual(scoring.points('CVE-2021-44228', 3), 80)
        for k, group in IDS.items():
            self.assertEqual(CHECKS[k].group, group)
            self.assertEqual(scoring.category_of(k), group)
            self.assertTrue(CHECKS[k].provisional)
        self.assertFalse(CHECKS['net.exposed_rdp'].provisional)
        self.assertEqual(scoring.PROVISIONAL_CATEGORIES, {'reputation', 'data_leakage'})

    def test_provisional_fail_leaves_headline_identical(self):
        p = self.reconcile_project()
        ip, cidr = self.owned('ip', '45.10.1.5'), self.owned('cidr', '45.10.0.0/22')  # the assets exist before the rows do
        before, cats, assessed = scoring.project_score(p, self.now), scoring.category_scores(p, self.now), scoring.assessed_assets(p, now=self.now)
        self.add_provisional(ip, cidr)
        self.assertEqual(scoring.project_score(p, self.now), before)
        self.assertEqual(scoring.assessed_assets(p, now=self.now), assessed)
        after = scoring.category_scores(p, self.now)
        for c in ORIGINAL:
            self.assertEqual(after[c]['score'], cats[c]['score'], c)
            self.assertEqual({k: v for k, v in after[c].items() if k != 'provisional'},
                             {k: v for k, v in cats[c].items() if k != 'provisional'}, c)
        for c in ('reputation', 'data_leakage'):
            self.assertIsNone(after[c]['score'])
            self.assertEqual(after[c]['grade'], 'N/A')
            self.assertTrue(after[c]['provisional'])
        self.assertEqual(scoring.forecast(p, [], self.now)['score'], before['score'])

    def test_waived_provisional_and_top_penalties_unchanged(self):
        a = self.host('a.x.com')  # two scored penalties: fewer than TOP_PENALTIES, so a provisional row would show
        self.check(a, 'web.hsts_missing', 'fail')
        self.check(a, 'tls.cert_expired', 'fail')
        before = scoring.project_score(self.p, self.now)
        self.assertEqual(len(before['top_penalties']), 2)
        self.check(a, 'net.exposed_jupyter', 'fail')
        self.check(a, 'leak.supabase_secret_key', 'fail')
        sync_issues(self.p, now=self.now)
        issue = TrackedIssue.objects.get(asset=a, key='net.exposed_jupyter')
        waivers.create_waiver(issue, 'accepted_risk', 'ok', User.objects.create(username='w'), now=self.now)
        after = scoring.project_score(self.p, self.now)
        self.assertEqual(after['waived_count'], before['waived_count'])
        self.assertEqual(after['top_penalties'], before['top_penalties'])
        self.assertFalse([r for r in after['top_penalties'] if r['issue'] in PROVISIONAL])

    def test_risky_assets_ignore_provisional_severities(self):
        a = self.host('a.x.com')
        self.check(a, 'web.hsts_missing', 'fail')
        self.check(a, 'net.exposed_jupyter', 'fail')  # critical, provisional
        penalties, _ = scoring.current_issues(self.p, now=self.now)
        rows = _risky_assets({a: penalties[a.id]})
        self.assertEqual(rows[0]['counts'], {'critical': 0, 'high': 0, 'medium': 1, 'low': 0})

    def test_provisional_worst_severity_has_no_ceiling(self):
        self.assertEqual(scoring._score({'leak.supabase_secret_key': 4, 'web.hsts_missing': 2}), 925)

    def test_ip_with_only_reputation_rows_stays_unassessed(self):
        p = self.reconcile_project()
        before = scoring.project_score(p, self.now)
        ip = self.owned('ip', '45.10.1.6')
        self.check(ip, 'rep.listed_drop', 'pass')
        self.check(ip, 'rep.listed_c2', 'pass')
        self.assertNotIn(ip.id, scoring.assessed_assets(p, now=self.now))
        after = scoring.project_score(p, self.now)
        self.assertEqual(after['unassessed'], before['unassessed'] + 1)
        self.assertEqual(after['asset_count'], before['asset_count'])
        scored = scoring.scored_assets(p).count()
        fresh = 3  # a, b, x.com carry non-provisional pass/fail rows
        self.assertEqual(after['check_coverage'], fresh / scored)

    def test_provisional_issues_are_tracked(self):
        p = self.reconcile_project()
        ip, cidr = self.owned('ip', '45.10.1.5'), self.owned('cidr', '45.10.0.0/22')
        self.add_provisional(ip, cidr)
        sync_issues(p, now=self.now)
        keys = set(TrackedIssue.objects.filter(project=p, status='open', key__in=PROVISIONAL).values_list('asset__value', 'key'))
        self.assertEqual(keys, {('45.10.1.5', 'rep.listed_c2'), ('a.x.com', 'net.exposed_jupyter'),
                                ('b.x.com', 'leak.supabase_secret_key'), ('45.10.0.0/22', 'rep.listed_drop')})
        counts = scoring.category_issue_counts(p, self.now)
        self.assertEqual((counts['reputation']['open'], counts['data_leakage']['open']), (2, 1))
        self.assertEqual(counts['network']['open'], 1)
        row = self.check_row(cidr, 'rep.listed_drop')
        row.status = 'pass'
        row.save()
        sync_issues(p, now=self.now)
        self.assertEqual(TrackedIssue.objects.get(asset=cidr, key='rep.listed_drop').status, 'fixed')
        self.assertEqual(scoring.category_issue_counts(p, self.now)['reputation']['open'], 1)

    def check_row(self, asset, check_id):
        from startScan.models import RiskCheck
        return RiskCheck.objects.get(asset=asset, check_id=check_id)

    def test_top_risks_provisional_rows(self):
        a = self.host('a.x.com')
        self.check(a, 'rep.listed_c2', 'fail')  # critical, provisional
        self.check(a, 'tls.cert_expired', 'fail')  # high
        penalties, assessed = scoring.current_issues(self.p, now=self.now)
        rows = activity.top_risks(self.p, {a: penalties[a.id]}, self.now)
        self.assertEqual([r['key'] for r in rows], ['tls.cert_expired', 'rep.listed_c2'])
        self.assertEqual((rows[0]['points'], rows[0]['provisional']), (80, False))
        self.assertEqual((rows[1]['points'], rows[1]['provisional']), (0, True))


class ProvisionalApiTest(CategoryBase):
    def test_issue_list_flags_provisional(self):
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        admin = User.objects.create_user('adm', password='p')
        assign_role(admin, 'sys_admin')
        c = APIClient()
        c.force_login(admin)
        a = self.host('a.x.com')
        ip = Asset.objects.create(project=self.p, kind='ip', value='45.10.1.5', scope_tier='owned_host')
        self.check(a, 'leak.supabase_secret_key', 'fail')
        self.check(ip, 'rep.listed_c2', 'fail')
        self.check(ip, 'rep.listed_drop', 'fail')
        self.check(a, 'web.hsts_missing', 'fail')
        sync_issues(self.p, now=self.now)

        def rows(**q):
            return c.get('/api/issues/', {'project': 'p', **q}).json()
        by_key = {r['key']: r for r in rows()}
        self.assertTrue(by_key['leak.supabase_secret_key']['provisional'])
        self.assertFalse(by_key['web.hsts_missing']['provisional'])
        self.assertEqual([r['key'] for r in rows(category='data_leakage')], ['leak.supabase_secret_key'])
        self.assertEqual({r['key'] for r in rows(category='reputation')}, {'rep.listed_c2', 'rep.listed_drop'})
