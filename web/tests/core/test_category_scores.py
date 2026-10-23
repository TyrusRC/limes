from datetime import timedelta

from django.contrib.auth.models import User
from django.utils import timezone

from limes import scoring, waivers
from limes.alerts.issues import sync_issues
from limes.checks.catalogue import CHECKS
from startScan.models import Asset, RiskCheck, ScoreSnapshot, TrackedIssue
from tests.core.test_scoring import Base

NONE_ASSESSED = {'web': None, 'tls': None, 'email': None, 'dns': None, 'network': None, 'vulnerabilities': None}


class CategoryBase(Base):
    def check(self, asset, check_id, status, ago=timedelta(0)):
        return RiskCheck.objects.create(asset=asset, check_id=check_id, status=status, severity=CHECKS[check_id].severity,
                                        last_checked=self.now - ago)

    def reconcile_project(self):
        s = self.scan()
        a, b, c = self.host('a.x.com'), self.host('b.x.com'), self.host('c.x.com')
        self.d = self.host('d.x.com', state='retired')
        self.a = a
        self.vuln(s, a, 3, template='cve-1')
        self.vuln(s, b, 2, template='cve-2')
        self.check(a, 'web.hsts_missing', 'fail')
        self.check(a, 'tls.cert_expired', 'fail')
        self.check(b, 'web.hsts_missing', 'pass')
        self.check(self.root, 'email.dmarc_missing', 'fail')
        self.check(self.root, 'dns.caa_missing', 'pass')
        sync_issues(self.p, now=self.now)
        TrackedIssue.objects.create(project=self.p, asset=self.d, key='cve-9', source='finding', severity=3)
        return self.p

    def by_hand(self, scores):
        return {k: (v['score'], v['grade'], v['assessed']) for k, v in scores.items()}


class CategoryTest(CategoryBase):
    def test_category_of(self):
        for key, want in [('web.hsts_missing', 'web'), ('tls.cert_expired', 'tls'), ('email.spf_missing', 'email'),
                          ('dns.caa_missing', 'dns'), ('net.exposed_rdp', 'network'), ('CVE-2021-44228', 'vulnerabilities'),
                          (scoring.issue_key('x' * 400), 'vulnerabilities'), ('web.not_a_check', 'vulnerabilities')]:
            self.assertEqual(scoring.category_of(key), want, key)
        a = self.host('a.x.com')
        for check_id in CHECKS:
            row = TrackedIssue.objects.create(project=self.p, asset=a, key=check_id, source='check', severity=1)
            self.assertIn(row, TrackedIssue.objects.filter(scoring.category_q(scoring.category_of(check_id))), check_id)
        self.assertIsNone(scoring.category_q('bogus'))

    def test_category_scores_match_scoring_by_hand(self):
        p = self.reconcile_project()
        # Each category is p10 (the minimum, with <= 4 assessed assets) of 950 - PENALTY, capped by CEILING:
        #   web: a fails hsts (medium 25) -> 925; b passes -> 950; min 925, 2 assets checked.
        #   tls: only a is checked; critical-free high cert_expired (80) -> 870, capped by the high ceiling to 799.
        #   email: only x.com is checked; dmarc medium -> 925.   dns: x.com passes -> 950.
        #   network: no network check ran -> not assessed.
        #   vulnerabilities: assessed assets under the baselined root are x.com, a, b, c (d is retired);
        #     a has a high finding -> 870 capped to 799, b medium -> 925, others 950; min 799.
        self.assertEqual(self.by_hand(scoring.category_scores(p)), {
            'web': (925, 'A', 2), 'tls': (799, 'B', 1), 'email': (925, 'A', 1), 'dns': (950, 'A', 1),
            'network': (None, 'N/A', 0), 'vulnerabilities': (799, 'B', 4)})
        # headline: a = 950 - 80 (cve-1) - 25 (hsts) - 80 (cert) = 765, the weakest of 4 assessed assets
        self.assertEqual(scoring.project_score(p)['score'], 765)

    def test_headline_unchanged_by_categories(self):
        p = self.reconcile_project()
        before = scoring.project_score(p)
        scoring.category_scores(p)
        self.assertEqual(scoring.project_score(p), before)
        self.assertEqual((before['score'], before['grade'], before['version']), (765, 'B', 'limes-score-v3'))

    def test_waived_issue_moves_adjusted_only(self):
        p = self.reconcile_project()
        issue = TrackedIssue.objects.get(asset=self.a, key='tls.cert_expired')
        waivers.create_waiver(issue, 'accepted_risk', 'ok', User.objects.create(username='u'), now=self.now)
        cats = scoring.category_scores(p, now=self.now)
        self.assertEqual((cats['tls']['score'], cats['tls']['raw_score'], cats['tls']['raw_grade']), (950, 799, 'B'))
        self.assertEqual(self.by_hand(cats)['web'], (925, 'A', 2))
        self.assertEqual(self.by_hand(cats)['vulnerabilities'], (799, 'B', 4))
        self.assertEqual(scoring.project_score(p, now=self.now)['score'], 799)

    def test_nothing_assessed_is_not_assessed(self):
        self.host('a.x.com')
        stale = self.check(self.host('b.x.com'), 'web.hsts_missing', 'fail', ago=timedelta(days=31))
        self.assertTrue(stale.pk)
        for v in scoring.category_scores(self.p).values():
            self.assertEqual((v['score'], v['grade'], v['assessed']), (None, 'N/A', 0))

    def test_checks_without_baseline(self):
        self.check(self.host('a.x.com'), 'web.hsts_missing', 'pass')
        cats = scoring.category_scores(self.p)
        self.assertEqual((cats['web']['score'], cats['web']['assessed']), (950, 1))
        self.assertIsNone(cats['vulnerabilities']['score'])

    def test_issue_counts_add_up_to_issues_page(self):
        p = self.reconcile_project()
        counts = scoring.category_issue_counts(p)
        self.assertEqual({k: v['open'] for k, v in counts.items()},
                         {'web': 1, 'tls': 1, 'email': 1, 'dns': 0, 'network': 0, 'vulnerabilities': 3})
        self.assertEqual(sum(v['open'] for v in counts.values()),
                         TrackedIssue.objects.filter(project=p, status='open').count())
        TrackedIssue.objects.filter(asset=self.d).update(status='fixed')
        other = self.owned_root('y.com', project=self.make_other())
        TrackedIssue.objects.create(project=other.project, asset=other, key='web.hsts_missing', source='check', severity=2)
        counts = scoring.category_issue_counts(p)
        self.assertEqual((counts['vulnerabilities']['open'], counts['web']['open']), (2, 1))
        issue = TrackedIssue.objects.get(asset=self.a, key='web.hsts_missing')
        waivers.create_waiver(issue, 'accepted_risk', 'ok', User.objects.create(username='u'))
        counts = scoring.category_issue_counts(p)
        self.assertEqual((counts['web']['waived'], counts['web']['open'], counts['tls']['waived']), (1, 1, 0))

    def make_other(self):
        from dashboard.models import Project
        return Project.objects.create(name='o', slug='o', insert_date=timezone.now())

    def test_snapshot_writes_categories(self):
        self.reconcile_project()
        scoring.snapshot_scores()
        snap = ScoreSnapshot.objects.get(project=self.p)
        self.assertEqual(snap.categories, {'web': 925, 'tls': 799, 'email': 925, 'dns': 950, 'network': None,
                                           'vulnerabilities': 799})
        self.assertEqual(snap.version, 'limes-score-v3')
        old = ScoreSnapshot.objects.create(project=self.p, date=snap.date - timedelta(days=1), version='v', grade='A')
        self.assertIsNone(old.categories)


class CategoryEdgeTest(CategoryBase):
    def test_penalised_asset_outside_checked_set_still_counts(self):
        # an IP has no owned root, so it is not in the vulnerabilities `checked` set, but the headline scores it
        s = self.scan()
        ip = Asset.objects.create(project=self.p, kind='ip', value='10.0.0.1', scope_tier='owned_host')
        self.check(ip, 'web.hsts_missing', 'pass')
        self.vuln(s, ip, 4)
        self.assertEqual(scoring.project_score(self.p)['score'], 599)
        cats = scoring.category_scores(self.p)
        self.assertEqual((cats['vulnerabilities']['score'], cats['vulnerabilities']['assessed']), (599, 2))

    def test_orphan_check_key_counts_as_vulnerabilities(self):
        p = self.reconcile_project()
        TrackedIssue.objects.create(project=p, asset=self.a, key='web.removed_check', source='check', severity=1)
        counts = scoring.category_issue_counts(p)
        self.assertEqual(counts['vulnerabilities']['open'], 4)
        self.assertEqual(sum(v['open'] for v in counts.values()), TrackedIssue.objects.filter(project=p, status='open').count())

    def test_exactly_one_category_matches_each_row(self):
        a = self.host('a.x.com')
        keys = [(k, 'check') for k in CHECKS] + [('CVE-1', 'finding'), ('web.removed_check', 'check')]
        for key, source in keys:
            row = TrackedIssue.objects.create(project=self.p, asset=a, key=key, source=source, severity=1)
            hits = [c for c in scoring.CATEGORIES if TrackedIssue.objects.filter(pk=row.pk).filter(scoring.category_q(c)).exists()]
            self.assertEqual(hits, [scoring.category_of(key)], key)

    def test_snapshot_shares_one_now(self):
        from unittest import mock
        self.reconcile_project()
        with mock.patch.object(scoring, 'category_scores', wraps=scoring.category_scores) as cs, \
                mock.patch.object(scoring, 'project_score', wraps=scoring.project_score) as ps:
            scoring.snapshot_scores()
        self.assertEqual(cs.call_args.args[1:] or cs.call_args.kwargs['now'], ps.call_args.args[1:] or ps.call_args.kwargs['now'])
