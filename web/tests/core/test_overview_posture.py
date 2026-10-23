from datetime import timedelta

from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.db import connection
from django.test import SimpleTestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.test import APIClient

from dashboard import posture
from dashboard.models import Project
from dashboard.stats import asm_stats
from dashboard.views import on_user_logged_in
from limes import scoring, waivers
from limes.alerts.issues import sync_issues
from startScan.models import Asset, ScoreSnapshot, Technology, TrackedIssue
from tests.core.test_category_scores import CategoryBase

HOSTILE = '<img src=x onerror=alert(1)>'


class PostureBase(CategoryBase):
    def ip(self, value, ports, ago=timedelta(0), **kw):
        enrichment = {'internetdb': {'ports': ports, 'fetched_at': (self.now - ago).isoformat()}}
        return Asset.objects.create(project=self.p, kind='ip', value=value, scope_tier=kw.pop('tier', 'owned_host'),
                                    enrichment=enrichment, **kw)

    def queries(self, fn):
        with CaptureQueriesContext(connection) as ctx:
            fn()
        return len(ctx)


class CategoryCardsTest(PostureBase):
    def test_category_cards_carry_counts_and_links(self):
        p = self.reconcile_project()
        cards = {c['key']: c for c in posture.category_cards(p, self.now)}
        self.assertEqual(list(cards), list(scoring.CATEGORIES))
        web = cards['web']
        self.assertEqual((web['label'], web['score'], web['grade'], web['open'], web['waived'], web['assessed']),
                         ('Website', 925, 'A', 1, 0, True))
        self.assertEqual((cards['network']['assessed'], cards['network']['score'], cards['network']['raw_score']),
                         (False, None, None))
        self.assertEqual(cards['network']['grade'], 'N/A')

    def test_category_change_needs_a_30_day_snapshot(self):
        p = self.reconcile_project()
        today = timezone.localtime(self.now).date()

        def deltas():
            return {c['key']: c['delta_30'] for c in posture.category_cards(p, self.now)}
        self.assertEqual(set(deltas().values()), {None})
        ScoreSnapshot.objects.create(project=p, date=today - timedelta(days=31), version='v', grade='A', categories=None)
        ScoreSnapshot.objects.create(project=p, date=today - timedelta(days=40), version='v', grade='A',
                                     categories={'web': 900, 'tls': None})
        ScoreSnapshot.objects.create(project=p, date=today - timedelta(days=10), version='v', grade='A',
                                     categories={'web': 100, 'tls': 100, 'vulnerabilities': 100})
        d = deltas()
        self.assertEqual(d['web'], 25)
        self.assertIsNone(d['tls'])
        self.assertIsNone(d['vulnerabilities'])

    def test_waived_only_project(self):
        s = self.scan()
        a = self.host('a.x.com')
        self.vuln(s, a, 3, template='cve-1')
        self.check(a, 'web.hsts_missing', 'fail')
        sync_issues(self.p, now=self.now)
        user = User.objects.create(username='u')
        for issue in TrackedIssue.objects.filter(project=self.p, status='open'):
            waivers.create_waiver(issue, 'accepted_risk', 'ok', user, now=self.now)
        cards = {c['key']: c for c in posture.category_cards(self.p, self.now)}
        for key in ('vulnerabilities', 'web'):
            c = cards[key]
            self.assertEqual((c['score'], c['open'], c['waived']), (950, 1, 1), key)
            self.assertLess(c['raw_score'], 950, key)
        self.assertEqual(scoring.project_score(self.p, self.now)['score'], 950)

    def test_nothing_assessed_is_explicit(self):
        self.host('a.x.com')
        for c in posture.category_cards(self.p, self.now):
            self.assertEqual((c['score'], c['assessed'], c['open'], c['delta_30']), (None, False, 0, None))


class ExposureTest(PostureBase):
    def test_exposure_from_fresh_internetdb(self):
        self.ip('1.2.3.4', [443, 3389])
        self.ip('1.2.3.5', [443])
        self.ip('1.2.3.6', [23], ago=timedelta(days=31))
        self.ip('1.2.3.7', [22], state='retired')
        self.ip('1.2.3.8', [21], tier='candidate')
        out = posture.exposure(self.p, self.now)
        self.assertEqual([(r['port'], r['service'], r['hosts'], r['risky'], r['severity'], r['check']) for r in out['rows']],
                         [(3389, 'rdp', 1, True, 'high', 'net.exposed_rdp'), (443, out['rows'][1]['service'], 2, False, None, None)])
        self.assertIsInstance(out['rows'][1]['service'], str)
        self.assertEqual((out['ports'], out['hosts']), (2, 2))

    def test_exposure_empty_and_limited(self):
        self.assertEqual(posture.exposure(self.p, self.now), {'rows': [], 'ports': 0, 'hosts': 0})
        self.ip('1.2.3.4', list(range(1000, 1030)) + [None, 'x', 70000, 22.0])
        out = posture.exposure(self.p, self.now)
        self.assertEqual((len(out['rows']), out['ports'], out['hosts']), (posture.EXPOSURE_LIMIT, 30, 1))

    def test_exposure_query_count_is_flat(self):
        self.ip('1.2.3.4', [443])
        one = self.queries(lambda: posture.exposure(self.p, self.now))
        for i in range(10):
            self.ip(f'2.2.2.{i}', [443, 22])
        self.assertEqual(self.queries(lambda: posture.exposure(self.p, self.now)), one)


class CertificatesTest(PostureBase):
    def cert(self, host, delta, check='tls.cert_expiring', status='pass', ago=timedelta(0), project=None):
        a = Asset.objects.create(project=project or self.p, kind='hostname', value=host, scope_tier='owned_host')
        self.check(a, check, status, ago=ago)
        from startScan.models import RiskCheck
        RiskCheck.objects.filter(asset=a, check_id=check).update(evidence={'not_after': (self.now + delta).isoformat()})
        return a

    def test_certificates_window_and_order(self):
        self.cert('b.x.com', timedelta(days=25))
        self.cert('a.x.com', timedelta(days=10, hours=1), status='fail')
        self.cert('c.x.com', timedelta(days=-2), check='tls.cert_expired', status='fail')
        self.cert('far.x.com', timedelta(days=40))
        self.cert('stale.x.com', timedelta(days=5), ago=timedelta(days=31))
        other = Project.objects.create(name='o', slug='o', insert_date=self.now)
        self.cert('o.y.com', timedelta(days=3), project=other)
        out = posture.certificates(self.p, self.now)
        self.assertEqual([(r['host'], r['days_left'], r['expired'], r['severity']) for r in out['rows']],
                         [('c.x.com', -2, True, 'high'), ('a.x.com', 10, False, 'medium'), ('b.x.com', 25, False, None)])
        self.assertEqual(out['total'], 3)
        self.assertEqual(out['rows'][1]['not_after'], self.now + timedelta(days=10, hours=1))

    def test_one_row_per_asset_earliest_and_limit(self):
        a = self.cert('a.x.com', timedelta(days=20))
        self.check(a, 'tls.cert_expired', 'pass')
        from startScan.models import RiskCheck
        RiskCheck.objects.filter(asset=a, check_id='tls.cert_expired').update(
            evidence={'not_after': (self.now + timedelta(days=5)).isoformat()})
        for i in range(12):
            self.cert(f'h{i}.x.com', timedelta(days=i + 1))
        out = posture.certificates(self.p, self.now)
        self.assertEqual((len(out['rows']), out['total']), (posture.CERT_LIMIT, 13))
        self.assertEqual(len([r for r in out['rows'] if r['host'] == 'a.x.com']), 1)

    def test_garbage_evidence_is_skipped(self):
        a = self.cert('a.x.com', timedelta(days=5))
        from startScan.models import RiskCheck
        RiskCheck.objects.filter(asset=a).update(evidence={'not_after': 'soon'})
        self.assertEqual(posture.certificates(self.p, self.now), {'rows': [], 'total': 0})

    def test_certificates_query_count_is_flat(self):
        self.cert('a.x.com', timedelta(days=5))
        one = self.queries(lambda: posture.certificates(self.p, self.now))
        for i in range(10):
            self.cert(f'h{i}.x.com', timedelta(days=i + 1))
        self.assertEqual(self.queries(lambda: posture.certificates(self.p, self.now)), one)


class TlsPassTest(SimpleTestCase):
    def test_tls_pass_keeps_not_after(self):
        from limes.checks import tls
        now = timezone.now()
        na = now + timedelta(days=25)
        res = {r.check: r for r in tls.evaluate({'cert': {'not_after': na, 'expired': False, 'hostname_ok': True,
                                                           'trusted': True}, 'legacy': {'TLSv1': False, 'TLSv1_1': False}}, now)}
        for cid in ('tls.cert_expiring', 'tls.cert_expired'):
            self.assertEqual((res[cid].status, res[cid].evidence), ('pass', {'not_after': na.isoformat()}), cid)


class TechnologiesTest(PostureBase):
    def tech(self, asset, *names):
        for n in names:
            asset.technologies.add(Technology.objects.create(name=n))

    def test_technologies_top_ten(self):
        assets = [self.host(f'h{i}.x.com') for i in range(4)]
        for i, a in enumerate(assets):
            self.tech(a, 'nginx')
            if i < 2:
                self.tech(a, 'php')
        self.tech(assets[0], *[f't{i:02d}' for i in range(11)])
        self.tech(self.host('c.x.com', tier='candidate'), 'only-candidate')
        self.tech(self.host('r.x.com', state='retired'), 'only-retired')
        Technology.objects.create(name=None)
        out = posture.technologies(self.p)
        self.assertEqual(len(out), 10)
        self.assertEqual(out[:2], [{'name': 'nginx', 'count': 4}, {'name': 'php', 'count': 2}])
        self.assertEqual(out[2], {'name': 't00', 'count': 1})
        self.assertEqual(sorted(o['name'] for o in out[2:]), sorted(f't{i:02d}' for i in range(8)))
        self.assertNotIn('only-candidate', [o['name'] for o in posture.technologies(self.p)])

    def test_technologies_empty_and_flat_queries(self):
        self.assertEqual(posture.technologies(self.p), [])
        self.tech(self.host('a.x.com'), 'nginx')
        one = self.queries(lambda: posture.technologies(self.p))
        for i in range(10):
            self.tech(self.host(f'h{i}.x.com'), f'n{i}')
        self.assertEqual(self.queries(lambda: posture.technologies(self.p)), one)

    def test_assets_api_filters_by_technology(self):
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        c = APIClient()
        c.force_login(User.objects.create_user('u', password='p'))
        a, b = self.host('a.x.com'), self.host('b.x.com')
        self.tech(a, 'nginx')
        self.tech(b, 'apache')
        a.technologies.add(Technology.objects.create(name='nginx'))  # a second row with the same name
        r = c.get('/api/listDatatableAsset/', {'project': 'p', 'technology': 'nginx', 'format': 'datatables'})
        body = r.json()
        self.assertEqual([x['value'] for x in body['data']], ['a.x.com'])
        self.assertEqual((body['recordsTotal'], body['recordsFiltered']), (1, 1))


class HostileNamesTest(PostureBase):
    def test_hostile_names_pass_through_unmodified(self):
        host = self.host(f'{HOSTILE}.x.com')
        self.check(host, 'tls.cert_expired', 'fail')
        from startScan.models import RiskCheck
        RiskCheck.objects.filter(asset=host).update(evidence={'not_after': (self.now + timedelta(days=3)).isoformat()})
        host.technologies.add(Technology.objects.create(name=HOSTILE))
        self.ip('1.2.3.4', [443])
        out = {'certs': posture.certificates(self.p, self.now), 'tech': posture.technologies(self.p),
               'cards': posture.category_cards(self.p, self.now), 'exp': posture.exposure(self.p, self.now)}
        self.assertEqual(out['certs']['rows'][0]['host'], f'{HOSTILE}.x.com')
        self.assertEqual(out['tech'][0]['name'], HOSTILE)

    def test_asm_stats_carries_the_cards(self):
        stats = asm_stats(self.p)
        self.assertEqual(stats['exposure'], {'rows': [], 'ports': 0, 'hosts': 0})
        self.assertEqual(stats['certificates'], {'rows': [], 'total': 0})
        self.assertEqual(stats['technologies'], [])
        self.assertEqual([c['key'] for c in stats['categories']], list(scoring.CATEGORIES))
