import os
import re
from datetime import timedelta

from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from dashboard import posture
from dashboard.stats import asm_stats
from dashboard.views import on_user_logged_in
from limes.feeds import sources
from limes.lookalike import report
from startScan.models import Asset, CveIntel, DomainBreach, FeedState, Lookalike, TrackedIssue
from tests.core.test_dashboard_stats import Base
from tests.core.test_overview_page import ESCAPED, X, section

WEB = os.path.join(os.path.dirname(__file__), '..', '..')


class LookalikeBase(Base):
    def setUp(self):
        super().setUp()
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.admin = User.objects.create_user('adm', password='p', email='adm@example.test')
        assign_role(self.admin, 'sys_admin')
        self.auditor = User.objects.create_user('aud', password='p')
        assign_role(self.auditor, 'auditor')
        self.c = APIClient()
        self.c.force_login(self.admin)
        self.dash = reverse('dashboardIndex', kwargs={'slug': 'p'})
        self.other_root = Asset.objects.get(project=self.other, value='y.com')

    def lk(self, domain, project=None, root=None, **kw):
        kw.setdefault('unicode', domain)
        kw.setdefault('status', 'registered')
        kw.setdefault('registered', True)
        return Lookalike.objects.create(project=project or self.p, root=root or self.root, domain=domain, source='permutation', **kw)

    def created(self, days):
        return {'registrar': 'Reg', 'created': (self.now - timedelta(days=days)).isoformat(), 'abuse_email': 'abuse@reg.example'}


class ListApiTest(LookalikeBase):
    def get(self, **q):
        r = self.c.get('/api/lookalikes/', {'project': 'p', **q})
        self.assertEqual(r.status_code, 200)
        return r.json()

    def test_list_scoped_and_filtered(self):
        self.lk('a-x.com', has_mx=True, rdap=self.created(3))
        self.lk('b-x.com', status='watching', rdap=self.created(400))
        self.lk('c-x.com', registered=False, status='unregistered')
        self.lk('other-y.com', project=self.other, root=self.other_root, has_mx=True, rdap=self.created(1))
        names = lambda **q: sorted(r['domain'] for r in self.get(**q)['results'])
        self.assertEqual(names(), ['a-x.com', 'b-x.com', 'c-x.com'])
        self.assertEqual(names(registered='true'), ['a-x.com', 'b-x.com'])
        self.assertEqual(names(registered='false'), ['c-x.com'])
        self.assertEqual(names(mx='true'), ['a-x.com'])
        self.assertEqual(names(young='true'), ['a-x.com'])
        self.assertEqual(names(status='watching'), ['b-x.com'])
        for junk in ('<script>', 'maybe', ''):  # unknown values are ignored, not errors
            self.assertEqual(names(status=junk, registered=junk, mx=junk, young=junk), ['a-x.com', 'b-x.com', 'c-x.com'])
        row = next(r for r in self.get()['results'] if r['domain'] == 'a-x.com')
        self.assertEqual((row['age_days'], row['registrar'], row['root'], row['idn'], row['has_mx']), (3, 'Reg', 'x.com', False, True))
        meta = self.get()['meta']
        self.assertEqual((meta['enabled'], meta['credit']), (True, 'Certificate data: crt.sh · Registration data: RDAP'))
        self.assertEqual(self.c.get('/api/lookalikes/', {'project': 'zzz'}).json()['results'], [])

    def test_hostile_rdap_stays_json_text_and_stray_created_cannot_break_filter(self):
        self.lk('a-x.com', rdap={'registrar': X, 'created': X})
        got = self.get(young='true')  # the cast only sees the shape rdap.parse writes
        self.assertEqual(got['results'], [])
        self.assertEqual(self.get()['results'][0]['registrar'], X)
        self.assertIsNone(self.get()['results'][0]['age_days'])


class DecideApiTest(LookalikeBase):
    def post(self, path, client=None, **body):
        return (client or self.c).post(f'/api/action/lookalike/{path}/', {'project': 'p', **body}, format='json')

    def test_decisions_audited(self):
        row = self.lk('a-x.com')
        r = self.post('decide', id=row.id, decision='watch', note='n' * 2000).json()
        row.refresh_from_db()
        self.assertEqual((r['status'], row.status, row.decided_by, len(row.note)), (True, 'watching', self.admin, 1000))
        self.assertIsNotNone(row.decided_at)
        self.assertEqual(self.post('decide', id=row.id, decision='delete').json()['status'], False)
        self.assertEqual(self.post('decide', id='x', decision='watch').json()['status'], False)
        # no PERM_MODIFY_TARGETS: refused, nothing changes
        denied = APIClient()
        denied.force_login(self.auditor)
        r = self.post('decide', client=denied, id=row.id, decision='ignore')
        row.refresh_from_db()
        self.assertEqual((r.status_code, row.status), (403, 'watching'))
        # an id of another project is not found, and does not change
        foreign = self.lk('other-y.com', project=self.other, root=self.other_root)
        r = self.post('decide', id=foreign.id, decision='ignore').json()
        foreign.refresh_from_db()
        self.assertEqual((r['status'], foreign.status, foreign.decided_by), (False, 'registered', None))

    def test_ours_never_creates_asset(self):
        row = self.lk('xn--exmple-cua.com', unicode='exämple.com')
        before = Asset.objects.count()
        r = self.post('decide', id=row.id, decision='ours').json()
        row.refresh_from_db()
        self.assertTrue(r['add_url'].endswith('?add=xn--exmple-cua.com'), r)
        self.assertEqual(r['add_url'], reverse('assets', kwargs={'slug': 'p'}) + '?add=xn--exmple-cua.com')
        self.assertEqual((Asset.objects.count(), row.status, row.decided_by), (before, 'registered', self.admin))  # nothing yet
        # the status flips only when the user confirms the add
        r = self.c.post('/api/add/assets/', {'project': 'p', 'entries': 'xn--exmple-cua.com'}, format='json').json()
        row.refresh_from_db()
        self.assertEqual((r['status'], row.status), (True, 'ours'))
        from limes.lookalike import check
        self.assertEqual(check.due_rows(self.now + timedelta(days=400), 50), [])  # never due again

    def test_report_sets_reported(self):
        row = self.lk('a-x.com', rdap=self.created(2), dns={'ns': ['ns.a.example'], 'a': ['198.51.100.1']})
        r = self.post('report', id=row.id).json()
        row.refresh_from_db()
        want = report.abuse_report(row, self.admin)
        self.assertEqual((r['to'], r['subject'], r['body']), (want['to'], want['subject'], want['body']))
        self.assertEqual((row.status, row.decided_by, r['to']), ('reported', self.admin, 'abuse@reg.example'))
        self.assertIsNotNone(row.reported_at)
        foreign = self.lk('other-y.com', project=self.other, root=self.other_root)
        self.assertFalse(self.post('report', id=foreign.id).json()['status'])
        denied = APIClient()
        denied.force_login(self.auditor)
        self.assertEqual(self.post('report', client=denied, id=row.id).status_code, 403)


class PageTest(LookalikeBase):
    def test_page_renders_no_domain_server_side(self):
        self.lk('xn--exmple-cua.com', unicode='exämple.com', rdap={'registrar': X})
        self.lk(X + '.com')
        r = self.c.get(reverse('lookalikes', kwargs={'slug': 'p'}))
        self.assertEqual(r.status_code, 200)
        html = r.content.decode()
        for needle in ('xn--exmple-cua.com', 'exämple.com', 'onerror', X):
            self.assertNotIn(needle, html)
        for el in ('lk_table', 'lk_f_status', 'lk_f_registered', 'lk_f_mx', 'lk_f_young', 'lk_report', 'lk_copy'):
            self.assertIn(f'id="{el}"', html)
        self.assertRegex(html, r'<textarea id="lk_report"[^>]*\breadonly\b')
        self.assertIn(reverse('lookalikes', kwargs={'slug': 'p'}), self.c.get(self.dash).content.decode())  # the sidebar link

    def test_script_builds_no_html_and_no_link(self):
        with open(os.path.join(WEB, 'static/custom/lookalikes.js')) as f:
            js = f.read()
        for bad in ('innerHTML', '.html(', 'insertAdjacentHTML', 'outerHTML', 'href', 'document.write', 'eval('):
            self.assertNotIn(bad, js)
        self.assertIn('navigator.clipboard.writeText', js)
        with open(os.path.join(WEB, 'startScan/templates/startScan/assets.html')) as f:
            self.assertRegex(f.read(), r"getElementById\('asset_entries'\)\.value = addValue")  # ?add= is text, never HTML


class BrandTest(LookalikeBase):
    def seed(self):
        self.lk('a-x.com', has_mx=True, rdap=self.created(5))                       # new, phishing-ready, awaiting
        self.lk('b-x.com', status='watching', rdap=self.created(400), ct={'count': 2})  # phishing-ready
        self.lk('c-x.com', status='reported')                                       # registered, no RDAP, first seen long ago
        Lookalike.objects.filter(domain='c-x.com').update(first_seen=self.now - timedelta(days=100))
        self.lk('d-x.com', status='ignored', has_mx=True, rdap=self.created(1))     # left out
        self.lk('e-x.com', status='gone', registered=False, has_mx=True, rdap=self.created(1))
        self.lk('f-x.com', status='ours', has_mx=True, rdap=self.created(1))
        self.lk('g-x.com', status='unregistered', registered=False)
        self.lk('other-y.com', project=self.other, root=self.other_root, has_mx=True, rdap=self.created(1))

    def test_brand_card_counts(self):
        self.seed()
        want = {'enabled': True, 'registered': 3, 'new_30': 1, 'phishing_ready': 2, 'awaiting': 1, 'tracked': 7}
        self.assertEqual(posture.brand(self.p, self.now), want)
        self.assertEqual(asm_stats(self.p)['brand'], want)
        self.c.get(self.dash)
        html = section(self.c.get(self.dash).content.decode(), 'dash_brand')
        self.assertIn(reverse('lookalikes', kwargs={'slug': 'p'}), html)
        for label, n in (('Registered', 3), ('New in 30 days', 1), ('Phishing-ready', 2), ('Awaiting review', 1)):
            self.assertRegex(html, rf'{label}</div><div class="ov-stat-value">{n}<')

    @override_settings(LOOKALIKE_ENABLED=False)
    def test_brand_card_off(self):
        self.c.get(self.dash)
        html = section(self.c.get(self.dash).content.decode(), 'dash_brand')
        self.assertIn('Lookalike monitoring is off', html)
        self.assertFalse(posture.brand(self.p, self.now)['enabled'])


class AttributionTest(LookalikeBase):
    def test_data_sources_footnote_dates_and_marks_stale(self):
        FeedState.objects.create(name='kev', url='u', last_good_at=self.now - timedelta(hours=2))
        FeedState.objects.create(name='drop_v4', url='u', last_good_at=self.now - timedelta(days=9))  # 3 x 1 day: stale
        rows = {r['name']: r for r in posture.data_sources(self.now)}
        self.assertNotIn('blocklist_de', rows)  # opt-in and off
        self.assertEqual((rows['kev']['stale'], rows['drop_v4']['stale'], rows['feodo']['last_good_at']), (False, True, None))
        self.assertTrue(all(r['credit'] and r['terms'].startswith('https://') for r in rows.values()))
        self.c.get(self.dash)
        html = section(self.c.get(self.dash).content.decode(), 'dash_categories')
        foot = html[html.index('id="dash_sources"'):]
        for feed in (sources.FEEDS[n] for n in rows):
            self.assertIn(feed.credit.replace('&', '&amp;'), foot)
        self.assertRegex(foot, r'drop_v4 \d{4}-\d\d-\d\d <span class="ov-tag ov-stale">stale</span>')
        self.assertRegex(foot, r'kev \d{4}-\d\d-\d\d(?! <span class="ov-tag ov-stale")')
        self.assertEqual(foot.count('ov-stale">stale'), 1)

    def test_other_surfaces_carry_their_credit(self):
        ip = Asset.objects.create(project=self.p, kind='ip', value='203.0.113.7', scope_tier='owned_host')
        from startScan.models import RiskCheck
        from limes.checks.catalogue import CHECKS
        RiskCheck.objects.create(asset=ip, check_id='rep.listed_drop', status='fail', severity=CHECKS['rep.listed_drop'].severity,
                                 last_checked=self.now, evidence={'entries': [{'feed': 'drop_v4', 'credit': sources.FEEDS['drop_v4'].credit}]})
        detail = self.c.get(f'/api/listDatatableAsset/{ip.id}/?project=p').json()
        self.assertIn('The Spamhaus Project', str(detail['risk_checks']))
        page = self.c.get(reverse('issues', kwargs={'slug': 'p'})).content.decode()
        self.assertIn('CISA KEV (CC0)', page)
        self.assertIn('EPSS by FIRST.org / Empirical Security', page)
        DomainBreach.objects.create(project=self.p, root=self.root, breach_name='Adobe', addresses=3)
        self.assertEqual(self.c.get(f'/api/listDatatableAsset/{self.root.id}/?project=p').json()['breaches'][0]['name'], 'Adobe')
        with open(os.path.join(WEB, 'static/custom/asset.js')) as f:
            self.assertIn('Have I Been Pwned</a>', f.read())
