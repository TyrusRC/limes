from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test.utils import CaptureQueriesContext, override_settings
from django.urls import reverse

from dashboard import activity, posture
from dashboard.stats import asm_stats, invalidate
from dashboard.models import Project
from limes.alerts.issues import sync_issues
from limes.checks.catalogue import CHECKS
from startScan.models import (Asset, ChangeEvent, IssueWaiver, RiskCheck, ScoreSnapshot, Technology, TrackedIssue,
                              Vulnerability)
from tests.core.test_dashboard_stats import Base

X = '<img src=x onerror=alert(1)>'
ESCAPED = '&lt;img src=x onerror=alert(1)&gt;'
NEW_IDS = ('dash_what_changed', 'dash_categories', 'dash_brand', 'dash_exposure', 'dash_certs', 'dash_tech', 'dash_remediation',
           'dash_discovery', 'dash_coverage', 'dash_top_risks')


def section(html, id_):
    start = html.index(f'id="{id_}"')
    return html[start:html.index('</section>', start)]


class OverviewPageTest(Base):
    def setUp(self):
        super().setUp()
        from django.contrib.auth.signals import user_logged_in
        from dashboard.views import on_user_logged_in
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.client.force_login(User.objects.create_user('u', password='p'))

    def page(self, slug):
        self.client.get(f'/{slug}/dashboard/')  # warm-up (lazy prefs creation)
        r = self.client.get(f'/{slug}/dashboard/')
        self.assertEqual(r.status_code, 200)
        return r.content.decode()

    def check(self, asset, check_id, status, **kw):
        return RiskCheck.objects.create(asset=asset, check_id=check_id, status=status, severity=CHECKS[check_id].severity,
                                        last_checked=self.now, **kw)

    def ip(self, value, ports, project=None):
        return self.asset(value, kind='ip', project=project, last_resolved_at=self.now,
                          enrichment={'internetdb': {'ports': ports, 'fetched_at': self.now.isoformat()}})

    def issues_url(self, slug='p'):
        return reverse('issues', kwargs={'slug': slug})

    def test_page_order(self):
        html = self.page('p')
        order = ['dash_risk', 'score_trend', 'dash_what_changed', 'dash_categories', 'dash_tags', 'dash_brand', 'dash_inventory', 'dash_findings',
                 'dash_exposure', 'dash_certs', 'dash_tech', 'dash_remediation', 'dash_discovery', 'dash_coverage',
                 'dash_top_risks', 'dash_risky', 'dash_changes', 'dash_monitoring']
        at = [html.index(f'id="{i}"') for i in order]
        self.assertEqual(at, sorted(at))

    def test_category_cards_link_and_states(self):
        a, b = self.asset('a.x.com'), self.asset('b.x.com')
        self.check(a, 'web.hsts_missing', 'fail')
        self.check(b, 'web.hsts_missing', 'pass')
        sync_issues(self.p, now=self.now)
        html = section(self.page('p'), 'dash_categories')
        cards = {c['key']: c for c in posture.category_cards(self.p, self.now)}
        self.assertTrue(cards['web']['assessed'])
        self.assertFalse(cards['network']['assessed'])
        for key, c in cards.items():
            start = html.index(f'id="cat_{key}"')
            card = html[start:html.index('</a>', start)]
            self.assertIn(f'href="{self.issues_url()}?category={key}"', card)
            if c['assessed']:
                self.assertIn(f'ov-grade-{c["grade"].lower()}', card)
            elif c['provisional']:
                self.assertIn('Provisional, not scored', card)
                self.assertNotIn('ov-grade-', card)
            else:
                self.assertIn('Not assessed', card)
                self.assertNotIn('ov-grade-', card)
            if not c['provisional']:
                self.assertIn('No trend yet', card)  # no snapshot 30 days back

    def test_hostile_names_escaped_in_every_card(self):
        host = self.asset(X + '.x.com', sources=[{'source': 'crtsh'}], last_resolved_at=self.now)
        Vulnerability.objects.create(scan_history=self.scan(), asset=host, name=X, template_id=X, severity=3,
                                     open_status=True)
        self.check(host, 'tls.cert_expiring', 'fail', evidence={'not_after': (self.now + timedelta(days=5)).isoformat()})
        host.technologies.add(Technology.objects.create(name=X))
        self.ip('203.0.113.9', [22, 443])
        never = self.asset(X + '.y.x.com')
        Asset.objects.filter(pk=never.pk).update(first_seen=self.now - timedelta(days=100))
        Asset.objects.filter(pk=self.root.pk).update(last_resolved_at=self.now)
        sync_issues(self.p, now=self.now)
        html = self.page('p')
        self.assertNotIn(X, html)
        for id_, wants in [('dash_certs', 1), ('dash_tech', 1), ('dash_remediation', 2), ('dash_coverage', 1),
                           ('dash_top_risks', 2), ('dash_what_changed', 1)]:
            self.assertGreaterEqual(section(html, id_).count(ESCAPED), wants, id_)
        self.assertIn(f'{ESCAPED}.y.x.com', section(html, 'dash_coverage'))  # the never-checked host is the oldest
        for id_ in ('dash_categories', 'dash_exposure', 'dash_discovery'):
            self.assertIn('<h2', section(html, id_))
        self.assertIn('>22<', section(html, 'dash_exposure'))

    def test_overview_provisional_cards(self):
        a = self.asset('a.x.com')
        self.check(a, 'leak.supabase_secret_key', 'fail')
        TrackedIssue.objects.create(project=self.p, asset=a, key=X, source='check', severity=4)
        sync_issues(self.p, now=self.now)
        html = section(self.page('p'), 'dash_categories')
        for key in ('reputation', 'data_leakage'):
            start = html.index(f'id="cat_{key}"')
            card = html[start:html.index('</a>', start)]
            self.assertIn('Provisional, not scored', card)
            self.assertIn(f'?category={key}"', card)
            self.assertNotIn('ov-grade-', card)
        self.assertIn('1 open', html[html.index('id="cat_data_leakage"'):])
        self.assertNotIn(X, html)

    def test_empty_and_unassessed_states(self):
        Project.objects.create(name='e', slug='e', insert_date=self.now)
        html = self.page('e')
        for id_ in NEW_IDS:
            self.assertIn(f'id="{id_}"', html)
        for text in ('No open ports seen', 'No certificates expire in the next 30 days', 'No technologies detected',
                     'Nothing fixed or opened yet', 'No owned assets yet'):
            self.assertIn(text, html)
        self.assertEqual(section(html, 'dash_categories').count('Not assessed'), 6)
        self.assertNotIn('ov-gauge-value', html)

    def test_top_risks_link_to_the_risk_detail(self):
        a = self.asset('a.x.com', last_resolved_at=self.now)
        self.check(a, 'web.hsts_missing', 'fail')
        sync_issues(self.p, now=self.now)
        issue = TrackedIssue.objects.get(asset=a, key='web.hsts_missing')
        self.assertIn(f'href="/scan/p/issues/{issue.id}/"', section(self.page('p'), 'dash_top_risks'))

    def test_risky_ports_link_to_network_issues(self):
        self.ip('203.0.113.9', [3389])
        html = section(self.page('p'), 'dash_exposure')
        self.assertIn(f'href="{self.issues_url()}?category=network"', html)

    def test_what_changed_names_its_baseline_date(self):
        from startScan.models import ScoreSnapshot
        day = self.now.date() - timedelta(days=31)
        ScoreSnapshot.objects.create(project=self.p, date=day, version='v', grade='B', score=700)
        self.scan()  # x.com is assessed: today's score is 950
        html = section(self.page('p'), 'dash_what_changed')
        self.assertIn(f'datetime="{day.isoformat()}', html)
        self.assertIn('Score 700 → 950', html)

    def test_overview_links_show_the_counted_rows(self):
        """Discovery and technology counts equal the rows their Assets-page link lists."""
        Asset.objects.create(project=self.p, kind='hostname', value='ct.x.com', scope_tier='owned_host',
                             sources=[{'source': 'crtsh'}])
        Asset.objects.create(project=self.p, kind='hostname', value='ct-cand.x.com', scope_tier='candidate',
                             sources=[{'source': 'crtsh'}])
        Asset.objects.create(project=self.p, kind='hostname', value='ct-gone.x.com', scope_tier='owned_host',
                             state='retired', sources=[{'source': 'crtsh'}])
        Asset.objects.create(project=self.p, kind='hostname', value='hand.x.com', scope_tier='owned_host',
                             added_by=User.objects.get(username='u'))
        tech = Technology.objects.create(name='Apache HTTP Server 2.4 & co')
        for a in Asset.objects.filter(value__in=('ct.x.com', 'ct-cand.x.com', 'ct-gone.x.com')):
            a.technologies.add(tech)

        def listed(**q):
            r = self.client.get('/api/listDatatableAsset/', {'project': 'p', 'format': 'datatables', 'length': 100,
                                                            'scope_tier': 'owned', **q})
            return r.json()['recordsFiltered']
        rows = activity.discovery(self.p)['rows']
        self.assertTrue(rows)
        for r in rows:
            if r['filter']:
                self.assertEqual(listed(source=r['filter']), r['count'], r)
        for t in posture.technologies(self.p):
            self.assertEqual(listed(technology=t['name']), t['count'], t)
        html = self.page('p')
        self.assertIn('?technology=Apache%20HTTP%20Server%202.4%20%26%20co&amp;scope_tier=owned', html)
        self.assertIn('?source=manual&amp;scope_tier=owned', html)


OVERVIEW_QUERIES = 81  # a rise must be justified in review; the Tags card reads the top tags in one query (+1); merged: p3's Brand aggregate and feed states (+3) and p4's uncached Real-time card (+3), re-measured; -3 when the sidebar lost its wordlist, API vault and report permission checks; -8 (measured) when the legacy sidebar and quick-add permission checks went
WARM_QUERIES = 13  # a cached GET: session, project, prefs and page chrome, plus the Real-time card's three (it is never cached)


class OverviewPageBase(OverviewPageTest):
    def seed(self, project, n, tag='', domain='x.com'):
        """n hosts with a finding, a fresh check, a technology, sources and a tracked issue, plus n IPs with ports."""
        scan = self.scan(domain=domain)
        for i in range(n):
            h = self.asset(f'h{i}{tag}.x.com', project=project, sources=[{'source': 'crtsh'}, {'source': 'manual'}],
                           last_resolved_at=self.now)
            Vulnerability.objects.create(scan_history=scan, asset=h, name=f'v{i}{tag}', template_id=f't{i}{tag}', severity=3,
                                         open_status=True)
            self.check(h, 'web.hsts_missing', 'fail')
            h.technologies.add(Technology.objects.get_or_create(name=f'tech{i}{tag}')[0])
            self.ip(f'203.0.113.{i + 1}', [22, 443, 3389], project=project)


class OverviewBudgetTest(OverviewPageBase):
    def queries(self, n):
        self.seed(self.p, n)
        sync_issues(self.p, now=self.now)
        self.client.get('/p/dashboard/')  # warm-up (lazy prefs creation)
        cache.clear()
        with CaptureQueriesContext(connection) as ctx:
            self.assertEqual(self.client.get('/p/dashboard/').status_code, 200)
        return len(ctx)

    def test_page_queries_bounded(self):
        Asset.objects.filter(pk=self.root.pk).update(last_resolved_at=self.now)
        small = self.queries(3)
        for a in Asset.objects.filter(project=self.p).exclude(pk=self.root.pk):
            a.delete()  # same project, fresh seed at N=40 (the IP values are reused, so the first batch must go)
        large = self.queries(40)
        self.assertEqual(small, large)
        self.assertEqual(large, OVERVIEW_QUERIES)

    @override_settings(CERTSPOTTER_API_KEY='k' * 8)
    def test_page_queries_with_an_api_key(self):
        self.assertEqual(self.queries(3), OVERVIEW_QUERIES + 1)  # api.card: one query for the roots' poll times

    def test_warm_page_query_count(self):
        self.seed(self.p, 5)
        self.page('p')  # the second GET leaves the stats cache populated
        with self.assertNumQueries(WARM_QUERIES):
            self.client.get('/p/dashboard/')

    def test_second_load_is_cached(self):
        self.page('p')
        with mock.patch('dashboard.stats.asm_stats', wraps=asm_stats) as m:
            self.client.get('/p/dashboard/')
            self.assertEqual(m.call_count, 0)
            invalidate(self.p.id)
            self.client.get('/p/dashboard/')
            self.assertEqual(m.call_count, 1)


class OverviewScopeTest(OverviewPageBase):
    def test_no_cross_project_data(self):
        before = asm_stats(self.p)
        o = self.other
        ox = Asset.objects.get(project=o, kind='root_domain')
        self.seed(o, 4, tag='-ONLY-IN-O', domain='y.com')
        for t in Technology.objects.filter(name__startswith='tech'):
            t.name = 'ONLY-IN-O ' + t.name
            t.save()
        sync_issues(o, now=self.now)
        for i in TrackedIssue.objects.filter(project=o)[:2]:
            IssueWaiver.objects.create(issue=i, kind='accepted_risk', reason='r')
        TrackedIssue.objects.filter(project=o).update(reopened=1, reopened_at=self.now - timedelta(days=2))
        self.check(ox, 'tls.cert_expiring', 'fail', evidence={'not_after': (self.now + timedelta(days=5)).isoformat()})
        ChangeEvent.objects.create(project=o, kind='issue_new', title='ONLY-IN-O event', asset=ox, severity=4)
        for d in (1, 40):
            ScoreSnapshot.objects.create(project=o, date=(self.now - timedelta(days=d)).date(), version='v', grade='B',
                                         score=700, categories={'web': 600})
        Asset.objects.filter(project=o).update(last_resolved_at=self.now)
        cache.clear()
        self.assertEqual(asm_stats(self.p), before)
        self.assertNotIn('ONLY-IN-O', self.page('p'))
