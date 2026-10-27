from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from rolepermissions.roles import assign_role

from dashboard.views import on_user_logged_in
from limes import portfolios, scoring, subsidiaries
from limes.mcp import registry
from startScan.models import Asset, Portfolio, Subsidiary, Tag, TrackedIssue, Vulnerability
from tests.core.mcp_base import McpBase
from tests.core.test_dashboard_stats import Base

XSS = '<script>alert(1)</script>'


class SubBase(Base):
    def setUp(self):
        super().setUp()
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.admin = User.objects.create_user('adm', password='p')
        assign_role(self.admin, 'sys_admin')
        self.auditor = User.objects.create_user('aud', password='p')
        assign_role(self.auditor, 'auditor')
        self.client.force_login(self.admin)
        self.s = self.scan()
        self.n = 0

    def host(self, sev=None, project=None, parent=None):
        self.n += 1
        a = self.asset(f'h{self.n}.x.com', project=project, parent=parent)
        if sev:
            Vulnerability.objects.create(scan_history=self.s, asset=a, name=f'v{self.n}', template_id=f't{self.n}',
                                         severity=sev, open_status=True)
            TrackedIssue.objects.create(project=a.project, asset=a, key=f'k{self.n}', source='finding', severity=sev)
        return a

    def post(self, url, body, user=None):
        return self.client.post(url, body, content_type='application/json')

    def mk(self, name, *assets, project=None):
        sub = Subsidiary.objects.create(project=project or self.p, name=name)
        Asset.objects.filter(id__in=[a.id for a in assets]).update(subsidiary=sub)
        return sub


class ScoreTest(SubBase):
    def test_own_score_and_the_headline_is_bit_identical(self):
        a, b = self.host(4), self.host(3)
        clean = self.host()
        for _ in range(3):
            self.host()
        before = scoring.project_score(self.p, self.now)
        sub = self.mk('Acme EU', a)
        self.mk('Clean Co', clean)
        after = scoring.project_score(self.p, self.now)
        self.assertEqual(before, after)  # every key, top penalties included
        rows = {r['name']: r for r in subsidiaries.scores(self.p, self.now)}
        self.assertEqual((rows['Acme EU']['score'], rows['Acme EU']['grade'], rows['Acme EU']['open']), (599, 'C', 1))
        self.assertEqual(rows['Clean Co']['score'], 950)
        self.assertEqual(rows['Acme EU']['id'], sub.id)

    def test_hosts_follow_their_root_and_the_nearest_assignment_wins(self):
        h1, h2 = self.host(3, parent=self.root), self.host(parent=self.root)
        self.mk('Root Co', self.root)
        mine = self.mk('Own Co', h2)
        mem = subsidiaries.members(self.p)[0]
        root_sub = Subsidiary.objects.get(name='Root Co')
        self.assertEqual(mem[root_sub.id], {self.root.id, h1.id})
        self.assertEqual(mem[mine.id], {h2.id})

    def test_scores_are_per_project(self):
        self.mk('Other Co', project=self.other)
        self.assertEqual(subsidiaries.scores(self.p, self.now), [])
        self.assertEqual(self.client.get('/api/subsidiaries/', {'project': 'p'}).json(), [])


class ApiTest(SubBase):
    def test_scoping_and_permissions(self):
        mine, theirs = self.host(), self.host(project=self.other)
        self.assertEqual(self.post('/api/subsidiaries/', {'project': 'p', 'name': 'A'}).status_code, 201)
        self.assertEqual(self.post('/api/subsidiaries/', {'project': 'p', 'name': 'A'}).status_code, 400)
        self.assertEqual(self.post('/api/subsidiaries/', {'project': 'nope', 'name': 'A'}).status_code, 404)
        self.mk('OnlyOther', project=self.other)
        r = self.client.delete('/api/subsidiaries/?project=p&name=OnlyOther')
        self.assertEqual(r.status_code, 404)
        self.assertTrue(Subsidiary.objects.filter(name='OnlyOther').exists())
        # a foreign asset fails the whole call and changes nothing
        r = self.post('/api/action/asset/subsidiary/', {'project': 'p', 'subsidiary': 'A', 'assets': [mine.id, theirs.id]})
        self.assertEqual(r.status_code, 404)
        self.assertIsNone(Asset.objects.get(pk=mine.pk).subsidiary_id)
        r = self.post('/api/action/asset/subsidiary/', {'project': 'p', 'subsidiary': 'OnlyOther', 'assets': [mine.id]})
        self.assertEqual(r.status_code, 404)
        r = self.post('/api/action/asset/subsidiary/', {'project': 'p', 'subsidiary': 'A', 'assets': [mine.id]})
        self.assertEqual(r.json()['assets'], 1)
        self.assertEqual(self.client.get('/api/subsidiaries/', {'project': 'p'}).json()[0]['name'], 'A')
        self.client.force_login(self.auditor)  # reading is open, writing is not
        self.assertEqual(self.client.get('/api/subsidiaries/', {'project': 'p'}).status_code, 200)
        self.assertEqual(self.post('/api/subsidiaries/', {'project': 'p', 'name': 'B'}).status_code, 403)
        self.assertEqual(self.client.delete('/api/subsidiaries/?project=p&name=A').status_code, 403)
        self.client.force_login(self.admin)
        self.assertEqual(self.client.delete('/api/subsidiaries/?project=p&name=A').status_code, 200)
        self.assertIsNone(Asset.objects.get(pk=mine.pk).subsidiary_id)  # back to the organization

    def test_issue_list_toggle_and_filter(self):
        a, b = self.host(3), self.host(2)
        self.mk('A', a)
        names = lambda **q: {i['asset'] for i in self.client.get('/api/issues/', {'project': 'p', **q}).json()}
        self.assertEqual(names(), {a.value, b.value})
        self.assertEqual(names(subsidiaries='false'), {b.value})
        self.assertEqual(names(subsidiary='A'), {a.value})
        self.assertEqual(names(subsidiary='Nope'), set())


class PortfolioTest(SubBase):
    def setUp(self):
        super().setUp()
        self.a, self.b, self.c = self.host(3), self.host(2), self.host(1)
        self.sub = self.mk('A', self.a, self.b)
        t = Tag.objects.create(project=self.p, name='prod')
        self.b.tags.add(t)
        self.c.tags.add(t)

    def test_rule_is_tags_and_subsidiary_plus_picks(self):
        p = portfolios.create(self.p, 'Prod in A', ['Prod'], 'A')
        self.assertEqual(portfolios.asset_ids(self.p, p), {self.b.id})
        p2 = portfolios.create(self.p, 'Tag only', ['prod'])
        self.assertEqual(portfolios.asset_ids(self.p, p2), {self.b.id, self.c.id})
        p3 = portfolios.create(self.p, 'Picks', assets=[self.a.id])
        self.assertEqual(portfolios.asset_ids(self.p, p3), {self.a.id})
        with self.assertRaises(portfolios.PortfolioError):
            portfolios.create(self.p, 'Empty')
        with self.assertRaises(portfolios.NotFound):
            portfolios.create(self.p, 'Foreign', assets=[self.host(project=self.other).id])

    def test_selection_filters_issues_assets_and_exports(self):
        p = portfolios.create(self.p, 'Prod', ['prod'])
        theirs = Portfolio.objects.create(project=self.other, name='Theirs')
        r = self.post('/api/action/portfolio/select/', {'project': 'p', 'portfolio': theirs.id})
        self.assertEqual(r.status_code, 404)  # another project's portfolio cannot be selected
        self.assertEqual(self.client.get('/api/issues/', {'project': 'p'}).json().__len__(), 3)
        self.assertEqual(self.post('/api/action/portfolio/select/', {'project': 'p', 'portfolio': p.id}).status_code, 200)
        issues = self.client.get('/api/issues/', {'project': 'p'}).json()
        self.assertEqual({i['asset'] for i in issues}, {self.b.value, self.c.value})
        assets = self.client.get('/api/listDatatableAsset/', {'project': 'p', 'no_page': '1'}).json()
        self.assertEqual({r['value'] for r in assets}, {self.b.value, self.c.value})
        csv = self.client.get('/p/reports/export/assets.csv').content.decode()
        self.assertIn(self.b.value, csv)
        self.assertNotIn(self.a.value, csv)
        self.assertNotIn(self.a.value, self.client.get('/p/reports/export/issues.csv').content.decode())
        # the selection is per project and re-validated: deleting the portfolio drops it
        self.assertEqual(len(self.client.get('/api/issues/', {'project': 'o'}).json()), 0)
        p.delete()
        self.assertEqual(len(self.client.get('/api/issues/', {'project': 'p'}).json()), 3)

    def test_overview_limits_findings_not_the_headline(self):
        before = self.client.get('/p/dashboard/').context['risk']['score']
        p = portfolios.create(self.p, 'Prod', ['prod'])
        self.post('/api/action/portfolio/select/', {'project': 'p', 'portfolio': p.id})
        ctx = self.client.get('/p/dashboard/').context
        self.assertEqual(ctx['risk']['score'], before)
        self.assertEqual(ctx['portfolio_card']['assets'], 2)
        self.assertEqual(ctx['findings']['high'], 0)  # a (high) is outside the portfolio
        self.assertEqual(ctx['findings']['medium'], 1)

    def test_rest_crud_is_project_scoped(self):
        r = self.post('/api/portfolios/', {'project': 'p', 'name': 'N', 'subsidiary': 'Missing'})
        self.assertEqual(r.status_code, 404)
        r = self.post('/api/portfolios/', {'project': 'p', 'name': 'N', 'tags': ['prod']})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(self.client.get('/api/portfolios/', {'project': 'p'}).json()[0]['tags'], ['prod'])
        self.assertEqual(self.client.get('/api/portfolios/', {'project': 'o'}).json(), [])
        other = Portfolio.objects.create(project=self.other, name='X')
        self.assertEqual(self.client.delete(f'/api/portfolios/?project=p&id={other.id}').status_code, 404)
        self.client.force_login(self.auditor)
        self.assertEqual(self.client.delete(f'/api/portfolios/?project=p&id={r.json()["id"]}').status_code, 403)


class EscapingTest(SubBase):
    def test_names_are_escaped_everywhere_they_render(self):
        a = self.host(3)
        self.mk(XSS, a)
        p = portfolios.create(self.p, XSS + 'pf', subsidiary=XSS)
        self.post('/api/action/portfolio/select/', {'project': 'p', 'portfolio': p.id})
        html = self.client.get('/p/dashboard/').content.decode()
        self.assertNotIn(XSS, html)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', html)
        self.assertIn('id="portfolio_menu"', html)
        self.assertNotIn(XSS, self.client.get('/p/issues/').content.decode())


class McpTest(McpBase):
    def test_read_tools_are_scoped_read_only_and_untrusted(self):
        registry.load_tools()
        for n in ('list_subsidiaries', 'list_portfolios'):
            self.assertTrue(registry.annotations(registry.REGISTRY[n])['readOnlyHint'])
            self.assertEqual(self.err(self.call(n, project='nope')), 'not_found')
        Subsidiary.objects.create(project=self.p2, name='Hidden')
        Subsidiary.objects.create(project=self.p1, name=XSS)
        items = self.data(self.call('list_subsidiaries', project='p1'))['items']
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['score'], None)
        self.assertNotIn(XSS, self.outside_untrusted(items))
