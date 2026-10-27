import json
import pathlib
import re
from unittest import mock
from urllib.parse import urlsplit

import requests
from django.core.cache import cache
from django.test import SimpleTestCase

from limes import api_discovery as ad, continuous, monitor, safe_fetch, scope, scoring
from limes.alerts.issues import sync_issues
from limes.checks.catalogue import PROVISIONAL
from limes.scan_target import ensure_scan_target
from startScan.models import Asset, IpAddress, RiskCheck, TrackedIssue
from targetApp.models import Domain
from tests.core.mcp_base import McpBase
from tests.core.test_dashboard_stats import Base

WEB = pathlib.Path(__file__).resolve().parents[2]
HOSTILE = '<img src=x onerror=alert(1)>'


class Resp:
    def __init__(self, status, body=b''):
        self.status_code, self.body = status, body

    def iter_content(self, chunk_size=8192):
        for i in range(0, len(self.body), chunk_size):
            yield self.body[i:i + chunk_size]

    def close(self):
        pass


class FakeWeb:
    """A fake safe_fetch.pinned_get: one getter per host, GET only, refuses URLs on other hosts like the real one."""
    def __init__(self):
        self.routes, self.calls, self.made = {}, [], []

    def serve(self, host, path, doc, status=200):
        body = doc if isinstance(doc, bytes) else json.dumps(doc).encode()
        self.routes[(host, path)] = (status, body)

    def make_get(self, host, deadline=None):
        self.made.append(host)
        self.deadlines = getattr(self, 'deadlines', []) + [deadline]

        def get(url, **kw):
            assert set(kw) <= {'headers', 'timeout', 'allow_redirects', 'stream'}, kw
            assert kw.get('allow_redirects') is False
            parts = urlsplit(url)
            if parts.hostname != host:
                raise requests.exceptions.InvalidURL('not on host')
            self.calls.append((parts.hostname, parts.path))
            return Resp(*self.routes.get((host, parts.path), (404, b'')))
        return get

    def hosts_called(self):
        return {h for h, _ in self.calls}

    def count(self, host=None, prefix=''):
        return sum(1 for h, p in self.calls if (host is None or h == host) and p.startswith(prefix))


def oas3(servers, paths=None, secure=True, title='Pay API'):
    doc = {'openapi': '3.0.1', 'info': {'title': title, 'version': '1.2'}, 'servers': servers,
           'paths': paths or {'/users': {'get': {}, 'post': {}}, '/users/{id}': {'get': {}}, '/health': {'get': {}}}}
    if secure:
        doc['components'] = {'securitySchemes': {'bearer': {'type': 'http', 'scheme': 'bearer'}}}
    return doc


class DiscoveryBase(Base):
    def setUp(self):
        super().setUp()
        cache.clear()
        self.web = FakeWeb()
        self.n = 0

    def host(self, name, tier='owned_host', ip='8.8.8.8', authorized=False, **kw):
        a = self.asset(name, tier=tier, http_status=200, active_authorized=authorized, **kw)
        a.ip_addresses.add(IpAddress.objects.get_or_create(address=ip)[0])
        return a

    def run_discovery(self, **kw):
        return ad.discover(self.p, self.root, self.now, make_get=self.web.make_get, **kw)

    def apis(self, project=None):
        return {a.value: a for a in Asset.objects.filter(project=project or self.p, kind='api')}

    def check(self, asset, check_id):
        return RiskCheck.objects.get(asset=asset, check_id=check_id)


class DiscoveryTest(DiscoveryBase):
    def test_documents_become_assets_with_provisional_checks(self):
        parent = self.host('a.x.com')
        self.host('b.x.com')
        self.host('c.x.com')
        self.host('d.x.com')
        self.host('e.x.com')
        self.host('f.x.com')
        cand = self.host('cand.x.com', tier='candidate')
        brand = self.host('brand.x.com', tier='co_brand', authorized=False)
        # a: OpenAPI 3, relative + same-host absolute + another host's server
        self.web.serve('a.x.com', '/openapi.json', oas3([{'url': '/v1'}, {'url': 'HTTPS://A.x.com:8443/v2/?q=1#f'},
                                                         {'url': 'https://evil.example/v1'}]))
        self.web.serve('a.x.com', '/docs', b'<html>docs</html>')
        # b: Swagger 2 without any security definition
        self.web.serve('b.x.com', '/swagger.json', {'swagger': '2.0', 'info': {'title': 'Old', 'version': '0.1'},
                                                    'host': 'b.x.com', 'basePath': '/legacy', 'schemes': ['https'],
                                                    'paths': {'/ping': {'get': {}}}})
        # c: oversized body, d: invalid JSON, e: servers only elsewhere, f: GraphQL
        self.web.serve('c.x.com', '/openapi.json', b'{"openapi":"3.0.0","paths":{},"pad":"' + b'x' * (ad.BODY_CAP + 10) + b'"}')
        self.web.serve('d.x.com', '/openapi.json', b'{"openapi": "3.0.0", "paths": {')
        self.web.serve('e.x.com', '/openapi.json', oas3([{'url': 'https://other.example/api'}]))
        self.web.serve('f.x.com', '/graphql', {'errors': [{'message': 'Must provide query string.'}]}, status=400)
        counts = self.run_discovery()
        apis = self.apis()
        self.assertEqual(set(apis), {
            'https://a.x.com/v1', 'https://a.x.com:8443/v2', 'https://b.x.com/legacy', 'https://e.x.com',
            'https://f.x.com/graphql'})
        self.assertEqual(counts['apis'], 5)
        # scope guard: the other host's server is evidence text only, never an asset or a request
        self.assertNotIn('evil.example', ''.join(apis))
        self.assertEqual(apis['https://a.x.com/v1'].enrichment['other_servers'], ['https://evil.example/v1'])
        self.assertEqual(apis['https://e.x.com'].enrichment['other_servers'], ['https://other.example/api'])
        self.assertEqual(self.web.hosts_called(), {'a.x.com', 'b.x.com', 'c.x.com', 'd.x.com', 'e.x.com', 'f.x.com'})
        self.assertEqual(sorted(self.web.made), ['a.x.com', 'b.x.com', 'c.x.com', 'd.x.com', 'e.x.com', 'f.x.com'])
        a = apis['https://a.x.com/v1']
        self.assertEqual((a.parent, a.scope_tier, a.sources[0]['source']), (parent, 'owned_host', 'api_discovery'))
        self.assertEqual(a.enrichment, {
            'spec_url': 'https://a.x.com/openapi.json', 'title': 'Pay API', 'version': '1.2', 'endpoints': 3,
            'methods': ['GET', 'POST'], 'auth_schemes': ['http:bearer'], 'other_servers': ['https://evil.example/v1'],
            'docs_ui': [{'path': '/docs', 'status': 200, 'size': 17}]})
        # checks: a documented + secured; b documented without security
        self.assertEqual({c: self.check(a, c).status for c in ('api.exposed_docs', 'api.no_auth_declared')},
                         {'api.exposed_docs': 'fail', 'api.no_auth_declared': 'pass'})
        size = len(self.web.routes[('a.x.com', '/openapi.json')][1])
        self.assertEqual(self.check(a, 'api.exposed_docs').evidence, {'path': '/openapi.json', 'status': 200, 'size': size})
        b = apis['https://b.x.com/legacy']
        self.assertEqual([self.check(b, c).status for c in ('api.exposed_docs', 'api.no_auth_declared', 'api.unauthenticated_access')],
                         ['fail', 'fail', 'not_applicable'])
        g = apis['https://f.x.com/graphql']
        self.assertEqual(g.enrichment['protocol'], 'graphql')
        self.assertEqual({r.status for r in RiskCheck.objects.filter(asset=g)}, {'not_applicable'})
        # nothing for the oversized body, the broken JSON, the candidate or the unauthorised co-brand host
        self.assertNotIn(ad.canonical('/', 'c.x.com')[1], apis)
        self.assertFalse(any(v.startswith(('https://c.x.com', 'https://d.x.com')) for v in apis))
        self.assertEqual(self.web.count('cand.x.com') + self.web.count('brand.x.com'), 0)
        self.assertNotIn('cand.x.com', self.web.made)
        self.assertEqual(self.web.count('a.x.com', '/docs'), 1)

    def test_every_request_is_a_get_on_a_vetted_owned_host(self):
        self.host('a.x.com')
        self.web.serve('a.x.com', '/openapi.json', oas3([{'url': '/v1'}]))
        self.run_discovery()
        self.assertTrue(self.web.calls)
        src = (WEB / 'limes/api_discovery.py').read_text()
        self.assertIsNone(re.search(r'\.(post|put|delete|patch|head|options|request)\(', src))
        self.assertNotRegex(src, r'\bimport (pickle|yaml)\b|\beval\(|\bexec\(')
        # the default getter is the pinned one: it refuses every URL that is not on its own host
        get = safe_fetch.pinned_get('a.x.com', '8.8.8.8')
        with self.assertRaises(requests.exceptions.InvalidURL):
            get('https://other.example/openapi.json')

    def test_documentation_paths_are_twelve_and_the_probe_is_capped_at_twenty(self):
        self.assertEqual(len(ad.DOC_PATHS), 12)
        self.host('a.x.com')
        paths = {f'/items{i:02d}': {'get': {}} for i in range(30)}
        paths.update({'/by/{id}': {'get': {}}, '/q?x=1': {'get': {}}, '/../etc': {'get': {}}, '/write': {'post': {}}})
        self.web.serve('a.x.com', '/openapi.json', oas3([{'url': '/v1'}], paths=paths))
        self.web.serve('a.x.com', '/v1/items00', {'ok': True})
        self.run_discovery()
        self.assertEqual(self.web.count('a.x.com'), 12 + 20)
        probed = [p for _, p in self.web.calls if p.startswith('/v1/')]
        self.assertEqual(len(probed), 20)
        self.assertEqual(len(set(probed)), 20)  # each once
        self.assertFalse(any('{' in p or '?' in p or '..' in p or p.endswith('write') for p in probed))
        a = self.apis()['https://a.x.com/v1']
        self.assertEqual(self.check(a, 'api.unauthenticated_access').status, 'fail')
        self.assertEqual(self.check(a, 'api.unauthenticated_access').evidence,
                         {'tested': 20, 'open': [{'path': '/items00', 'status': 200, 'size': 12}], 'open_count': 1})

    def test_unauthenticated_probe_outcomes(self):
        self.host('a.x.com')
        self.host('b.x.com')
        self.host('c.x.com')
        for h, secure in (('a.x.com', True), ('b.x.com', True), ('c.x.com', False)):
            self.web.serve(h, '/openapi.json', oas3([{'url': '/v1'}], secure=secure))
        self.web.serve('a.x.com', '/v1/users', b'<html>login</html>')  # 200 but not JSON: not data
        self.web.serve('b.x.com', '/v1/users', {'error': 'unauthorized'}, status=401)
        self.run_discovery()
        status = lambda h: self.check(self.apis()[f'https://{h}/v1'], 'api.unauthenticated_access').status
        self.assertEqual((status('a.x.com'), status('b.x.com'), status('c.x.com')), ('pass', 'pass', 'not_applicable'))
        self.assertEqual(self.web.count('c.x.com'), 12)  # no declared security: nothing probed

    def test_hosts_that_may_not_be_attacked_are_never_contacted(self):
        self.host('ok.x.com')
        self.host('brand.x.com', tier='co_brand')
        self.host('priv.x.com', ip='10.0.0.5')
        self.host('rej.x.com', tier='rejected')
        Asset.objects.create(project=self.p, kind='hostname', value='silent.x.com', scope_tier='owned_host')  # never probed
        self.host('auth.x.com', tier='co_brand', authorized=True)
        self.host('gone.x.com', state='retired')
        self.run_discovery()
        self.assertEqual(self.web.hosts_called(), {'ok.x.com'})  # owned tiers only: not even an authorised co-brand host

    def test_budget_fails_closed(self):
        self.host('a.x.com')
        self.web.serve('a.x.com', '/openapi.json', oas3([{'url': '/v1'}]))
        with mock.patch('limes.intel.ratelimit.take_daily', return_value=False):
            counts = self.run_discovery()
        self.assertEqual((counts['requests'], self.web.calls, self.apis()), (0, [], {}))

    def test_a_vanished_api_ages_like_any_asset(self):
        self.host('a.x.com')
        self.web.serve('a.x.com', '/openapi.json', oas3([{'url': '/v1'}]))
        self.run_discovery()
        del self.web.routes[('a.x.com', '/openapi.json')]
        for _ in range(3):
            self.run_discovery()
        self.assertEqual(self.apis()['https://a.x.com/v1'].state, 'missing')

    def test_canonical_values(self):
        c = lambda u: ad.canonical(u, 'a.x.com')
        self.assertEqual(c('/v1/'), ('same', 'https://a.x.com/v1'))
        self.assertEqual(c('v1'), ('same', 'https://a.x.com/v1'))
        self.assertEqual(c('/'), ('same', 'https://a.x.com'))
        self.assertEqual(c('https://A.X.com:443/Base?x=1#y'), ('same', 'https://a.x.com/Base'))
        self.assertEqual(c('https://a.x.com:8443/b'), ('same', 'https://a.x.com:8443/b'))
        for url in ('http://a.x.com:8080/b', 'http://a.x.com/b', 'https://a.x.com:6379/k', 'https://a.x.com:22/x', 'http://a.x.com:443/b'):
            self.assertEqual(c(url)[0], 'other', url)  # evidence text only: never requested, never an asset
        self.assertEqual(c('//a.x.com/v2'), ('same', 'https://a.x.com/v2'))
        self.assertEqual(c('https://evil.example/v1')[0], 'other')
        self.assertEqual(c('https://a.x.com.evil.example/v1')[0], 'other')
        for bad in ('https://user:pw@a.x.com/v1', 'https://a.x.com@evil.example/', 'ftp://a.x.com/', 'https://{host}/v1',
                    '/a/../b', '/a b', 'javascript:alert(1)', None, 5, 'https://a.x.com:99999/', '/%s' % ('a' * 300), 'https://a.x.com\\@evil/'):
            self.assertEqual(c(bad), (None, None), bad)


class ProvisionalApiTest(DiscoveryBase):
    def test_api_checks_cost_nothing_and_leave_every_score_identical(self):
        self.scan()
        self.host('a.x.com')
        self.web.serve('a.x.com', '/openapi.json', oas3([{'url': '/v1'}], secure=False))
        cache.clear()
        before = (scoring.project_score(self.p, self.now), scoring.category_scores(self.p, self.now),
                  scoring.assessed_assets(self.p, now=self.now), scoring.current_issues(self.p, self.now)[1])
        self.run_discovery()
        sync_issues(self.p, now=self.now)
        issues = TrackedIssue.objects.filter(project=self.p, asset__kind='api')
        self.assertEqual({i.key for i in issues}, {'api.exposed_docs', 'api.no_auth_declared'})  # tracked and visible
        self.assertTrue(all(i.key in PROVISIONAL for i in issues))
        after = (scoring.project_score(self.p, self.now), scoring.category_scores(self.p, self.now),
                 scoring.assessed_assets(self.p, now=self.now), scoring.current_issues(self.p, self.now)[1])
        self.assertEqual(after, before)
        self.assertEqual(scoring.points('api.exposed_docs', 2), 0)
        self.assertNotIn(self.apis()['https://a.x.com/v1'].id, scoring.scored_assets(self.p).values_list('id', flat=True))


class ApiNeverATargetTest(DiscoveryBase):
    def test_an_api_asset_is_never_a_scan_or_monitor_target(self):
        host = self.host('a.x.com')
        self.web.serve('a.x.com', '/openapi.json', oas3([{'url': '/v1'}]))
        self.run_discovery()
        api = self.apis()['https://a.x.com/v1']
        Asset.objects.filter(pk=api.pk).update(cadence_tier='crown_jewel')
        self.assertNotIn(api, monitor.monitored())
        self.assertNotIn(api.id, [a.id for a in monitor.due_assets(self.now)])
        self.assertNotIn(api.id, [a.id for a in continuous.due_roots(self.now)])
        self.assertEqual(continuous.set_cadence(api, 'off')[0], False)
        self.assertEqual(continuous.start_asm_scan(api)[0], False)
        self.assertEqual(ensure_scan_target(api), (None, None))
        self.assertFalse(Domain.objects.filter(name__contains='/').exists())
        self.assertEqual(monitor.monitor_state(api)['interval'], None)
        self.assertIn(api.id, scoring.issue_assets(self.p).values_list('id', flat=True))  # tracked for api.* checks only
        self.assertNotIn(api.id, scoring.scored_assets(self.p).values_list('id', flat=True))
        # port scan takes the hostnames this scan saved, nuclei the URLs of the run's file, never an api asset
        from limes.tasks import inventory
        Asset.objects.filter(pk=api.pk).update(sources=[{'source': 'discovery', 'evidence': 'scan:99'}])
        self.assertNotIn(api.value, inventory.run_hostnames(self.p, 99))
        src = (WEB / 'limes/tasks/stages.py').read_text()
        for fn in ('nmap', 'vulnerability_scan'):
            body = src[src.index(f"def {fn}("):]
            body = body[:body.index('\n@app.task')] if '\n@app.task' in body else body
            self.assertNotIn('Asset', body, fn)
        self.assertEqual(scope.may_attack(self.p, [api.value])[0], [api.value])  # judged by its host, as any URL is
        self.assertEqual((api.scope_tier, api.parent_id), ('owned_host', host.id))


class ApiIsolationTest(DiscoveryBase):
    def test_a_project_never_sees_another_projects_apis(self):
        self.host('a.x.com')
        self.web.serve('a.x.com', '/openapi.json', oas3([{'url': '/v1'}]))
        self.run_discovery()
        other = Asset.objects.create(project=self.other, kind='api', value='https://secret.y.com/v1', scope_tier='owned_host')
        from django.contrib.auth.models import User
        from django.contrib.auth.signals import user_logged_in
        from dashboard.views import on_user_logged_in
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.client.force_login(User.objects.create_user('u', password='p'))
        rows = self.client.get('/api/listDatatableAsset/', {'project': 'p', 'kind': 'api', 'no_page': '1'}).json()
        self.assertEqual([r['value'] for r in rows], ['https://a.x.com/v1'])
        r = self.client.get(f'/api/listDatatableAsset/{other.id}/', {'project': 'p'})
        self.assertEqual(r.status_code, 404)
        rows = self.client.get('/api/listDatatableAsset/', {'project': 'o', 'kind': 'api', 'no_page': '1'}).json()
        self.assertEqual([r['value'] for r in rows], ['https://secret.y.com/v1'])


class HostileSpecTest(DiscoveryBase):
    """A document's title, version and scheme names are attacker text: clipped on the way in, escaped on every way out."""
    def setUp(self):
        super().setUp()
        self.host('a.x.com')
        doc = oas3([{'url': '/v1'}], title=HOSTILE + 'T' * 500)
        doc['components']['securitySchemes'] = {HOSTILE: {'type': HOSTILE + '\x07' + 'y' * 100}}
        doc['info']['version'] = '<script>1</script>'
        self.web.serve('a.x.com', '/openapi.json', doc)
        self.run_discovery()
        self.api = self.apis()['https://a.x.com/v1']

    def test_stored_text_is_clipped_and_free_of_control_characters(self):
        e = self.api.enrichment
        self.assertLessEqual(len(e['title']), 200)
        self.assertLessEqual(len(e['auth_schemes'][0]), 40)
        self.assertNotIn('\x07', e['auth_schemes'][0])

    @staticmethod
    def drop_calls(text, names):
        """text without `name( ... )` calls (balanced), for each name."""
        for name in names:
            while True:
                at = text.find(name + '(')
                if at < 0:
                    break
                depth, k = 0, at + len(name)
                while k < len(text):
                    depth += (text[k] == '(') - (text[k] == ')')
                    k += 1
                    if depth == 0:
                        break
                text = text[:at] + 'X' + text[k:]
        return text

    def test_assets_js_escapes_every_value_it_joins_into_markup(self):
        """In the API renderers, document data (anything read off `e` or `a`) may appear only inside asset_esc(...),
        or in an if() condition; removing those leaves no data access behind."""
        src = (WEB / 'static/custom/asset.js').read_text()
        for fn in ('asset_api_summary', 'asset_api_section'):
            body = src[src.index(f'function {fn}('):]
            body = re.sub(r'(?m)^\s*//.*$', '', body[:body.index('\n}\n')])
            body = re.sub(r"'(?:[^'\\\n]|\\.)*'", 'S', body)
            body = self.drop_calls(body, ['asset_esc', 'asset_opt', 'if '])
            body = body.split('\n', 1)[1]  # the signature line names the parameter
            body = body.replace('var e = a.enrichment || {}', 'var e = X')  # the one place the data is picked up
            self.assertIsNone(re.search(r'\b[ea]\.\w', body), f'{fn} reads document data outside asset_esc: {body}')
            self.assertIn('X', body)
        page = (WEB / 'startScan/templates/startScan/assets.html').read_text()
        self.assertIn("asset_api_summary(row)", page)
        self.assertIn("{data: 'enrichment'", page)

    def test_mcp_wraps_every_api_text(self):
        from limes.mcp.tools import inventory
        item = inventory.asset_item(self.api)
        self.assertEqual(item['api']['title'], {'untrusted_text': ('<img src=x onerror=alert(1)>' + 'T' * 500)[:200]})
        for field in ('title', 'version', 'spec_url'):
            self.assertEqual(set(item['api'][field]), {'untrusted_text'})
        self.assertTrue(all(set(x) == {'untrusted_text'} for x in item['api']['auth_schemes']))
        plain = [v for k, v in item.items() if isinstance(v, str)]
        self.assertTrue(all('<' not in v for v in plain))
        self.assertIn('api', inventory.KINDS)


class McpApiTest(McpBase):
    def test_list_assets_returns_api_assets_wrapped_and_scoped(self):
        from limes.mcp import registry
        registry.load_tools()
        Asset.objects.create(project=self.p1, kind='api', value='https://a.x.com/v1', scope_tier='owned_host',
                             enrichment={'title': HOSTILE, 'version': '1', 'endpoints': 3, 'auth_schemes': ['http:bearer']})
        Asset.objects.create(project=self.p2, kind='api', value='https://secret.y.com/v1', scope_tier='owned_host')
        d = self.data(self.call('list_assets', project='p1', kind='api'))['items']
        self.assertEqual([i['value']['untrusted_text'] for i in d], ['https://a.x.com/v1'])
        self.assertEqual(d[0]['api']['title'], {'untrusted_text': HOSTILE})
        self.assertEqual(d[0]['api']['endpoints'], 3)
        self.assertNotIn(HOSTILE, ' '.join(self.outside_untrusted(d)))
        self.assertNotIn('secret.y.com', json.dumps(d))
        self.assertEqual(self.data(self.call('list_assets', project='p2', kind='api'))['items'][0]['value']['untrusted_text'],
                         'https://secret.y.com/v1')
        self.assertNotIn('api', (self.data(self.call('list_assets', project='p1', kind='hostname'))['items'] or [{}])[0])


class OverviewApiCountTest(DiscoveryBase):
    def test_attack_surface_counts_owned_apis_only(self):
        from dashboard.stats import asm_stats
        self.host('a.x.com')
        self.web.serve('a.x.com', '/openapi.json', oas3([{'url': '/v1'}, {'url': '/v2'}]))
        self.run_discovery()
        Asset.objects.create(project=self.p, kind='api', value='https://z.x.com/v1', scope_tier='candidate')
        Asset.objects.create(project=self.other, kind='api', value='https://y.com/v1', scope_tier='owned_host')
        inv = asm_stats(self.p)['inventory']
        self.assertEqual((inv['api'], inv['owned_root'], inv['owned_host']), (2, 1, 1))  # an API is never a root or a host


class VolumeAndLifecycleTest(DiscoveryBase):
    """Findings 1-5 of the Part B review."""

    def many_servers(self, host, n=10):
        return [{'url': f'/s{i}'} for i in range(n)]

    def test_the_probe_budget_is_per_host_and_the_apis_per_host_are_capped(self):
        self.host('a.x.com')
        paths = {f'/p{i:02d}': {'get': {}} for i in range(20)}
        for i, path in enumerate(ad.SPEC_PATHS[:4]):
            self.web.serve('a.x.com', path, oas3([{'url': f'/d{i}s{j}'} for j in range(10)], paths=paths))
        counts = self.run_discovery()
        self.assertEqual(self.web.count('a.x.com') - 12, 20)  # one sweep for the whole host
        self.assertEqual(len(self.apis()), ad.MAX_APIS_PER_HOST)
        self.assertEqual(counts['requests'], 32)
        self.assertEqual(len({p for _, p in self.web.calls}), 32)  # nothing fetched twice
        later = [a for a in self.apis().values() if not RiskCheck.objects.filter(asset=a, check_id='api.unauthenticated_access', status__in=('pass', 'fail')).exists()]
        self.assertTrue(later)  # the APIs after the budget ran out say 'not applicable', not 'pass'

    def test_only_a_few_documents_are_followed_per_host(self):
        self.host('a.x.com')
        for i, path in enumerate(ad.SPEC_PATHS):
            self.web.serve('a.x.com', path, oas3([{'url': f'/doc{i}'}], secure=False))
        self.run_discovery()
        self.assertEqual(set(self.apis()), {f'https://a.x.com/doc{i}' for i in range(ad.MAX_SPECS_PER_HOST)})

    def test_no_budget_is_spent_once_the_host_deadline_has_passed(self):
        self.host('a.x.com')
        self.web.serve('a.x.com', '/openapi.json', oas3([{'url': '/v1'}]))
        spent = []
        real = ad.safe_fetch.Deadline

        def expired_after_docs(seconds, clock=None):
            d = real(seconds)
            d.expired = lambda: len(self.web.calls) >= 12
            return d
        with mock.patch('limes.api_discovery.safe_fetch.Deadline', expired_after_docs), \
                mock.patch('limes.intel.ratelimit.take_daily', side_effect=lambda *a, **k: spent.append(1) or True):
            self.run_discovery()
        self.assertEqual((len(self.web.calls), len(spent)), (12, 12))  # the probe's 2 would-be requests cost nothing
        a = self.apis()['https://a.x.com/v1']
        self.assertEqual(self.check(a, 'api.unauthenticated_access').status, 'error')  # cut short is inconclusive

    def test_a_rerun_leaves_a_rejected_api_alone_and_does_not_revive_a_retired_one(self):
        self.host('a.x.com')
        self.web.serve('a.x.com', '/openapi.json', oas3([{'url': '/v1'}, {'url': '/v2'}, {'url': '/v3'}]))
        self.run_discovery()
        apis = self.apis()
        Asset.objects.filter(pk=apis['https://a.x.com/v1'].pk).update(scope_tier='rejected', decision_reason='not ours')
        Asset.objects.filter(pk=apis['https://a.x.com/v2'].pk).update(state='retired')
        before = {a.value: (a.scope_tier, a.state, a.enrichment, a.last_seen, a.decision_reason) for a in Asset.objects.filter(kind='api')}
        self.run_discovery()
        after = {a.value: (a.scope_tier, a.state, a.enrichment, a.last_seen, a.decision_reason) for a in Asset.objects.filter(kind='api')}
        self.assertEqual(after['https://a.x.com/v1'], before['https://a.x.com/v1'])
        self.assertEqual(after['https://a.x.com/v2'], before['https://a.x.com/v2'])
        self.assertEqual(self.apis()['https://a.x.com/v3'].state, 'active')

    def test_a_missing_api_comes_back_when_it_is_seen_again(self):
        self.host('a.x.com')
        self.web.serve('a.x.com', '/openapi.json', oas3([{'url': '/v1'}]))
        self.run_discovery()
        Asset.objects.filter(kind='api').update(state='missing', missed_count=3)
        self.run_discovery()
        self.assertEqual(self.apis()['https://a.x.com/v1'].state, 'active')

    def test_rejecting_or_demoting_the_parent_takes_its_apis_out(self):
        from dashboard.stats import asm_stats
        parent = self.host('a.x.com')
        self.web.serve('a.x.com', '/openapi.json', oas3([{'url': '/v1'}], secure=False))
        self.scan()
        self.run_discovery()
        api = self.apis()['https://a.x.com/v1']
        sync_issues(self.p, now=self.now)
        tracked = lambda: api.id in scoring.issue_assets(self.p).values_list('id', flat=True)
        self.assertEqual((tracked(), asm_stats(self.p)['inventory']['api']), (True, 1))
        for tier in ('rejected', 'candidate'):
            Asset.objects.filter(pk=parent.pk).update(scope_tier=tier)
            self.assertEqual((tracked(), asm_stats(self.p)['inventory']['api']), (False, 0), tier)  # at once, before any rerun
            self.assertNotIn(api.id, [c for c in scoring.current_issues(self.p, self.now)[0]])
            self.run_discovery()  # the host is skipped, but its APIs follow it
            api.refresh_from_db()
            self.assertEqual(api.scope_tier, tier)
            Asset.objects.filter(pk=parent.pk).update(scope_tier='owned_host')
            self.run_discovery()
            api.refresh_from_db()
            self.assertEqual((api.scope_tier, tracked()), ('owned_host', True))
        Asset.objects.filter(pk=parent.pk).update(state='retired')
        self.assertEqual(tracked(), False)

    def test_a_host_outage_ages_nothing(self):
        self.host('a.x.com')
        self.web.serve('a.x.com', '/openapi.json', oas3([{'url': '/v1'}]))
        self.run_discovery()
        self.web.routes.clear()

        def down(host, deadline=None):
            def get(url, **kw):
                raise requests.exceptions.ConnectionError('refused')
            return get
        for _ in range(4):
            ad.discover(self.p, self.root, self.now, make_get=down)
        api = self.apis()['https://a.x.com/v1']
        self.assertEqual((api.state, api.missed_count), ('active', 0))
        for _ in range(3):  # the host answers (404) and the API is not there: now it ages
            self.run_discovery()
        self.assertEqual(self.apis()['https://a.x.com/v1'].state, 'missing')

    def test_a_document_cannot_pick_the_port_or_the_scheme(self):
        self.host('a.x.com')
        self.web.serve('a.x.com', '/openapi.json', oas3([
            {'url': 'http://a.x.com:6379/k'}, {'url': 'https://a.x.com:22/x'}, {'url': 'http://a.x.com/clear'},
            {'url': 'https://a.x.com:8443/ok'}, {'url': '/v1'}]))
        self.run_discovery()
        self.assertEqual(set(self.apis()), {'https://a.x.com:8443/ok', 'https://a.x.com/v1'})
        self.assertFalse(any(p.startswith(('/k', '/x', '/clear')) for _, p in self.web.calls))
        self.assertEqual(sorted(self.apis()['https://a.x.com/v1'].enrichment['other_servers']),
                         ['http://a.x.com/clear', 'http://a.x.com:6379/k', 'https://a.x.com:22/x'])


class SweepVerdictTest(SimpleTestCase):
    def verdict(self, tested, errors, open_=()):
        from limes.checks import api as api_checks
        spec = {'path': '/openapi.json', 'status': 200, 'size': 1, 'schemes': 1}
        r = api_checks.evaluate({'spec': spec, 'probe': {'tested': tested, 'errors': errors, 'open': list(open_)}})
        return {x.check: x.status for x in r}['api.unauthenticated_access']

    def test_a_sweep_that_mostly_failed_is_inconclusive(self):
        self.assertEqual(self.verdict(20, 19), 'error')
        self.assertEqual(self.verdict(20, 20), 'error')
        self.assertEqual(self.verdict(20, 11), 'error')
        self.assertEqual(self.verdict(20, 10), 'pass')
        self.assertEqual(self.verdict(20, 0), 'pass')
        self.assertEqual(self.verdict(20, 19, [{'path': '/a', 'status': 200, 'size': 1}]), 'fail')  # an open route is a fail
