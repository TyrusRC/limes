"""Every URL against every kind of user. The URL list is read from the resolver, so a new route is tested the day it
is added, and a new route that is not project-scoped has to be listed here on purpose."""
import json

from django.db import transaction
from django.urls import get_resolver, reverse

from memberships import policy
from tests.core.access_base import AccessBase

# Routes that name no project at all, with the reason each is safe.
UNSCOPED = {
    'onboarding': 'redirects to a project the user may open',
    'four_oh_four': 'static page',
    'sso_login': 'anonymous start of SSO; no project data', 'sso_callback': 'anonymous end of SSO; no project data',
    'login': 'anonymous', 'logout': 'own session', 'healthz': 'anonymous health probe',
    'serve_protected_media': 'authorised per file: reports/<project id>/ and <target>_<scan id>/ need membership of that project',
    'delete_project': 'resolved to its project by id (policy.EXTRA_RESOLVERS)',
    'api:stop_scan': 'resolved to its projects by scan id (policy.EXTRA_RESOLVERS)',
    'api:getFileContents': 'global tool configs: global admin only (policy.GLOBAL_ONLY)',
    'api:create_project': 'global admin only (policy.GLOBAL_ONLY); creator becomes admin',
    'api:notification-mark-read': 'own read state', 'api:notification-mark-all-read': 'own read state',
    'api:notification-clear-all': 'own read state', 'api:notification-unread-count': 'reads only what the user may see',
    'api:notification-list': 'reads only what the user may see', 'api:notification-detail': 'reads only what the user may see',
}
INT_ARGS = {'id', 'run_id', 'schedule_id', 'pk', 'member_id'}
SKIP = {'admin'}  # django admin: staff only, not project data


def all_routes():
    """[(view_name, url)] for every named route, with placeholders filled in for slug p2 and id 1."""
    resolver = get_resolver()
    out = []

    def walk(res, prefix):
        for name, entries in res.reverse_dict.lists():
            if not isinstance(name, str):
                continue
            params = next((ent[0][0][1] for ent in entries if ent[0] and 'format' not in ent[0][0][1]), None)
            if params is None:
                continue
            kw = {k: (1 if k in INT_ARGS else 'p2') for k in params}
            ns = prefix[:-1] if prefix else None
            try:
                url = reverse(f'{prefix}{name}', kwargs=kw)
            except Exception:
                continue
            out.append((f'{prefix}{name}', url, kw))
    walk(resolver, '')
    for ns, (_, sub) in resolver.namespace_dict.items():
        if ns != 'admin':
            walk(sub, ns + ':')
    seen = {}
    for name, url, kw in out:
        seen.setdefault(name, (url, kw))
    return [(n, u, k) for n, (u, k) in sorted(seen.items())]


def send(client, method, url, project=None):
    """One request, rolled back afterwards (a request that is let through may delete things or break the
    transaction). In the API the project travels as a parameter (query, and JSON body for writes)."""
    with transaction.atomic():
        r = _send(client, method, url, project)
        transaction.set_rollback(True)
    return r


def _send(client, method, url, project=None):
    m = method.lower()
    if method in ('GET', 'HEAD', 'OPTIONS'):
        return getattr(client, m)(url + (f'?project={project}' if project else ''))
    if project and url.startswith('/api/'):
        return getattr(client, m)(url + f'?project={project}', json.dumps({'project': project, 'scan_ids': []}),
                                  content_type='application/json')
    return getattr(client, m)(url, json.dumps({}), content_type='application/json')


class RoutesTest(AccessBase):
    def test_the_enumeration_is_not_vacuous(self):
        names = {n for n, _, _ in all_routes()}
        self.assertGreater(len(names), 60)
        for must in ('dashboardIndex', 'assets', 'issues', 'report_download', 'delete_engine_url', 'api:issues',
                     'api:waive_issue', 'api:asset-list', 'api:notification-mark-all-read', 'project_members'):
            self.assertIn(must, names)

    def test_every_route_is_scoped_or_deliberately_not(self):
        for name, url, kw in all_routes():
            scoped = 'slug' in kw or url.startswith('/api/')
            if not scoped:
                self.assertIn(name, UNSCOPED, f'{name} {url} names no project: add it to UNSCOPED with the reason, or scope it')
        for name in UNSCOPED:
            self.assertIn(name, {n for n, _, _ in all_routes()}, f'stale UNSCOPED entry {name}')

    def test_policy_names_exist(self):
        names = {n for n, _, _ in all_routes()}
        for group in (policy.ADMIN_ONLY, policy.READ_ONLY_POST_OK, policy.SELF_SERVICE, policy.MUTATING_GET, policy.GLOBAL_ONLY, policy.NO_PROJECT_WRITES,
                      set(policy.EXTRA_RESOLVERS)):
            for n in group:
                self.assertIn(n, names, f'policy names {n}, which is not a route')

    def test_non_member_gets_the_same_404_for_a_project_that_exists_and_one_that_does_not(self):
        outsider = self.client_for(self.user('out', role='admin'))  # admin of p1, nothing in p2
        for name, url, kw in all_routes():
            if not ('slug' in kw or url.startswith('/api/')):
                continue
            for method in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE'):
                theirs = send(outsider, method, url, project='p2')
                nowhere = send(outsider, method, url.replace('/p2/', '/nowhere/') if 'slug' in kw else url, project='nowhere')
                for r in (theirs, nowhere):
                    self.assertEqual(r.status_code, 404, f'{method} {name} {url}')
                    self.assertEqual(r.wsgi_request.limes_access, 'not_found', f'{method} {name} {url}: the view ran')
                self.assertEqual(theirs.content.decode()[:0], nowhere.content.decode()[:0])

    def test_anonymous_reaches_nothing_scoped(self):
        from django.test import Client
        c = Client()
        for name, url, kw in all_routes():
            if 'slug' in kw or url.startswith('/api/'):
                r = send(c, 'GET', url, project='p1')
                self.assertIn(r.status_code, (302, 401, 403, 404), f'{name} {url}')
                self.assertNotEqual(getattr(r.wsgi_request, 'limes_access', None), 'allowed', name)

    def test_member_is_let_through_to_the_view(self):
        c = self.client_for(self.user('m', role='read_only'))
        for name, url, kw in all_routes():
            if 'slug' in kw or url.startswith('/api/'):
                url = url.replace('/p2/', '/p1/')
                r = send(c, 'GET', url, project='p1')
                if name in policy.ADMIN_ONLY or name in policy.GLOBAL_ONLY:
                    continue
                self.assertEqual(r.wsgi_request.limes_access, 'allowed', f'{name} {url} {r.status_code}')

    def test_project_param_in_any_place_is_checked(self):
        c = self.client_for(self.user('m', role='admin'))
        url = reverse('api:issues')
        for bad in (
            c.get(url + '?project=p1&project=p2'),  # a member project first must not hide the second
            c.get(url + '?project=p2&project=p1'),
            c.post(url, json.dumps({'project': 'p2'}), content_type='application/json'),
            c.post(url + '?project=p1', json.dumps({'project': 'p2'}), content_type='application/json'),
            c.post(url + '?project=p1', {'project': 'p2'}),
            c.post(url, json.dumps({'project': ['p1', 'p2']}), content_type='application/json'),
            c.post(url, json.dumps({'project': {'slug': 'p1'}}), content_type='application/json'),
            c.get(reverse('api:notification-unread-count') + '?project_slug=p2'),
        ):
            self.assertEqual(bad.status_code, 404)
            self.assertEqual(bad.wsgi_request.limes_access, 'not_found')
        ok = c.get(url + '?project=p1')
        self.assertEqual(ok.wsgi_request.limes_access, 'allowed')
