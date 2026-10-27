"""Regression tests for the S1 adversarial review. Each asserts the CORRECT behaviour and failed on the first
version of the branch."""
import json
import os
import tempfile
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import Client, override_settings
from django.urls import reverse
from rest_framework.test import APIRequestFactory, force_authenticate

from api import views as api_views
from dashboard.models import InAppNotification, Project
from memberships.models import AccessAudit, ProjectMember
from startScan.models import Asset
from tests.core.access_base import AccessBase
from tests.core.test_access_matrix import all_routes

User = get_user_model()
ADD = '/api/add/assets/'


def assets(project):
    return list(Asset.objects.filter(project=project).values_list('value', flat=True))


class BodyDifferentialTest(AccessBase):
    """Whatever the body looks like, a request for a project the user may not write to writes nothing."""

    def bodies(self, slug):
        j = json.dumps({'project': slug, 'entries': ['evil.example.com']})
        jpad = '{"project": "%s", "entries": ["evil.example.com"], "pad": "ÿ"}' % slug
        form = f'project={slug}&text=evil.example.com&entries=evil.example.com'
        dup = '{"project": "p1", "project": "%s", "entries": ["evil.example.com"]}' % slug
        dup2 = '{"project": "%s", "project": "p1", "entries": ["evil.example.com"]}' % slug
        return {
            'latin-1 charset with a byte utf-8 rejects': (jpad.encode('latin-1'), 'application/json; charset=latin-1'),
            'utf-16 charset': (j.encode('utf-16'), 'application/json; charset=utf-16'),
            'utf-16 body, no charset': (j.encode('utf-16'), 'application/json'),
            'utf-8 BOM': (b'\xef\xbb\xbf' + j.encode(), 'application/json'),
            'upper-case json type': (j.encode(), 'Application/JSON'),
            'upper-case charset': (j.encode(), 'application/json; CHARSET=UTF-8'),
            'plain json': (j.encode(), 'application/json'),
            'text/plain json': (j.encode(), 'text/plain'),
            'no content type': (j.encode(), ''),
            'form': (form.encode(), 'application/x-www-form-urlencoded'),
            'form, odd case': (form.encode(), 'application/X-WWW-Form-Urlencoded'),
            'form, odd case, charset': (form.encode(), 'Application/x-www-form-urlencoded; Charset=latin-1'),
            'duplicate keys, mine first': (dup.encode(), 'application/json'),
            'duplicate keys, mine last': (dup2.encode(), 'application/json'),
            'form duplicate keys': (f'project=p1&{form}'.encode(), 'application/x-www-form-urlencoded'),
            'form duplicate keys 2': (f'{form}&project=p1'.encode(), 'application/x-www-form-urlencoded'),
            'NaN constant': (b'{"project": "%s", "x": NaN}' % slug.encode(), 'application/json'),
            'nested project': (json.dumps({'project': {'slug': slug}, 'entries': ['evil.example.com']}).encode(), 'application/json'),
            'array project': (json.dumps({'project': ['p1', slug], 'entries': ['evil.example.com']}).encode(), 'application/json'),
            'top-level array': (json.dumps([{'project': slug}]).encode(), 'application/json'),
        }

    def post(self, c, body, ctype, query=''):
        extra = {'content_type': ctype} if ctype else {'content_type': ''}
        return c.generic('POST', ADD + query, body, **extra)

    def check(self, user, slug, own_ok):
        c = self.client_for(user)
        for name, (body, ctype) in self.bodies(slug).items():
            r = self.post(c, body, ctype)
            if own_ok and name == 'duplicate keys, mine last':
                continue  # both parsers take the last key: this really is a write to their own project
            self.assertEqual(assets(self.p2), [], f'{name}: wrote into p2 ({r.status_code})')
            if not own_ok:  # a read-only member may not write to their own project either
                self.assertEqual(assets(self.p1), [], f'{name}: wrote into p1 ({r.status_code})')
            self.assertNotIn(r.status_code, (200, 201, 202), name)

    def test_outsider_cannot_write_to_p2_in_any_encoding(self):
        self.check(self.user('out', role='admin', global_role='penetration_tester'), 'p2', own_ok=True)  # admin of p1: a body that really names p1 is their business

    def test_read_only_member_cannot_write_to_own_project_in_any_encoding(self):
        self.check(self.user('ro', role='read_only', global_role='penetration_tester'), 'p1', own_ok=False)

    def test_multipart_for_a_foreign_project(self):
        c = self.client_for(self.user('out', role='admin', global_role='penetration_tester'))
        r = c.post(ADD, {'project': 'p2', 'text': 'evil.example.com'})  # multipart by default
        self.assertEqual(r.status_code, 404)
        self.assertEqual(assets(self.p2), [])

    def test_the_honest_case_still_works(self):
        c = self.client_for(self.user('std', role='standard', global_role='penetration_tester'))
        r = c.post(ADD, json.dumps({'project': 'p1', 'entries': ['ok.example.com']}), content_type='application/json')
        self.assertEqual(r.status_code, 200, r.content)
        r = c.post(ADD, json.dumps({'project': 'p1', 'entries': ['ok2.example.com']}), content_type='Application/JSON; charset=UTF-8')
        self.assertEqual(r.status_code, 200, r.content)
        self.assertEqual(sorted(assets(self.p1)), ['ok.example.com', 'ok2.example.com'])


class DrfLayerTest(AccessBase):
    """Second layer: the DRF permission decides from DRF's own parse, even if the middleware were fooled or absent."""

    def call(self, user, view, method='post', data=None, path='/api/x/', **extra):
        f = APIRequestFactory()
        req = getattr(f, method)(path, data, format='json') if data is not None else getattr(f, method)(path)
        force_authenticate(req, user=user)
        resp = view(req, **extra)
        resp.render()
        return resp

    def test_outsider_is_refused_without_the_middleware(self):
        u = self.user('out', role='admin', global_role='penetration_tester')
        r = self.call(u, api_views.AddAssets.as_view(), data={'project': 'p2', 'entries': ['evil.example.com']})
        self.assertEqual(r.status_code, 404)
        self.assertEqual(assets(self.p2), [])

    def test_read_only_is_refused_without_the_middleware(self):
        u = self.user('ro', role='read_only', global_role='penetration_tester')
        r = self.call(u, api_views.AddAssets.as_view(), data={'project': 'p1', 'entries': ['evil.example.com']})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(assets(self.p1), [])

    def test_viewset_default_permission_applies_too(self):
        u = self.user('out', role='admin')
        r = self.call(u, api_views.AssetDatatableViewSet.as_view({'get': 'list'}), 'get', path='/api/listDatatableAsset/?project=p2')
        self.assertEqual(r.status_code, 404)

    def test_no_data_means_no_project_and_no_write(self):
        u = self.user('std', role='standard', global_role='penetration_tester')
        r = self.call(u, api_views.AddAssets.as_view(), data={'entries': ['x.example.com']})
        self.assertIn(r.status_code, (403, 404))

    def test_every_api_view_carries_the_project_permission(self):
        from django.urls import get_resolver
        from memberships.drf import ProjectRolePermission
        seen = 0

        def walk(patterns):
            nonlocal seen
            for p in patterns:
                if hasattr(p, 'url_patterns'):
                    walk(p.url_patterns)
                    continue
                cls = getattr(p.callback, 'cls', None) or getattr(p.callback, 'view_class', None)
                if cls is not None and hasattr(cls, 'permission_classes'):
                    seen += 1
                    self.assertTrue(any(issubclass(pc, ProjectRolePermission) for pc in cls.permission_classes),
                                    f'{cls.__name__} would skip the project permission')
        walk(get_resolver().url_patterns)
        self.assertGreater(seen, 20)


class GlobalOnlyTest(AccessBase):
    def pentester_admin(self):
        return self.client_for(self.user('pa', role='admin', global_role='penetration_tester'))

    def test_creating_a_project_needs_a_global_admin_and_is_post_only(self):
        c = self.pentester_admin()
        url = reverse('api:create_project')
        for r in (c.post(url, {'name': 'mine'}), c.post(url + '?name=mine'), c.get(url + '?name=mine')):
            self.assertIn(r.status_code, (403, 405))
        self.assertFalse(Project.objects.filter(slug='mine').exists())
        boss = self.client_for(self.user('boss', global_role='sys_admin'))
        self.assertEqual(boss.get(url + '?name=viaget').status_code, 405)
        r = boss.post(url, {'name': 'viapost'})
        self.assertEqual(r.status_code, 200, r.content)
        self.assertTrue(ProjectMember.objects.filter(user__username='boss', project__slug='viapost', role='admin').exists())

    def test_creation_does_not_echo_database_errors_or_reveal_projects(self):
        boss = self.client_for(self.user('boss', global_role='sys_admin'))
        r = boss.post(reverse('api:create_project'), {'name': 'p1'})
        self.assertEqual(r.status_code, 400)
        text = r.content.decode().lower()
        for leak in ('duplicate', 'constraint', 'dashboard_project', 'key (slug)', 'already exists'):
            self.assertNotIn(leak, text)
        outsider = self.pentester_admin()
        r = outsider.post(reverse('api:create_project'), {'name': 'p2'})
        self.assertEqual(r.status_code, 403)
        self.assertNotIn('p2', r.content.decode())

    def test_csrf_on_creation(self):
        boss = User.objects.create_user('b2', password='p')
        from rolepermissions.roles import assign_role
        assign_role(boss, 'sys_admin')
        c = Client(enforce_csrf_checks=True)
        c.force_login(boss)
        self.assertEqual(c.post(reverse('api:create_project'), {'name': 'csrf'}).status_code, 403)
        self.assertFalse(Project.objects.filter(slug='csrf').exists())

    def test_project_admin_does_not_unlock_instance_settings(self):
        c = self.pentester_admin()
        for name in ('notification_settings', 'proxy_settings', 'tool_settings', 'admin_interface', 'admin_interface_update'):
            r = c.get(reverse(name, kwargs={'slug': 'p1'}))
            self.assertEqual(r.status_code, 403, name)
            self.assertEqual(c.post(reverse(name, kwargs={'slug': 'p1'}), {}).status_code, 403, name)
        r = c.get(reverse('api:getFileContents') + '?nuclei_config')
        self.assertEqual(r.status_code, 403)

    def test_global_admin_still_reaches_them(self):
        c = self.client_for(self.user('boss', global_role='sys_admin'))
        for name in ('notification_settings', 'proxy_settings', 'tool_settings'):
            r = c.get(reverse(name, kwargs={'slug': 'p1'}))
            self.assertEqual(r.wsgi_request.limes_access, 'allowed', name)

    def test_project_deletion_is_audited_and_admin_only(self):
        std = self.client_for(self.user('std', role='standard', global_role='penetration_tester'))
        self.assertEqual(std.post(reverse('delete_project', kwargs={'id': self.p1.pk})).status_code, 403)
        boss = self.client_for(self.user('boss', global_role='sys_admin'))
        boss.post(reverse('delete_project', kwargs={'id': self.p2.pk}))
        self.assertFalse(Project.objects.filter(pk=self.p2.pk).exists())
        a = AccessAudit.objects.get(action='project_deleted')
        self.assertEqual((a.actor_name, a.subject), ('boss', 'p2'))


# Writes that name no project and are still fine: sign-in/out, the first-project onboarding, one's own notification
# read state, and Django's own admin (which checks its own permissions).
NO_PROJECT_WRITES = {'login', 'logout', 'sso_login', 'sso_callback', 'onboarding', 'api:create_project',
                     'api:notification-mark-read', 'api:notification-mark-all-read', 'api:notification-clear-all'}


class DefaultDenyTest(AccessBase):
    def test_every_write_route_names_a_project_or_is_listed(self):
        c = self.client_for(self.user('std', role='standard', global_role='penetration_tester'))
        c2 = self.client_for(self.user('sa', global_role='sys_admin'))
        for name, url, kw in all_routes():
            if name in NO_PROJECT_WRITES or 'slug' in kw or url.startswith('/media/') or name == 'healthz':
                continue
            for method in ('POST', 'PUT', 'PATCH', 'DELETE'):
                for client in (c, c2):
                    with __import__('django').db.transaction.atomic():
                        r = client.generic(method, url, '{}', content_type='application/json')
                        __import__('django').db.transaction.set_rollback(True)
                    self.assertEqual(r.status_code in (403, 404, 405) or getattr(r.wsgi_request, 'limes_access', '') in
                                     ('forbidden', 'not_found'), True,
                                     f'{method} {name} {url} -> {r.status_code}: a write that names no project got through')

    def test_unsafe_methods_without_a_project_are_refused_by_the_middleware_itself(self):
        c = self.client_for(self.user('std', role='standard', global_role='penetration_tester'))
        for url in ('/api/action/asset/confirm/', '/api/add/assets/', '/api/notifications/', '/api/action/stop/scan/'):
            r = c.post(url, json.dumps({}), content_type='application/json')
            self.assertEqual(getattr(r.wsgi_request, 'limes_access', None), 'forbidden', url)


class NotificationsTest(AccessBase):
    def setUp(self):
        super().setUp()
        self.n1 = InAppNotification.objects.create(project=self.p1, title='a', description='d', icon='x')
        self.n2 = InAppNotification.objects.create(project=self.p2, title='b', description='d', icon='x')
        self.sysn = InAppNotification.objects.create(project=None, notification_type='system', title='s', description='d', icon='x')

    def test_nobody_can_create_update_or_delete_notifications(self):
        c = self.client_for(self.user('a', role='admin', global_role='sys_admin'))
        evil = json.dumps({'title': 'Re-login', 'description': 'd', 'icon': 'x', 'redirect_link': 'https://evil.example/'})
        self.assertIn(c.post('/api/notifications/', evil, content_type='application/json').status_code, (403, 405))
        self.assertIn(c.delete(f'/api/notifications/{self.n1.pk}/').status_code, (403, 405))
        self.assertIn(c.patch(f'/api/notifications/{self.n1.pk}/', evil, content_type='application/json').status_code, (403, 405))
        self.assertEqual(InAppNotification.objects.count(), 3)
        self.assertFalse(InAppNotification.objects.filter(title='Re-login').exists())

    def test_read_state_is_per_user_and_scoped_to_visible_projects(self):
        a = self.client_for(self.user('a', role='read_only'))
        b = self.client_for(self.user('b', role='read_only'))
        self.assertEqual(a.post(f'/api/notifications/{self.n1.pk}/mark_read/').status_code, 204)
        flags = lambda c: {n['title']: n['is_read'] for n in c.get('/api/notifications/?project_slug=p1').json()}
        self.assertEqual(flags(a), {'a': True, 's': False})
        self.assertEqual(flags(b), {'a': False, 's': False})
        self.assertEqual(b.get('/api/notifications/unread_count/').json()['count'], 2)
        self.assertEqual(a.get('/api/notifications/unread_count/').json()['count'], 1)
        self.assertEqual(a.post(f'/api/notifications/{self.n2.pk}/mark_read/').status_code, 404)  # not their project

    def test_clear_all_and_mark_all_only_touch_the_callers_view(self):
        a = self.client_for(self.user('a', role='read_only'))
        b = self.client_for(self.user('b', role='read_only'))
        self.assertEqual(a.post('/api/notifications/clear_all/').status_code, 204)
        self.assertEqual(InAppNotification.objects.count(), 3)
        self.assertEqual(a.get('/api/notifications/unread_count/').json()['count'], 0)
        self.assertEqual(b.get('/api/notifications/unread_count/').json()['count'], 2)
        self.assertEqual(a.post('/api/notifications/mark_all_read/?project_slug=p2').status_code, 404)


class MediaPathTest(AccessBase):
    def test_report_guard_survives_odd_paths(self):
        tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(tmp, 'reports', str(self.p2.id)))
        open(os.path.join(tmp, 'reports', str(self.p2.id), 'r.html'), 'w').write('secret')
        c = self.client_for(self.user('out', role='admin'))
        i = self.p2.id
        with override_settings(MEDIA_ROOT=tmp):
            for p in (f'reports/{i}/r.html', f'reports//{i}/r.html', f'reports/./{i}/r.html', f'reports/%2e/{i}/r.html',
                      f'reports%2f{i}/r.html', f'reports/x/../{i}/r.html', f'./reports/{i}/r.html', f'/reports/{i}/r.html',
                      f'reports/{i}//r.html', f'REPORTS/{i}/r.html', f'reports/0{i}/r.html', f'reports/+{i}/r.html',
                      f'reports/{i}\\r.html'):
                r = c.get('/media/' + p)
                self.assertEqual(r.status_code, 404, p)
                self.assertIsNone(r.get('X-Accel-Redirect'), p)
            mine = self.client_for(self.user('in', role='admin'))
            ProjectMember.objects.create(user=User.objects.get(username='in'), project=self.p2, role='read_only')
            self.assertEqual(mine.get(f'/media/reports/{i}/r.html').status_code, 200)

    def test_api_prefix_tricks_do_not_resolve(self):
        c = self.client_for(self.user('out', role='admin', global_role='penetration_tester'))
        for p in ('//api/add/assets/', '/api/./add/assets/', '/api//add/assets/', '/api/add/assets/./', '/API/add/assets/'):
            r = c.post(p, json.dumps({'project': 'p2', 'entries': ['evil.example.com']}), content_type='application/json')
            self.assertIn(r.status_code, (301, 404, 403), p)
        self.assertEqual(assets(self.p2), [])
