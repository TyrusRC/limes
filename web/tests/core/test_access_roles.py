"""The role matrix: what read_only, standard and admin may do in a project, over every route. The expected sets are
written out here on purpose, apart from memberships.policy, so editing the policy alone cannot pass these tests."""
from tests.core.access_base import AccessBase
from tests.core.test_access_matrix import all_routes, send

ADMIN_ONLY = {'project_members', 'project_member_add', 'project_member_role', 'project_member_remove',
              'project_members_api', 'project_member_api', 'delete_project'}
GLOBAL_ONLY = {'notification_settings', 'proxy_settings', 'tool_settings', 'admin_interface', 'admin_interface_update',
               'api:getFileContents', 'api:create_project', 'add_engine', 'update_engine', 'delete_engine_url'}
READS_VIA_POST = {'api:score_forecast', 'api:select_portfolio'}  # the second only sets the caller's own session view
OWN_THINGS = {'profile', 'api_tokens', 'api:notification-mark-read', 'api:notification-mark-all-read',
              'api:notification-clear-all'}
GET_THAT_WRITES = set()
METHODS = ('GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE')
READS = ('GET', 'HEAD', 'OPTIONS')


def scoped():
    return [(n, u.replace('/p2/', '/p1/'), k) for n, u, k in all_routes()
            if 'slug' in k or u.startswith('/api/')]


class RoleMatrixTest(AccessBase):
    def verdict(self, client, method, name, url):
        r = send(client, method, url, project='p1')
        return getattr(r.wsgi_request, 'limes_access', None), r

    def test_read_only(self):
        c = self.client_for(self.user('ro', role='read_only', global_role='penetration_tester'))
        for name, url, _ in scoped():
            for method in METHODS:
                got, r = self.verdict(c, method, name, url)
                if name in ADMIN_ONLY or name in GLOBAL_ONLY or name in GET_THAT_WRITES:
                    want = 'forbidden'
                elif method in READS or name in READS_VIA_POST or name in OWN_THINGS:
                    want = 'allowed'
                else:
                    want = 'forbidden'
                self.assertEqual(got, want, f'read_only {method} {name} {url} -> {r.status_code}')
                if want == 'forbidden':
                    self.assertEqual(r.status_code, 403)

    def test_standard(self):
        c = self.client_for(self.user('st', role='standard', global_role='penetration_tester'))
        for name, url, _ in scoped():
            for method in METHODS:
                got, r = self.verdict(c, method, name, url)
                want = 'forbidden' if name in ADMIN_ONLY or name in GLOBAL_ONLY else 'allowed'
                self.assertEqual(got, want, f'standard {method} {name} {url} -> {r.status_code}')

    def test_project_admin(self):
        c = self.client_for(self.user('ad', role='admin', global_role='penetration_tester'))
        for name, url, _ in scoped():
            for method in METHODS:
                got, r = self.verdict(c, method, name, url)
                want = 'forbidden' if name in GLOBAL_ONLY else 'allowed'  # instance-wide settings are not a project's
                self.assertEqual(got, want, f'project admin {method} {name} {url} -> {r.status_code}')

    def test_global_admin(self):
        c = self.client_for(self.user('sa', global_role='sys_admin'))
        c.raise_request_exception = False  # a few legacy views crash on odd verbs; only the access layer is judged here
        for name, url, _ in scoped():
            for method in METHODS:
                got, r = self.verdict(c, method, name, url)
                self.assertEqual(got, 'allowed', f'sys_admin {method} {name} {url} -> {r.status_code}')

    def test_read_only_cannot_write_through_an_action_endpoint_and_data_is_unchanged(self):
        from startScan.models import Asset
        a = Asset.objects.create(project=self.p1, kind='root_domain', value='x.com', scope_tier='candidate')
        c = self.client_for(self.user('ro', role='read_only', global_role='penetration_tester'))
        for url, body in (('/api/action/asset/confirm/', {'asset_id': a.id, 'project': 'p1', 'tier': 'owned_root'}),
                          ('/api/action/asset/reject/', {'asset_id': a.id, 'project': 'p1', 'reason': 'x'}),
                          ('/api/add/assets/', {'project': 'p1', 'entries': ['y.com']})):
            r = c.post(url, body, content_type='application/json')
            self.assertEqual(r.status_code, 403, url)
        a.refresh_from_db()
        self.assertEqual(a.scope_tier, 'candidate')
        self.assertFalse(Asset.objects.filter(value='y.com').exists())

    def test_global_roles_keep_working_alongside_project_roles(self):
        # an auditor may not scan whatever the project role says: both layers must agree
        c = self.client_for(self.user('aud', role='admin', global_role='auditor'))
        r = c.post('/api/action/asset/rescan/', {'project': 'p1', 'asset_id': 1}, content_type='application/json')
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.wsgi_request.limes_access, 'allowed')  # the project layer passed; rolepermissions refused

    def test_sys_admin_and_superuser_have_global_access(self):
        for u in (self.user('sa', global_role='sys_admin'), self.user('su', is_superuser=True)):
            c = self.client_for(u)
            for slug in ('p1', 'p2'):
                r = c.get(f'/{slug}/dashboard/')
                self.assertEqual(r.wsgi_request.limes_access, 'allowed', u.username)

    def test_inactive_user_and_unrelated_global_role_get_nothing(self):
        for u in (self.user('pt', global_role='penetration_tester'), self.user('aud', global_role='auditor')):
            r = self.client_for(u).get('/p1/dashboard/')
            self.assertEqual(r.status_code, 404, u.username)
        u = self.user('gone', role='admin')
        c = self.client_for(u)
        u.is_active = False
        u.save()
        self.assertNotEqual(c.get('/p1/dashboard/').status_code, 200)

    def test_membership_removal_takes_effect_on_the_next_request(self):
        u = self.user('m', role='admin')
        c = self.client_for(u)
        self.assertEqual(c.get('/p1/dashboard/').wsgi_request.limes_access, 'allowed')
        u.project_memberships.all().delete()
        self.assertEqual(c.get('/p1/dashboard/').status_code, 404)


class MediaTest(AccessBase):
    def test_report_snapshots_are_served_to_their_project_only(self):
        import os
        import tempfile
        from django.test import override_settings
        m = self.client_for(self.user('m', role='read_only'))
        with tempfile.TemporaryDirectory() as d, override_settings(MEDIA_ROOT=d + '/'):
            for p in (self.p1, self.p2):
                os.makedirs(f'{d}/reports/{p.pk}')
                open(f'{d}/reports/{p.pk}/ok.html', 'w').close()
            self.assertEqual(m.get(f'/media/reports/{self.p1.pk}/ok.html').status_code, 200)
            self.assertEqual(m.get(f'/media/reports/{self.p2.pk}/ok.html').status_code, 404)  # exists, not theirs
            self.assertEqual(m.get('/media/reports/../../etc/passwd').status_code, 404)
