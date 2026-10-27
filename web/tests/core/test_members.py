import json

from django.contrib.auth import get_user_model
from django.test import Client

from memberships import services
from memberships.models import AccessAudit, ProjectMember
from tests.core.access_base import AccessBase


class MembersBase(AccessBase):
    def setUp(self):
        super().setUp()
        self.boss = self.user('boss', role='admin')
        self.c = self.client_for(self.boss)
        self.api = '/p1/members/api/'

    def member(self, user, role):
        return ProjectMember.objects.create(user=user, project=self.p1, role=role)


class ServiceTest(MembersBase):
    def test_last_admin_cannot_be_demoted_or_removed_but_a_second_one_can_leave(self):
        mine = ProjectMember.objects.get(user=self.boss)
        for call in (lambda: services.change_role(self.boss, self.p1, mine.pk, 'standard'),
                     lambda: services.remove_member(self.boss, self.p1, mine.pk)):
            with self.assertRaises(services.MemberError) as cm:
                call()
            self.assertEqual(cm.exception.status, 409)
        self.assertEqual(ProjectMember.objects.get(pk=mine.pk).role, 'admin')
        other = self.member(self.user('b2'), 'admin')
        services.change_role(self.boss, self.p1, mine.pk, 'read_only')
        with self.assertRaises(services.MemberError):  # b2 is now the last one
            services.remove_member(self.boss, self.p1, other.pk)

    def test_admin_of_another_project_does_not_count(self):
        ProjectMember.objects.create(user=self.boss, project=self.p2, role='admin')
        with self.assertRaises(services.MemberError):
            services.remove_member(self.boss, self.p1, ProjectMember.objects.get(user=self.boss, project=self.p1).pk)

    def test_member_ids_are_scoped_to_the_project(self):
        foreign = ProjectMember.objects.create(user=self.user('f'), project=self.p2, role='standard')
        for call in (lambda: services.change_role(self.boss, self.p1, foreign.pk, 'admin'),
                     lambda: services.remove_member(self.boss, self.p1, foreign.pk)):
            with self.assertRaises(services.MemberError) as cm:
                call()
            self.assertEqual(cm.exception.status, 404)
        foreign.refresh_from_db()
        self.assertEqual(foreign.role, 'standard')

    def test_add_by_username_or_email_only_existing_active_users(self):
        a, b = self.user('alice'), self.user('bob')
        services.add_member(self.boss, self.p1, 'alice', 'standard')
        services.add_member(self.boss, self.p1, 'BOB@example.test', 'read_only')
        self.assertEqual(set(ProjectMember.objects.filter(project=self.p1).values_list('user__username', 'role')),
                         {('boss', 'admin'), ('alice', 'standard'), ('bob', 'read_only')})
        for ident, role, status in (('nobody', 'standard', 404), ('', 'standard', 400), ('alice', 'standard', 409),
                                    ('alice', 'root', 400)):
            with self.assertRaises(services.MemberError) as cm:
                services.add_member(self.boss, self.p1, ident, role)
            self.assertEqual(cm.exception.status, status, ident)
        off = self.user('off')
        off.is_active = False
        off.save()
        with self.assertRaises(services.MemberError):
            services.add_member(self.boss, self.p1, 'off', 'standard')

    def test_ambiguous_email_is_refused(self):
        get_user_model().objects.create_user('twin', email='alice@example.test')
        self.user('alice')
        with self.assertRaises(services.MemberError):
            services.add_member(self.boss, self.p1, 'alice@example.test', 'standard')

    def test_every_change_is_audited(self):
        u = self.user('alice')
        m = services.add_member(self.boss, self.p1, 'alice', 'standard')
        services.change_role(self.boss, self.p1, m.pk, 'read_only')
        services.remove_member(self.boss, self.p1, m.pk)
        got = list(AccessAudit.objects.filter(project=self.p1).order_by('id').values_list('action', 'actor_name', 'subject', 'detail'))
        self.assertEqual(got, [('member_added', 'boss', 'alice', 'role standard'),
                               ('role_changed', 'boss', 'alice', 'standard -> read_only'),
                               ('member_removed', 'boss', 'alice', 'was read_only')])
        u.delete()
        self.assertEqual(AccessAudit.objects.filter(subject='alice').count(), 3)  # names are copied, not joined

    def test_refused_changes_are_not_audited(self):
        with self.assertRaises(services.MemberError):
            services.add_member(self.boss, self.p1, 'ghost', 'standard')
        self.assertEqual(AccessAudit.objects.count(), 0)


class RestTest(MembersBase):
    def post(self, body, c=None):
        return (c or self.c).post(self.api, json.dumps(body), content_type='application/json')

    def test_list_add_change_remove(self):
        self.user('alice')
        r = self.post({'user': 'alice', 'role': 'standard'})
        self.assertEqual(r.status_code, 201)
        mid = r.json()['member']['id']
        self.assertEqual({m['username']: m['role'] for m in self.c.get(self.api).json()['members']},
                         {'boss': 'admin', 'alice': 'standard'})
        r = self.c.patch(f'{self.api}{mid}/', json.dumps({'role': 'read_only'}), content_type='application/json')
        self.assertEqual((r.status_code, r.json()['member']['role']), (200, 'read_only'))
        self.assertEqual(self.c.delete(f'{self.api}{mid}/').status_code, 200)
        self.assertFalse(ProjectMember.objects.filter(pk=mid).exists())

    def test_last_admin_refusal_is_409_and_garbage_is_400(self):
        mine = ProjectMember.objects.get(user=self.boss).pk
        self.assertEqual(self.c.delete(f'{self.api}{mine}/').status_code, 409)
        r = self.c.patch(f'{self.api}{mine}/', json.dumps({'role': 'standard'}), content_type='application/json')
        self.assertEqual(r.status_code, 409)
        for body in ({'user': 5, 'role': 'standard'}, {'user': 'x', 'role': ['admin']}, [1], 'x'):
            self.assertEqual(self.post(body).status_code, 400, body)
        self.assertEqual(self.c.post(self.api, 'not json', content_type='application/json').status_code, 400)

    def test_only_admins_reach_it_and_a_standard_member_cannot_promote_themselves(self):
        std = self.user('std', role='standard')
        c = self.client_for(std)
        mid = ProjectMember.objects.get(user=std).pk
        self.assertEqual(c.get(self.api).status_code, 403)
        self.assertEqual(self.post({'user': 'boss', 'role': 'admin'}, c).status_code, 403)
        r = c.patch(f'{self.api}{mid}/', json.dumps({'role': 'admin'}), content_type='application/json')
        self.assertEqual(r.status_code, 403)
        self.assertEqual(c.post(f'/p1/members/{mid}/role', {'role': 'admin'}).status_code, 403)
        self.assertEqual(ProjectMember.objects.get(pk=mid).role, 'standard')
        outsider = self.client_for(self.user('out', role=None))
        self.assertEqual(outsider.get(self.api).status_code, 404)

    def test_other_projects_admin_cannot_manage_this_one(self):
        other = self.user('o2')
        ProjectMember.objects.create(user=other, project=self.p2, role='admin')
        c = self.client_for(other)
        self.assertEqual(c.get(self.api).status_code, 404)
        self.assertEqual(self.post({'user': 'o2', 'role': 'admin'}, c).status_code, 404)
        self.assertFalse(ProjectMember.objects.filter(user=other, project=self.p1).exists())

    def test_csrf_is_enforced(self):
        c = Client(enforce_csrf_checks=True)
        c.force_login(self.boss)
        self.assertEqual(c.post(self.api, json.dumps({'user': 'boss', 'role': 'admin'}), content_type='application/json').status_code, 403)
        mid = ProjectMember.objects.get(user=self.boss).pk
        self.assertEqual(c.post(f'/p1/members/{mid}/remove').status_code, 403)
        self.assertEqual(c.delete(f'{self.api}{mid}/').status_code, 403)
        self.assertTrue(ProjectMember.objects.filter(pk=mid).exists())

    def test_verbs(self):
        mid = ProjectMember.objects.get(user=self.boss).pk
        self.assertEqual(self.c.get(f'{self.api}{mid}/').status_code, 405)
        self.assertEqual(self.c.delete(self.api).status_code, 405)
        self.assertEqual(self.c.get(f'/p1/members/{mid}/remove').status_code, 405)


class PageTest(MembersBase):
    def test_page_lists_escapes_and_posts_forms(self):
        evil = self.user('<script>alert(1)</script>', role='standard')
        evil.email = '"><img src=x onerror=alert(2)>@example.test'
        evil.save()
        html = self.c.get('/p1/members/').content.decode()
        self.assertNotIn('<script>alert(1)', html)
        self.assertNotIn('<img src=x', html)
        self.assertIn('&lt;script&gt;alert(1)', html)
        self.assertIn('csrfmiddlewaretoken', html)
        self.user('alice')
        r = self.c.post('/p1/members/add', {'user': 'alice', 'role': 'standard'})
        self.assertEqual(r.status_code, 302)
        self.assertIn('member_added', self.c.get('/p1/members/').content.decode())
        self.assertTrue(ProjectMember.objects.filter(user__username='alice', role='standard').exists())

    def test_last_admin_refusal_shows_as_a_message_not_an_error_page(self):
        mid = ProjectMember.objects.get(user=self.boss).pk
        r = self.c.post(f'/p1/members/{mid}/remove', follow=True)
        self.assertEqual(r.status_code, 200)
        self.assertIn('at least one admin', r.content.decode())
        self.assertTrue(ProjectMember.objects.filter(pk=mid).exists())

    def test_menu_link_only_for_admins(self):
        std = self.client_for(self.user('std', role='standard'))
        self.assertNotIn('/p1/members/', std.get('/p1/dashboard/').content.decode())
        self.assertIn('/p1/members/', self.c.get('/p1/dashboard/').content.decode())


class CreatorTest(AccessBase):
    def test_creating_a_project_through_the_api_makes_the_creator_its_admin(self):
        u = self.user('maker', global_role='sys_admin')
        r = self.client_for(u).post('/api/action/create/project', {'name': 'Fresh One'})
        self.assertEqual(r.status_code, 200, r.content)
        m = ProjectMember.objects.get(user=u, project__slug='fresh-one')
        self.assertEqual(m.role, 'admin')
        self.assertEqual(self.client_for(u).get('/fresh-one/dashboard/').wsgi_request.limes_access, 'allowed')

    def test_a_user_without_projects_sees_no_project_names(self):
        c = self.client_for(self.user('nobody'))
        body = c.get('/p1/projects/').content.decode()  # 404 page: no names either
        self.assertNotIn('>p1<', body)
        r = c.get('/')
        self.assertEqual(r.status_code, 200)
        self.assertNotIn('Location', r)
        self.assertEqual(c.post('/', {'project_name': 'grab', 'create_username': 'x', 'create_password': 'y',
                                      'create_user_role': 'sys_admin'}).status_code, 200)
        from dashboard.models import Project
        self.assertFalse(Project.objects.filter(slug='grab').exists())
        self.assertFalse(get_user_model().objects.filter(username='x').exists())

    def test_onboarding_goes_to_a_project_the_user_may_open_not_just_the_first(self):
        u = self.user('m')
        ProjectMember.objects.create(user=u, project=self.p2, role='read_only')
        r = self.client_for(u).get('/')
        self.assertEqual((r.status_code, r['Location']), (302, '/p2/dashboard/'))

    def test_project_switcher_lists_only_my_projects(self):
        c = self.client_for(self.user('m', role='read_only'))
        html = c.get('/p1/dashboard/').content.decode()
        self.assertNotIn('/p2/', html)
        both = self.client_for(self.user('both', role='read_only'))
        ProjectMember.objects.create(user=get_user_model().objects.get(username='both'), project=self.p2, role='read_only')
        self.assertIn('/p2/', both.get('/p1/dashboard/').content.decode())
