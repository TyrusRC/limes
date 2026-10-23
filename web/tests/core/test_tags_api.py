import threading

from django.contrib.auth.models import User
from django.db import connection, transaction
from django.contrib.auth.signals import user_logged_in
from django.test import TestCase, TransactionTestCase
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from dashboard.models import Project
from dashboard.views import on_user_logged_in
from limes import tags
from startScan.models import Asset, Tag, TrackedIssue

URL = '/api/action/asset/tags/'


class TagsBase(TestCase):
    def setUp(self):
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.admin = User.objects.create_user('adm', password='p')
        assign_role(self.admin, 'sys_admin')
        self.auditor = User.objects.create_user('aud', password='p')
        assign_role(self.auditor, 'auditor')
        self.p = Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())
        self.q = Project.objects.create(name='p2', slug='p2', insert_date=timezone.now())
        self.a = self.asset(self.p, 'a.x.com')
        self.b = self.asset(self.p, 'b.x.com')
        self.c = self.asset(self.q, 'c.y.com')

    def asset(self, project, value):
        return Asset.objects.create(project=project, kind='hostname', value=value, scope_tier='owned_host')

    def api(self, user=None, **kw):
        c = APIClient(**kw)
        c.force_login(user or self.admin)
        return c

    def tag(self, **body):
        body.setdefault('project', 'p1')
        return self.api().post(URL, body, format='json')

    def names(self, asset):
        return sorted(asset.tags.values_list('name', flat=True))


class TagActionTest(TagsBase):
    def test_bulk_add_normalises_creates_and_remove_deletes_empty_tags(self):
        r = self.tag(assets=[self.a.id, self.b.id], add=['Prod', ' eu:west ', 'payments'])
        self.assertEqual(r.status_code, 200, r.content)
        self.assertEqual(self.names(self.a), ['eu:west', 'payments', 'prod'])
        self.assertEqual(self.names(self.b), ['eu:west', 'payments', 'prod'])
        self.assertEqual(Tag.objects.filter(project=self.p).count(), 3)
        self.tag(assets=[self.a.id], remove=['PROD', 'never-existed'])
        self.assertEqual(self.names(self.a), ['eu:west', 'payments'])
        self.assertTrue(Tag.objects.filter(project=self.p, name='prod').exists())  # b still uses it
        self.tag(assets=[self.b.id], remove=['prod'])
        self.assertFalse(Tag.objects.filter(project=self.p, name='prod').exists())  # nothing uses it any more

    def test_add_is_idempotent(self):
        self.tag(assets=[self.a.id], add=['prod'])
        self.assertEqual(self.tag(assets=[self.a.id], add=['prod']).status_code, 200)
        self.assertEqual(self.names(self.a), ['prod'])

    def test_same_name_in_two_projects_is_two_tags(self):
        self.tag(assets=[self.a.id], add=['prod'])
        self.api().post(URL, {'project': 'p2', 'assets': [self.c.id], 'add': ['prod']}, format='json')
        self.assertEqual(Tag.objects.filter(name='prod').count(), 2)
        self.assertNotEqual(self.a.tags.get().pk, self.c.tags.get().pk)

    def test_invalid_names_are_a_400_and_change_nothing(self):
        for bad in ('', ' ', '-lead', 'has space', 'x' * 41, '<img src=x>', 'ünï', 'a\nb', 5, None, ['x']):
            r = self.tag(assets=[self.a.id], add=['ok', bad])
            self.assertEqual(r.status_code, 400, repr(bad))
            self.assertFalse(r.json()['status'])
        self.assertEqual(Tag.objects.count(), 0)
        self.assertEqual(self.tag(assets=[self.a.id], add=['x' * 40]).status_code, 200)  # the longest legal name

    def test_malformed_bodies_are_a_400(self):
        c = self.api()
        for body in ({'project': 'p1'}, {'project': 'p1', 'assets': []}, {'project': 'p1', 'assets': [self.a.id]},
                     {'project': 'p1', 'assets': 'x', 'add': ['a']}, {'project': 'p1', 'assets': [True], 'add': ['a']},
                     {'project': 'p1', 'assets': [self.a.id], 'add': 'prod'},
                     {'project': 'p1', 'assets': [self.a.id], 'add': ['a'], 'remove': ['a']}):
            self.assertEqual(c.post(URL, body, format='json').status_code, 400, body)
        self.assertEqual(c.post(URL, ['x'], format='json').status_code, 400)
        self.assertEqual(Tag.objects.count(), 0)

    def test_limits_are_errors_not_silent_drops(self):
        names = [f't{i}' for i in range(20)]
        self.assertEqual(self.tag(assets=[self.a.id], add=names).status_code, 200)
        r = self.tag(assets=[self.a.id, self.b.id], add=['one-too-many'])
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.names(self.b), [])  # the whole call is refused, b included
        self.assertFalse(Tag.objects.filter(name='one-too-many').exists())
        self.assertEqual(self.tag(assets=[self.a.id], add=['t0']).status_code, 200)  # already there: not over
        self.assertEqual(self.tag(assets=[self.a.id], add=['fresh'], remove=['t0']).status_code, 200)  # net 20
        self.assertEqual(self.a.tags.count(), 20)

    def test_project_tag_limit(self):
        self.fill(self.p, self.a, 200)
        self.assertEqual(self.tag(assets=[self.a.id], add=['p5']).status_code, 200)  # existing: fine
        self.assertEqual(self.tag(assets=[self.a.id], add=['p201']).status_code, 400)
        self.fill(self.q, self.c, 200)  # other project: own budget
        self.assertEqual(self.api().post(URL, {'project': 'p2', 'assets': [self.c.id], 'add': ['new']},
                                            format='json').status_code, 400)

    def fill(self, project, asset, n):
        """n tags on one asset, written straight to the DB (so it can be over the per-asset limit)."""
        Tag.objects.bulk_create([Tag(project=project, name=f'p{i}') for i in range(n)])
        Through = Asset.tags.through
        Through.objects.bulk_create([Through(asset_id=asset.id, tag_id=t) for t in
                                     Tag.objects.filter(project=project).values_list('id', flat=True)])

    def test_removing_works_on_data_already_over_the_limits(self):
        self.fill(self.p, self.a, 230)  # 230 on one asset and in the project: over both limits
        self.assertEqual(self.tag(assets=[self.a.id], remove=['p0']).status_code, 200)
        self.assertEqual(self.a.tags.count(), 229)
        self.assertEqual(self.tag(assets=[self.a.id], add=['p1']).status_code, 200)  # nothing new: not refused
        self.assertEqual(self.tag(assets=[self.a.id], add=['brand-new']).status_code, 400)
        self.assertEqual(self.tag(assets=[self.b.id], add=['brand-new']).status_code, 400)  # project is over too

    def test_tags_nobody_carries_are_not_listed_or_counted(self):
        Tag.objects.bulk_create([Tag(project=self.p, name=f'z{i}') for i in range(200)])  # no asset carries them
        self.assertEqual(self.tag(assets=[self.a.id], add=['real']).status_code, 200)
        self.assertEqual(self.api().get('/api/tags/', {'project': 'p1'}).json(), [{'name': 'real', 'assets': 1}])
        self.a.delete()
        self.assertEqual(self.api().get('/api/tags/', {'project': 'p1'}).json(), [])

    def test_at_most_200_assets_per_call(self):
        self.assertEqual(self.tag(assets=list(range(1, 202)), add=['x']).status_code, 400)
        self.assertEqual(self.tag(assets=[self.a.id] * 201, add=['x']).status_code, 400)
        self.assertEqual(self.tag(assets=[self.a.id] * 200, add=['x']).status_code, 200)  # duplicates collapse

    def test_a_cross_project_asset_id_is_a_404_for_the_whole_call(self):
        r = self.tag(assets=[self.a.id, self.c.id], add=['prod'])
        self.assertEqual(r.status_code, 404)
        self.assertEqual(Tag.objects.count(), 0)
        self.assertEqual(self.names(self.a), [])
        self.assertEqual(self.tag(assets=[10 ** 9], add=['prod']).status_code, 404)
        self.assertEqual(self.api().post(URL, {'project': 'nope', 'assets': [self.a.id], 'add': ['x']},
                                            format='json').status_code, 404)

    def test_remove_cannot_touch_another_projects_tag(self):
        self.api().post(URL, {'project': 'p2', 'assets': [self.c.id], 'add': ['prod']}, format='json')
        self.tag(assets=[self.a.id], remove=['prod'])
        self.assertEqual(self.names(self.c), ['prod'])

    def test_needs_the_modify_permission_and_csrf(self):
        r = self.api(self.auditor).post(URL, {'project': 'p1', 'assets': [self.a.id], 'add': ['x']}, format='json')
        self.assertEqual(r.status_code, 403)
        r = self.api(enforce_csrf_checks=True).post(URL, {'project': 'p1', 'assets': [self.a.id], 'add': ['x']}, format='json')
        self.assertEqual(r.status_code, 403)
        anon = APIClient().post(URL, {'project': 'p1', 'assets': [self.a.id], 'add': ['x']}, format='json')
        self.assertIn(anon.status_code, (302, 401, 403))
        self.assertEqual(Tag.objects.count(), 0)


class TagReadTest(TagsBase):
    def test_tags_list_is_project_scoped_with_counts(self):
        self.tag(assets=[self.a.id, self.b.id], add=['prod'])
        self.tag(assets=[self.a.id], add=['eu'])
        self.api().post(URL, {'project': 'p2', 'assets': [self.c.id], 'add': ['secret-y']}, format='json')
        r = self.api().get('/api/tags/', {'project': 'p1'})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), [{'name': 'prod', 'assets': 2}, {'name': 'eu', 'assets': 1}])
        self.assertNotIn('secret-y', r.content.decode())
        self.assertEqual(self.api().get('/api/tags/', {'project': 'nope'}).status_code, 404)
        self.assertEqual(self.api().get('/api/tags/').status_code, 404)

    def test_asset_serializer_lists_names_and_filter_is_project_scoped(self):
        self.tag(assets=[self.a.id], add=['prod', 'eu'])
        self.api().post(URL, {'project': 'p2', 'assets': [self.c.id], 'add': ['prod']}, format='json')
        rows = self.api().get('/api/listDatatableAsset/', {'project': 'p1', 'no_page': '1', 'tag': 'prod'}).json()
        self.assertEqual([(r['value'], sorted(r['tags'])) for r in rows], [('a.x.com', ['eu', 'prod'])])
        rows = self.api().get('/api/listDatatableAsset/', {'project': 'p1', 'no_page': '1', 'tag': 'PROD'}).json()
        self.assertEqual([r['value'] for r in rows], ['a.x.com'])  # filters by the normalised name
        rows = self.api().get('/api/listDatatableAsset/', {'project': 'p1', 'no_page': '1', 'tag': 'nope'}).json()
        self.assertEqual(rows, [])

    def test_issues_filter_by_the_issue_assets_tag(self):
        self.tag(assets=[self.a.id], add=['prod'])
        self.api().post(URL, {'project': 'p2', 'assets': [self.c.id], 'add': ['prod']}, format='json')
        ia = TrackedIssue.objects.create(project=self.p, asset=self.a, key='web.hsts_missing', source='check', severity=2)
        TrackedIssue.objects.create(project=self.p, asset=self.b, key='web.hsts_missing', source='check', severity=2)
        TrackedIssue.objects.create(project=self.q, asset=self.c, key='web.hsts_missing', source='check', severity=2)
        rows = self.api().get('/api/issues/', {'project': 'p1', 'tag': 'prod'}).json()
        self.assertEqual([r['id'] for r in rows], [ia.id])
        self.assertEqual(len(self.api().get('/api/issues/', {'project': 'p1'}).json()), 2)
        self.assertEqual(self.api().get('/api/issues/', {'project': 'p1', 'tag': 'nope'}).json(), [])


class TagLockTest(TransactionTestCase):
    def test_change_tags_waits_for_the_project_row_lock(self):
        """The limit checks read then write; without the project row lock two calls could both pass them."""
        p = Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())
        a = Asset.objects.create(project=p, kind='hostname', value='a.x.com', scope_tier='owned_host')
        # The call below writes nothing (the asset already has the tag), so only the lock itself can make it wait.
        a.tags.add(Tag.objects.create(project=p, name='prod'))
        done = threading.Event()
        errors = []

        def other():
            try:
                tags.change_tags(p, [a.id], add=['prod'])
            except Exception as e:  # reported below, never swallowed
                errors.append(e)
            finally:
                connection.close()
                done.set()

        with transaction.atomic():
            Project.objects.select_for_update().get(pk=p.pk)
            t = threading.Thread(target=other)
            t.start()
            self.assertFalse(done.wait(1.0), 'change_tags ran while another transaction held the project row')
        self.assertTrue(done.wait(10))
        t.join()
        self.assertEqual(errors, [])
        self.assertEqual(a.tags.count(), 1)
