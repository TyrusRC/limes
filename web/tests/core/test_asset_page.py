from django.test import TestCase
from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.utils import timezone
from dashboard.views import on_user_logged_in
from dashboard.models import Project


class AssetPageTest(TestCase):
    def setUp(self):
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.client.force_login(User.objects.create_user('u', password='p'))
        Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())

    def test_page_renders_table_and_api_url(self):
        self.client.get('/scan/p1/assets')  # warm-up (lazy prefs creation)
        r = self.client.get('/scan/p1/assets')
        self.assertEqual(r.status_code, 200)
        html = r.content.decode()
        for needle in ('Assets', 'id="asset_results"', '/api/listDatatableAsset/', 'id="f_tag"'):
            self.assertIn(needle, html)


class AssetPageTabsAndBulkTest(TestCase):
    def setUp(self):
        from rolepermissions.roles import assign_role
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())
        self.admin = User.objects.create_user('adm', password='p')
        assign_role(self.admin, 'sys_admin')
        self.auditor = User.objects.create_user('aud', password='p')
        assign_role(self.auditor, 'auditor')

    def page(self, user):
        self.client.force_login(user)
        self.client.get('/scan/p1/assets')  # warm-up (lazy prefs creation)
        return self.client.get('/scan/p1/assets').content.decode()

    def test_tabs_and_bulk_actions_follow_permissions(self):
        html = self.page(self.admin)
        for needle in ('id="tab_active"', 'id="tab_inactive"', 'role="tablist"', 'id="rescan_bulk"', 'id="tag_bulk_add"',
                       'data-can-pick="1"', 'limes/assets_ux.js', 'id="f_kind"'):
            self.assertIn(needle, html)
        html = self.page(self.auditor)
        self.assertIn('id="tab_active"', html)  # reading is for everyone
        for needle in ('id="rescan_bulk"', 'id="tag_bulk_add"', 'id="asset_pick_all"'):
            self.assertNotIn(needle, html)
        self.assertIn('data-can-pick="0"', html)
