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
