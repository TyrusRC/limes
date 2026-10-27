import re

from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.test import TestCase
from django.utils import timezone
from rolepermissions.roles import assign_role

from dashboard.models import Project
from dashboard.views import on_user_logged_in


class SidebarAndShellTest(TestCase):
    def setUp(self):
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())
        u = User.objects.create_user('adm', password='p')
        assign_role(u, 'sys_admin')
        self.client.force_login(u)
        self.client.get('/p1/home/')  # warm-up (lazy prefs creation)

    def test_every_sidebar_link_resolves(self):
        html = self.client.get('/p1/home/').content.decode()
        nav = html[html.index('id="l-sidebar"'):html.index('</nav>')]
        hrefs = re.findall(r'href="([^"#][^"]*)"', nav)
        self.assertGreater(len(hrefs), 8)
        for href in hrefs:
            r = self.client.get(href)
            self.assertEqual(r.status_code, 200, f'{href} -> {r.status_code}')

    def test_shell_has_skip_link_target_and_landmarks(self):
        html = self.client.get('/p1/home/').content.decode()
        self.assertIn('href="#main"', html)
        self.assertIn('<main class="l-content" id="main" tabindex="-1">', html)
        self.assertIn('aria-label="Primary"', html)

    def test_new_pages_have_breadcrumbs_and_one_h1(self):
        for path in ('/p1/home/', '/scan/p1/issues', '/scan/p1/assets'):
            html = self.client.get(path).content.decode()
            self.assertIn('breadcrumb-item active', html, path)
            self.assertEqual(html.count('<h1'), 1, path)

    def test_stylesheet_honours_reduced_motion(self):
        from pathlib import Path
        css = (Path(__file__).resolve().parents[2] / 'static/limes/ux.css').read_text()
        self.assertIn('prefers-reduced-motion: reduce', css)
