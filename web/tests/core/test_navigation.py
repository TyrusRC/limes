import re

from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rolepermissions.checkers import has_permission
from rolepermissions.permissions import revoke_permission
from rolepermissions.roles import assign_role

from dashboard.models import Project
from dashboard.views import on_user_logged_in

SLUG = 'p1'

# Every sidebar link, with the permission that gates it (None = everyone).
NAV = {
    'dashboardIndex': None, 'scan_history': None, 'assets': None, 'issues': None, 'lookalikes': None,
    'scan_engine_index': 'modify_scan_configurations',
    'proxy_settings': 'modify_scan_configurations',
    'tool_settings': 'modify_scan_configurations',
    'limes_settings': 'modify_system_configurations',
    'notification_settings': 'modify_scan_configurations',
}


class NavigationTest(TestCase):
    def setUp(self):
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        Project.objects.create(name='p1', slug=SLUG, insert_date=timezone.now())
        self.admin = User.objects.create_superuser('adm', password='p')
        self.auditor = User.objects.create_user('aud', password='p')
        assign_role(self.auditor, 'auditor')

    def shell(self, user):
        self.client.force_login(user)
        r = self.client.get(reverse('dashboardIndex', args=[SLUG]))
        self.assertEqual(r.status_code, 200)
        html = r.content.decode()
        side = re.search(r'<nav[^>]*class="l-sidebar[^"]*"[^>]*>(.*?)</nav>', html, re.S)
        top = re.search(r'<header[^>]*class="l-topbar[^"]*"[^>]*>(.*?)</header>', html, re.S)
        self.assertIsNotNone(side, 'sidebar missing')
        self.assertIsNotNone(top, 'top bar missing')
        return side.group(1), top.group(1)

    def href(self, name):
        return 'href="%s"' % reverse(name, args=[SLUG])

    def test_sidebar_links_follow_permissions(self):
        side, top = self.shell(self.admin)
        for name in NAV:
            self.assertIn(self.href(name), side, name)
        self.assertIn(self.href('list_projects'), top)

        side, top = self.shell(self.auditor)
        self.assertIn(self.href('list_projects'), top)
        for name, perm in NAV.items():
            shown = perm is None or has_permission(self.auditor, perm)
            self.assertEqual(self.href(name) in side, shown, name)
        for name in ('issues', 'assets'):
            self.assertIn(self.href(name), side)
        # the auditor role really is gated: some Configure links must be hidden
        self.assertNotIn(self.href('limes_settings'), side)

    def test_user_without_role_sees_no_gated_links(self):
        nobody = User.objects.create_user('nobody', password='p')
        side, top = self.shell(nobody)
        for name, perm in NAV.items():
            self.assertEqual(self.href(name) in side, perm is None, name)
        self.assertNotIn('Configure', side)
        self.assertNotIn(self.href('add_engine'), top)

    def test_each_configure_gate_checked_on_its_own(self):
        # sys_admin minus one permission: the Configure section still renders, so each inner
        # gate (not just the section gate) has to hide its link
        user = User.objects.create_user('partial', password='p')
        assign_role(user, 'sys_admin')
        revoke_permission(user, 'modify_scan_configurations')
        side, top = self.shell(user)
        for name, perm in NAV.items():
            self.assertEqual(self.href(name) in side, perm is None or has_permission(user, perm), name)
        self.assertNotIn(self.href('scan_engine_index'), side)
        self.assertIn(self.href('limes_settings'), side)
        self.assertNotIn(self.href('add_engine'), top)

    def test_add_engine_shortcut_follows_permission(self):
        _, top = self.shell(self.admin)
        self.assertIn(self.href('add_engine'), top)

    def test_not_found_pages_render_without_a_project(self):
        # no slug in these URLs, so no current project: the page must not need one (it used to raise NoReverseMatch -> 500)
        self.client.force_login(self.auditor)
        self.assertEqual(self.client.get('/no/such/page').status_code, 404)
        r = self.client.get(reverse('four_oh_four'))  # where permission checks send a user who may not open a page
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'Page not found')

    def test_project_and_user_names_are_escaped(self):
        Project.objects.filter(slug=SLUG).update(name='<img src=x onerror=alert(1)>')
        evil = User.objects.create_superuser('"><svg onload=alert(2)>', password='p')
        _, top = self.shell(evil)
        self.assertNotIn('<img src=x', top)
        self.assertNotIn('<svg onload', top)
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;', top)

    def test_active_link_comes_from_url_name(self):
        side, _ = self.shell(self.admin)
        active = re.findall(r'<a[^>]*aria-current="page"[^>]*>', side)
        self.assertEqual(len(active), 1)
        self.assertIn(self.href('dashboardIndex'), active[0])
