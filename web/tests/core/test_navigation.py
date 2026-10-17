import re

from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rolepermissions.checkers import has_permission
from rolepermissions.roles import assign_role

from dashboard.models import Project
from dashboard.views import on_user_logged_in

SLUG = 'p1'

# Every link the old top_nav.html carried, with the permission that gated it (None = everyone).
NAV = {
    'dashboardIndex': None, 'list_target': None, 'scan_history': None, 'subscan_history': None,
    'scheduled_scan_view': None, 'assets': None, 'issues': None, 'all_subdomains': None,
    'all_endpoints': None, 'all_vulns': None, 'list_note': None, 'list_organization': None,
    'scan_engine_index': 'modify_scan_configurations',
    'wordlist_list': 'modify_wordlists',
    'interesting_lookup': 'modify_interesting_lookup',
    'proxy_settings': 'modify_scan_configurations',
    'tool_settings': 'modify_scan_configurations',
    'api_vault': 'modify_system_configurations',
    'llm_toolkit': 'modify_system_configurations',
    'report_settings': 'modify_scan_report',
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
        self.assertNotIn(self.href('api_vault'), side)
        self.assertIn(self.href('report_settings'), side)

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
