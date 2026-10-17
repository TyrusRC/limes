from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.test import SimpleTestCase, TestCase
from django.utils import timezone
from rolepermissions.roles import assign_role

from api.serializers import InAppNotificationSerializer
from dashboard.models import InAppNotification, Project
from dashboard.views import on_user_logged_in
from targetApp.models import Domain, Organization


class OrganizationDomainListTest(TestCase):
    def setUp(self):
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        user = User.objects.create_user('u', password='p')
        assign_role(user, 'sys_admin')
        self.client.force_login(user)
        now = timezone.now()
        self.project = Project.objects.create(name='p1', slug='p1', insert_date=now)
        self.org = Organization.objects.create(name='o', insert_date=now, project=self.project)
        self.domains = [Domain.objects.create(name=f'd{i}.test', project=self.project, insert_date=now) for i in (1, 2)]
        self.org.domains.add(*self.domains)

    def test_update_page_preselects_domain_ids(self):
        self.client.get(f'/target/p1/update/organization/{self.org.id}')  # warm-up (lazy prefs creation)
        r = self.client.get(f'/target/p1/update/organization/{self.org.id}')
        self.assertEqual(r.status_code, 200)
        ids = ', '.join(f"'{d.id}'" for d in self.domains)
        self.assertIn(f"$('#domains').val([{ids}]).change();", r.content.decode())


class NotificationRedirectLinkTest(SimpleTestCase):
    SAFE = ['/scan/p1/detail/3', 'scan/3', '/', 'https://example.test/x', 'HTTP://example.test']
    UNSAFE = ['javascript:alert(1)', ' JavaScript:x', 'java\tscript:x', '\x01javascript:x', 'data:text/html,x',
              '//evil.test', '/\\evil.test', '/\t/evil.test', 'https:evil.test', 'ftp://example.test']

    def link(self, url):
        return InAppNotificationSerializer(InAppNotification(title='t', redirect_link=url)).data['redirect_link']

    def test_safe_links_pass(self):
        for url in self.SAFE:
            with self.subTest(url=url):
                self.assertEqual(self.link(url), url)

    def test_unsafe_links_dropped(self):
        for url in self.UNSAFE + ['', None]:
            with self.subTest(url=url):
                self.assertIsNone(self.link(url))

