from django.test import SimpleTestCase

from api.serializers import InAppNotificationSerializer
from dashboard.models import InAppNotification


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

