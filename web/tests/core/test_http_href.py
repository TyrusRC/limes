from django.test import SimpleTestCase

from startScan.templatetags.custom_tags import http_href


class HttpHrefTest(SimpleTestCase):
    """Links built from scan data must never carry a script scheme."""

    def test_non_http_schemes_are_neutralised(self):
        for value in ('JaVaScript:x', ' javascript:x', 'java\tscript:x', 'data:text/html,x', None, ''):
            with self.subTest(value=value):
                self.assertIn(http_href(value), ('', '#'))

    def test_http_urls_pass(self):
        self.assertEqual(http_href('https://a'), 'https://a')
        self.assertEqual(http_href(' https://a'), 'https://a')
        self.assertEqual(http_href('HTTP://a'), 'HTTP://a')
