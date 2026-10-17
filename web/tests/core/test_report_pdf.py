from django.test import SimpleTestCase

from startScan.views import executive_summary_html, report_url_fetcher


class ExecutiveSummaryTest(SimpleTestCase):
    """Scan-derived values are text in the PDF summary, never markup."""

    def test_substituted_values_are_escaped(self):
        html = executive_summary_html(
            'Target **{target_name}**: {target_description}',
            {'{target_name}': '<img src="http://169.254.169.254/x">',
             '{target_description}': '<link rel=attachment href="file:///etc/passwd">'})
        self.assertNotIn('<img', html)
        self.assertNotIn('<link', html)
        self.assertIn('&lt;img', html)
        self.assertIn('<strong>', html)


class ReportFetcherTest(SimpleTestCase):
    """The PDF renderer only fetches what the report templates need."""

    def test_local_and_internal_urls_are_refused(self):
        for url in ('file:///etc/passwd', 'http://127.0.0.1:8000/', 'http://169.254.169.254/latest',
                    'https://evil.example/x.png', 'FILE:///etc/passwd'):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    report_url_fetcher(url)

    def test_inline_images_are_allowed(self):
        result = report_url_fetcher('data:text/plain;base64,aGk=')
        self.assertEqual(result['mime_type'], 'text/plain')
