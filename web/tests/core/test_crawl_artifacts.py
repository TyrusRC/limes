from django.test import SimpleTestCase

from limes.pipeline import crawl


class ArtifactSourceUrlTest(SimpleTestCase):
    def test_known_path(self):
        m = {'a.js': 'https://x.com/a.js'}
        self.assertEqual(crawl.artifact_source_url('/r/code_artifacts/a.js', m), 'https://x.com/a.js')

    def test_relative_and_bare_paths_resolve_by_basename(self):
        m = {'abc123.js': 'https://x.com/a.js'}
        for p in ('code_artifacts/abc123.js', 'abc123.js', '/abs/code_artifacts/abc123.js'):
            self.assertEqual(crawl.artifact_source_url(p, m), 'https://x.com/a.js')

    def test_unknown_path_falls_back(self):
        self.assertEqual(crawl.artifact_source_url('/nope', {}), '')
        self.assertEqual(crawl.artifact_source_url('/nope', {}, default='https://x.com'), 'https://x.com')


class ArgvTest(SimpleTestCase):
    def test_katana_exact_host_depth_and_identity(self):
        argv = crawl.build_katana_argv('/in.txt', 4, ['-H', 'User-Agent: ua'])
        self.assertEqual(argv[argv.index('-fs') + 1], 'fqdn')
        self.assertEqual(argv[argv.index('-d') + 1], '4')
        self.assertIn('User-Agent: ua', argv)

    def test_gau_has_no_identity(self):
        argv = crawl.build_gau_argv('example.com', threads=5)
        self.assertEqual(argv[:2], ['gau', 'example.com'])
        self.assertNotIn('-H', argv)

    def test_filter_host_urls(self):
        out = crawl.filter_host_urls(
            ['https://a.example.com/x', 'https://evilexample.com/', 'noise', 'http://example.com'], 'example.com')
        self.assertEqual(out, ['https://a.example.com/x', 'http://example.com'])
