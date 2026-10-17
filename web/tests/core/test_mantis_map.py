import os
from unittest import mock, skipUnless

from django.test import SimpleTestCase

from limes.integrations import mantis


class MantisMapTest(SimpleTestCase):
    def test_map_finding(self):
        f = {'rule_id': 'secret-aws-key', 'severity': 'ERROR', 'confidence': 'HIGH',
             'path': 'static/app.js', 'start_line': 12, 'end_line': 12,
             'message': 'AWS key', 'metadata': {'cwe': 'CWE-798'}, 'verdict': 'TRUE'}
        v = mantis.map_finding(f, source_url='https://t.test/app.js')
        self.assertEqual(v['source'], 'mantis')
        self.assertEqual(v['http_url'], 'https://t.test/app.js')
        self.assertEqual(v['severity'], 3)  # ERROR -> high
        self.assertIn('secret-aws-key', v['name'])
        self.assertEqual(v['cwe_ids'], ['CWE-798'])

    def test_severity_bands(self):
        self.assertEqual(mantis.map_finding({'severity': 'WARNING', 'metadata': {}}, 's')['severity'], 2)
        self.assertEqual(mantis.map_finding({'severity': 'INFO', 'metadata': {}}, 's')['severity'], 0)

    def test_audit_dir_calls_api(self):
        with mock.patch('limes.integrations.mantis._audit', return_value=[{'severity': 'INFO', 'metadata': {}, 'path': 'a', 'rule_id': 'r'}]) as m:
            out = mantis.audit_dir('/code', packs=['secrets', 'web'])
        m.assert_called_once()
        self.assertEqual(len(out), 1)

    def test_rule_id_drops_install_path(self):
        # opengrep prefixes rule ids with the rule file's dotted install path
        f = {'rule_id': 'usr.local.lib.python3.10.dist-packages.mantis.resources.rules.secrets.secret-aws-access-key-id',
             'severity': 'ERROR', 'message': 'AWS Access Key ID literal', 'metadata': {}}
        v = mantis.map_finding(f, source_url='https://t.test/app.js')
        self.assertEqual(v['template_id'], 'secrets.secret-aws-access-key-id')
        self.assertEqual(v['type'], 'secrets.secret-aws-access-key-id')
        self.assertTrue(v['name'].startswith('secrets.secret-aws-access-key-id: '))
        self.assertNotIn('dist-packages', v['name'])

    def test_audit_dir_keeps_extra_engines_off(self):
        # mantis >= 0.2 runs trivy/grype by default, which reach the network
        with mock.patch('limes.integrations.mantis._audit', return_value=[]) as m:
            mantis.audit_dir('/code', packs=['secrets'])
        self.assertEqual(m.call_args.kwargs.get('engines'), 'none')


def _real_mantis():
    import importlib.util
    import shutil
    return importlib.util.find_spec('mantis') is not None and shutil.which('opengrep') is not None


@skipUnless(_real_mantis(), 'mantis-sast and opengrep are installed in the scan image only')
class RealMantisTest(SimpleTestCase):
    def test_finds_a_secret_in_crawled_js(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, 'app.js'), 'w') as f:
                f.write('var k = "AKIAIOSFODNN7EXAMPLE";\n')  # AWS's documented example key
            found = [mantis.map_finding(x, 'https://t.test/app.js') for x in mantis.audit_dir(d, packs=['secrets'])]
        self.assertIn('secrets.secret-aws-access-key-id', [v['template_id'] for v in found])
