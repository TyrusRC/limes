from unittest import mock

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
