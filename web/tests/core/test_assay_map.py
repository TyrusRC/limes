import json
import pathlib

from django.test import SimpleTestCase

from limes.integrations import assay, severity

FIX = pathlib.Path(__file__).parent / 'fixtures' / 'assay_report_sample.json'


class SeverityTest(SimpleTestCase):
    def test_map(self):
        self.assertEqual((severity.to_int('critical'), severity.to_int('info'), severity.to_int('weird')), (4, 0, -1))


class AssayArgvTest(SimpleTestCase):
    def test_argv_has_json_profile_and_no_destructive_flags(self):
        argv = assay.build_argv('/t.txt', 'normal', '/id.yaml', '/out', extra_no_flags=[])
        self.assertIn('--json', argv)
        self.assertIn('--profile', argv)
        self.assertIn('normal', argv)
        self.assertFalse(assay.DESTRUCTIVE_FLAGS & set(argv))

    def test_passive_profile(self):
        argv = assay.build_argv('/t.txt', 'passive', '/id.yaml', '/out', extra_no_flags=['--no-postmessage'])
        self.assertIn('passive', argv)
        self.assertIn('--no-postmessage', argv)


class AssayParseTest(SimpleTestCase):
    def test_maps_findings(self):
        report = json.loads(FIX.read_text())
        vulns = assay.parse_report(report)
        self.assertEqual(len(vulns), 1)
        v = vulns[0]
        self.assertEqual(v['severity'], 3)
        self.assertEqual(v['http_url'], 'https://t.test/a?id=1')
        self.assertEqual(v['source'], 'assay')
        self.assertEqual(v['cwe_ids'], ['CWE-89'])
        self.assertAlmostEqual(v['cvss_score'], 8.2)
        self.assertEqual(v['name'], 'SQLi')

    def test_empty_findings(self):
        self.assertEqual(assay.parse_report({'scan_result': {'findings': []}}), [])
        self.assertEqual(assay.parse_report({}), [])
