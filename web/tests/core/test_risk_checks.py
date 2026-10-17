from django.db import IntegrityError, transaction
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.checks.catalogue import CHECKS, RISKY_PORTS
from startScan.asset_models import Asset, RiskCheck

SPEC = {
    'web.https_missing': 3, 'web.http_no_redirect': 2, 'web.hsts_missing': 2, 'web.csp_missing': 1,
    'web.frame_options_missing': 1, 'web.content_type_options_missing': 1,
    'web.cookie_flags_missing': 1, 'web.version_disclosure': 1,
    'tls.cert_expired': 3, 'tls.cert_expiring': 2, 'tls.cert_hostname_mismatch': 3,
    'tls.cert_untrusted': 3, 'tls.legacy_protocol': 2,
    'email.spf_missing': 2, 'email.spf_permissive': 2, 'email.dmarc_missing': 2,
    'email.dmarc_none': 1, 'email.mx_unprotected': 1,
    'dns.dnssec_missing': 1, 'dns.caa_missing': 1,
}
PORTS = {'ftp': 21, 'telnet': 23, 'smb': 445, 'rdp': 3389, 'mssql': 1433, 'oracle': 1521,
         'mysql': 3306, 'postgres': 5432, 'redis': 6379, 'elasticsearch': 9200,
         'memcached': 11211, 'mongodb': 27017, 'docker': 2375, 'vnc': 5900}


class CatalogueTest(SimpleTestCase):
    def test_ids_and_severities_match_the_spec(self):
        want = dict(SPEC)
        want.update({f'net.exposed_{s}': 2 if s == 'ftp' else 3 for s in PORTS})
        self.assertEqual({k: c.severity for k, c in CHECKS.items()}, want)
        self.assertEqual(CHECKS['net.exposed_ftp'].severity, 2)
        self.assertEqual({p: v[0] for p, v in RISKY_PORTS.items()}, {p: s for s, p in PORTS.items()})
        for port, (svc, sev) in RISKY_PORTS.items():
            self.assertEqual(sev, CHECKS[f'net.exposed_{svc}'].severity)
        for k, c in CHECKS.items():
            self.assertEqual(c.id, k)

    def test_every_check_has_title_and_fix(self):
        for c in CHECKS.values():
            for text in (c.title, c.fix):
                self.assertTrue(text.strip(), c.id)
                self.assertNotIn('\n', text, c.id)


class RiskCheckModelTest(TestCase):
    def test_one_row_per_asset_and_check(self):
        project = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        asset = Asset.objects.create(project=project, kind='hostname', value='a.example.com')
        RiskCheck.objects.create(asset=asset, check_id='web.hsts_missing', status='fail', severity=2)
        with self.assertRaises(IntegrityError), transaction.atomic():
            RiskCheck.objects.create(asset=asset, check_id='web.hsts_missing', status='pass', severity=2)
