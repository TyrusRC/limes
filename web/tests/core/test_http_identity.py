from types import SimpleNamespace

from django.test import SimpleTestCase, override_settings
from cryptography.fernet import Fernet

from limes import identity

KEY = Fernet.generate_key().decode()


@override_settings(HEADER_ENCRYPTION_KEY=KEY)
class HttpxIdentityArgsTest(SimpleTestCase):
    """The argv http_crawl/screenshot append comes from for_domain -> render_httpx."""

    def args(self, request_headers):
        domain = SimpleNamespace(request_headers=request_headers)
        argv, tmp = identity.render_httpx(identity.ScanIdentity.for_domain(domain))
        identity.cleanup(tmp)
        return argv

    def test_explicit_ua_no_random_agent(self):
        argv = self.args({'user_agent': 'Limes/1.0', 'headers': []})
        self.assertEqual(argv[:2], ['-H', 'User-Agent: Limes/1.0'])
        self.assertNotIn('-random-agent', argv)

    def test_headers_with_empty_ua_gets_default_ua(self):
        argv = self.args({'user_agent': '', 'headers': [{'name': 'X-Team', 'value': 'a'}]})
        self.assertIn(f'User-Agent: {identity.DEFAULT_UA}', argv)
        self.assertIn('X-Team: a', argv)
        self.assertNotIn('-random-agent', argv)

    def test_no_identity_still_has_ua(self):
        argv = self.args(None)
        self.assertIn(f'User-Agent: {identity.DEFAULT_UA}', argv)

    def test_secret_header_delivered_inline_and_redactable(self):
        enc = identity.encrypt('Bearer T0K3N')
        domain = SimpleNamespace(request_headers={'user_agent': 'Limes/1.0', 'headers': [
            {'name': 'Authorization', 'value': enc, 'secret': True}]})
        ident = identity.ScanIdentity.for_domain(domain)
        argv, tmp = identity.render_httpx(ident)
        # httpx -H cannot read '@file': the real header line must be in argv
        i = argv.index('Authorization: Bearer T0K3N')
        self.assertEqual(argv[i - 1], '-H')
        self.assertFalse([a for a in argv if a.startswith('@')])
        self.assertEqual(tmp, [])
        self.assertIn('User-Agent: Limes/1.0', argv)
        self.assertNotIn('-random-agent', argv)
        # the runner scrubs it from stored commands/logs
        self.assertEqual(identity.redaction_secrets(ident), ['Bearer T0K3N'])
