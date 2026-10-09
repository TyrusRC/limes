import os

from django.test import SimpleTestCase, override_settings
from cryptography.fernet import Fernet

from limes import identity

KEY = Fernet.generate_key().decode()


@override_settings(HEADER_ENCRYPTION_KEY=KEY)
class EncryptTest(SimpleTestCase):
    def test_roundtrip(self):
        token = identity.encrypt('S3cr3t')
        self.assertNotIn('S3cr3t', token)
        self.assertEqual(identity.decrypt(token), 'S3cr3t')


@override_settings(HEADER_ENCRYPTION_KEY=KEY)
class RenderTest(SimpleTestCase):
    def ident(self, ua='limes/scan', headers=()):
        return identity.ScanIdentity(user_agent=ua, headers=[identity.Header(*h) for h in headers])

    def test_httpx_sets_explicit_ua_and_no_random_agent(self):
        argv, tmp = identity.render_httpx(self.ident(ua='Limes/1.0'))
        self.assertIn('-H', argv)
        self.assertIn('User-Agent: Limes/1.0', argv)
        self.assertNotIn('-random-agent', argv)
        identity.cleanup(tmp)

    def test_headers_with_no_ua_still_get_deterministic_ua(self):
        argv, tmp = identity.render_httpx(self.ident(ua='', headers=[('X-Env', 'test', False)]))
        joined = ' '.join(argv)
        self.assertIn('User-Agent: ', joined)  # a default UA, never empty, never -random-agent
        self.assertNotIn('-random-agent', argv)
        self.assertIn('X-Env: test', argv)
        identity.cleanup(tmp)

    def test_httpx_secret_header_is_inline_not_file_ref(self):
        ident = self.ident(headers=[('Authorization', 'Bearer T0K3N', True)])
        argv, tmp = identity.render_httpx(ident)
        self.assertIn('Authorization: Bearer T0K3N', argv)
        self.assertFalse([a for a in argv if a.startswith('@')])
        self.assertEqual(tmp, [])

    def test_secret_header_not_in_argv(self):
        ident = self.ident(headers=[('Authorization', 'Bearer T0K3N', True)])
        argv, tmp = identity.render_header_args(ident)
        self.assertNotIn('Bearer T0K3N', ' '.join(argv))
        contents = ''.join(open(p).read() for p in tmp)
        self.assertIn('Bearer T0K3N', contents)
        for p in tmp:
            self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)
        identity.cleanup(tmp)
        self.assertFalse(any(os.path.exists(p) for p in tmp))

    def test_redaction_secrets_lists_only_secret_values(self):
        ident = self.ident(headers=[('Authorization', 'Bearer T0K3N', True), ('X-Env', 'test', False)])
        self.assertEqual(identity.redaction_secrets(ident), ['Bearer T0K3N'])

    def test_assay_config_written_with_identity(self):
        ident = self.ident(ua='Limes/1.0', headers=[('X-Env', 'test', False)])
        import tempfile
        path = tempfile.mktemp(suffix='.yaml')
        tmp = identity.write_assay_config(ident, profile='normal', path=path)
        body = open(path).read()
        self.assertIn('Limes/1.0', body)
        self.assertIn('X-Env: test', body)
        self.assertIn('normal', body)
        identity.cleanup(tmp + [path])
