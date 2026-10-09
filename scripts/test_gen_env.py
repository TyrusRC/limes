import base64
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLE = os.path.join(HERE, '..', '.env.example')


class GenEnvTest(unittest.TestCase):
    def run_gen(self, out):
        return subprocess.run([sys.executable, os.path.join(HERE, 'gen_env.py'), '--out', out, '--example', EXAMPLE],
                              capture_output=True, text=True)

    def parse(self, path):
        with open(path) as f:
            return dict(line.strip().split('=', 1) for line in f if '=' in line and not line.startswith('#'))

    def test_generates_unique_secrets(self):
        d = tempfile.mkdtemp()
        a, b = os.path.join(d, 'a'), os.path.join(d, 'b')
        self.assertEqual(self.run_gen(a).returncode, 0)
        self.assertEqual(self.run_gen(b).returncode, 0)
        ea, eb = self.parse(a), self.parse(b)
        for key in ('POSTGRES_PASSWORD', 'DJANGO_SUPERUSER_PASSWORD', 'LIMES_SECRET_KEY', 'AUTHORITY_PASSWORD'):
            self.assertGreaterEqual(len(ea[key]), 32, key)
            self.assertNotEqual(ea[key], eb[key], key)
            self.assertNotIn('CHANGE_ME', ea[key])
        self.assertEqual(os.stat(a).st_mode & 0o777, 0o600)

    def test_generates_valid_fernet_key(self):
        d = tempfile.mkdtemp()
        out = os.path.join(d, 'e')
        self.assertEqual(self.run_gen(out).returncode, 0)
        key = self.parse(out)['LIMES_SECRET_KEY_ENCRYPTION']
        # Fernet: urlsafe base64 of exactly 32 bytes
        self.assertEqual(len(base64.urlsafe_b64decode(key.encode())), 32)

    def test_sizes_from_host(self):
        d = tempfile.mkdtemp()
        out = os.path.join(d, 'e')
        self.run_gen(out)
        env = self.parse(out)
        self.assertRegex(env['WORKER_SCAN_MEM'], r'^\d+g$')

    def test_refuses_to_overwrite(self):
        d = tempfile.mkdtemp()
        out = os.path.join(d, 'e')
        open(out, 'w').close()
        self.assertNotEqual(self.run_gen(out).returncode, 0)


if __name__ == '__main__':
    unittest.main()
