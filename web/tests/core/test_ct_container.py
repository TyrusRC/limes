import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from django.test import SimpleTestCase

WEB = Path(__file__).resolve().parents[2]
COMPOSE = (WEB.parent / 'docker-compose.yml').read_text()


class ReadOnlyContainer(SimpleTestCase):
    """The ct-watch service runs with a read-only root filesystem, so settings must not open log files in the cwd."""

    def run_setup(self, **extra):
        with tempfile.TemporaryDirectory() as cwd:
            os.chmod(cwd, 0o555)
            env = {**os.environ, 'PYTHONPATH': str(WEB), 'DJANGO_SETTINGS_MODULE': 'limes.settings', **extra}
            return subprocess.run([sys.executable, '-c', 'import django; django.setup()'], cwd=cwd, env=env,
                                  capture_output=True, text=True, timeout=60)

    @unittest.skipIf(os.geteuid() == 0, 'root ignores directory modes')
    def test_log_dir_setting_keeps_logs_out_of_the_cwd(self):
        self.assertIn('Unable to configure handler', self.run_setup().stderr)  # the default is unchanged
        with tempfile.TemporaryDirectory() as logs:
            r = self.run_setup(LIMES_LOG_DIR=logs)
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_compose_points_the_watcher_logs_at_tmp(self):
        block = COMPOSE.split('  ct-watch:')[1].split('\nnetworks:')[0]
        self.assertIn('LIMES_LOG_DIR: /tmp', block)
