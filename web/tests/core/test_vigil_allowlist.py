import os
import sys
import time
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from limes import commands
from limes.integrations import assay

OLD = """Registered Security Tools:
==========================

  sqlmap
    Status:  ✗ Not Available
    Automatic SQL injection detection and exploitation

  nuclei
    Status:  ✓ Available
    Version: 3.1.0
    ProjectDiscovery Nuclei
"""
CHECK = """Tool Health Check:
==================

  ✓ nuclei (v3.1.0) - OK
  ✗ sqlmap - Not found in PATH
"""
PY = sys.executable


def out(text, code=0):
    return SimpleNamespace(return_code=code, timed_out=False, output=text, output_tail=text)


class EnvTest(SimpleTestCase):
    def test_path_is_only_the_allowlist_dir(self):
        with mock.patch.dict(os.environ, {'PATH': '/go/bin:/usr/bin', 'HOME': '/root'}):
            env = assay.restricted_env()
        self.assertEqual(env['PATH'], assay.ASSAY_BIN_DIR)
        self.assertEqual(env['HOME'], '/root')

    def test_secrets_are_dropped_and_basics_kept(self):
        leaky = {'POSTGRES_PASSWORD': 'x', 'LIMES_SECRET_KEY': 'x', 'AI_GATEWAY_API_KEY': 'x',
                 'NVD_API_KEY': 'x', 'GITHUB_TOKEN': 'x', 'HOME': '/root', 'LANG': 'C.UTF-8',
                 'https_proxy': 'http://p:1', 'PATH': '/go/bin'}
        with mock.patch.dict(os.environ, leaky, clear=True):
            env = assay.restricted_env()
        self.assertEqual(env, {'PATH': assay.ASSAY_BIN_DIR, 'HOME': '/root', 'LANG': 'C.UTF-8',
                               'https_proxy': 'http://p:1'})

    def test_preflight_and_scan_get_the_minimal_env(self):
        with mock.patch.dict(os.environ, {'POSTGRES_PASSWORD': 'x', 'HOME': '/root'}), \
                mock.patch('shutil.which', return_value='/usr/bin/assay'), \
                mock.patch.object(assay, 'preflight') as pf:
            assay_bin, env = assay.prepare(exists=lambda p: False)
        self.assertNotIn('POSTGRES_PASSWORD', env)
        self.assertNotIn('POSTGRES_PASSWORD', pf.call_args.args[1])
        self.assertEqual(pf.call_args.args[1], env)

    def test_allowlist_is_nuclei_only(self):
        self.assertEqual(assay.ASSAY_TOOL_ALLOWLIST, ('nuclei',))


class ParseTest(SimpleTestCase):
    def test_list_format(self):
        self.assertEqual(assay.parse_available_tools(OLD), {'nuclei'})

    def test_check_format(self):
        self.assertEqual(assay.parse_available_tools(CHECK), {'nuclei'})

    def test_none_available_is_valid(self):
        self.assertEqual(assay.parse_available_tools(OLD.replace('✓ Available', '✗ Not Available')), set())

    def test_unknown_status_wording_counts_as_available(self):
        self.assertEqual(assay.parse_available_tools(OLD.replace('✓ Available', '✓ Ready')), {'nuclei'})

    def test_listed_tool_without_status_fails_closed(self):
        with self.assertRaises(assay.AssayError):
            assay.parse_available_tools('Registered Security Tools:\n\n  nuclei\n    desc\n')

    def test_only_two_space_indent_is_a_name(self):
        text = OLD.replace('    ProjectDiscovery Nuclei', '    ProjectDiscovery\n      Nuclei').replace(
            '    Version: 3.1.0', '    Version: 3.1.0\n    extra')
        self.assertEqual(assay.parse_available_tools(text), {'nuclei'})

    def test_garbage_fails_closed(self):
        with self.assertRaises(assay.AssayError):
            assay.parse_available_tools('panic: something\n')
        with self.assertRaises(assay.AssayError):
            assay.parse_available_tools('')


class PreflightTest(SimpleTestCase):
    def setUp(self):
        assay._cache.clear()

    def test_ok_runs_with_restricted_env_and_is_cached(self):
        run = mock.Mock(return_value=out(OLD))
        env = {'PATH': assay.ASSAY_BIN_DIR}
        assay.preflight('/usr/bin/assay', env, run=run)
        assay.preflight('/usr/bin/assay', env, run=run)
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0], ['/usr/bin/assay', 'tools', 'list'])
        self.assertEqual(run.call_args.kwargs['env'], env)
        self.assertTrue(run.call_args.kwargs['timeout'])

    def test_unexpected_tool_raises_and_is_not_cached(self):
        bad = OLD.replace('sqlmap\n    Status:  ✗ Not Available', 'sqlmap\n    Status:  ✓ Available')
        run = mock.Mock(return_value=out(bad))
        with self.assertRaises(assay.AssayError) as cm:
            assay.preflight('/usr/bin/assay', {}, run=run)
        self.assertIn('sqlmap', str(cm.exception))
        with self.assertRaises(assay.AssayError):
            assay.preflight('/usr/bin/assay', {}, run=run)
        self.assertEqual(run.call_count, 2)

    def test_command_failure_fails_closed(self):
        with self.assertRaises(assay.AssayError):
            assay.preflight('/usr/bin/assay', {}, run=mock.Mock(return_value=out(OLD, code=1)))
        with self.assertRaises(assay.AssayError):
            assay.preflight('/usr/bin/assay', {}, run=mock.Mock(return_value=out('', code=None)))

    def test_cache_expires(self):
        run = mock.Mock(return_value=out(OLD))
        assay.preflight('/a', {}, run=run, now=lambda: 0)
        assay.preflight('/a', {}, run=run, now=lambda: assay.PREFLIGHT_TTL + 1)
        self.assertEqual(run.call_count, 2)

    def test_missing_binary(self):
        with mock.patch('shutil.which', return_value=None), self.assertRaises(assay.AssayError):
            assay.prepare()


class FixedPathsTest(SimpleTestCase):
    def prep(self, present):
        with mock.patch('shutil.which', return_value='/usr/bin/assay'), \
                mock.patch.object(assay, 'preflight'):
            return assay.prepare(exists=lambda p: p in present)

    def test_fake_sqlmap_in_usr_local_bin(self):
        with self.assertRaises(assay.AssayError) as cm:
            self.prep({'/usr/local/bin/sqlmap'})
        self.assertIn('/usr/local/bin/sqlmap', str(cm.exception))

    def test_katana_in_go_bin_is_not_probed_by_assay(self):
        self.prep({'/go/bin/katana', '/go/bin/gau', '/go/bin/nuclei'})

    def test_katana_in_root_go_bin(self):
        with self.assertRaises(assay.AssayError):
            self.prep({'/root/go/bin/katana'})

    def test_opt_script_and_allowlisted_nuclei(self):
        with self.assertRaises(assay.AssayError):
            self.prep({'/opt/sqlmap/sqlmap.py'})
        self.prep({'/usr/bin/nuclei', '/opt/nuclei/nuclei'})


class CommandsEnvTest(SimpleTestCase):
    def test_env_is_passed_to_subprocess(self):
        r = commands.run([PY, '-c', 'import os;print(os.environ.get("LIMES_T"))'],
                         env={**os.environ, 'LIMES_T': 'yes'})
        self.assertEqual(r.output.strip(), 'yes')

    def test_default_inherits_environment(self):
        with mock.patch.dict(os.environ, {'LIMES_T2': 'inh'}):
            r = commands.run([PY, '-c', 'import os;print(os.environ.get("LIMES_T2"))'])
        self.assertEqual(r.output.strip(), 'inh')
