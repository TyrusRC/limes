"""assay (DAST) integration.

Tool allowlist. assay dispatches to every external tool it finds on PATH (sqlmap, commix,
nikto, katana, gau, ...), and has no switch to turn that off. Limes runs assay with a PATH that
holds ONLY /opt/limes/assay-bin (symlinks to approved tools, built in web/Dockerfile) and
refuses to scan when `assay tools list` reports any other tool as available. Limes runs
katana/gau itself with its own rate and identity controls, so assay must not run them too.

To approve a tool: add it to ASSAY_TOOL_ALLOWLIST here AND add its symlink in the Dockerfile
"assay-bin" step. Never approve exploit-class tools (sqlmap, commix, ghauri, tplmap, dalfox):
scheduled scans would then run them automatically against production targets.
"""
import os
import re
import shutil
import time

from limes import commands
from limes.integrations.severity import to_int

ASSAY_TOOL_ALLOWLIST = ('nuclei',)
ASSAY_BIN_DIR = '/opt/limes/assay-bin'
PREFLIGHT_TTL = 600
PREFLIGHT_TIMEOUT = 30
_cache = {}

DESTRUCTIVE_FLAGS = frozenset({'--h2-reset', '--h2-continuation', '--h2-madeyoureset',
                               '--redos', '--mass-assign', '--proto-pollution-server', '--rate-limit'})


class AssayError(Exception):
    pass


def is_success(code):
    """assay exit codes: 0 = clean, 2 = findings crossed a fail-on threshold
    (success-with-findings). Any other code (incl. 1) is a real failure."""
    return code in (0, 2)


def build_argv(targets_file, profile, identity_config_path, output_dir, extra_no_flags):
    argv = ['assay', 'scan', '-l', targets_file, '--profile', profile,
            '--config', identity_config_path, '--output-dir', output_dir, '--json']
    argv += [f for f in extra_no_flags if f not in DESTRUCTIVE_FLAGS]
    return argv


def parse_report(report_json):
    result = (report_json or {}).get('scan_result') or {}
    vulns = []
    for f in result.get('findings') or []:
        # assay puts both CVE and CWE ids in its `cwe` array; split by prefix.
        ids = f.get('cwe') or []
        vulns.append({
            'name': f.get('title') or f.get('type', 'assay finding'),
            'type': f.get('type', ''),
            'severity': to_int(f.get('severity', 'unknown')),
            'http_url': f.get('url', ''),
            'description': f.get('description', ''),
            'remediation': f.get('remediation', ''),
            'cvss_score': f.get('cvss'),
            'cvss_metrics': f.get('cvss_vector', ''),
            'cve_ids': [c for c in ids if c.upper().startswith('CVE')],
            'cwe_ids': [c for c in ids if c.upper().startswith('CWE')],
            'references': f.get('references', []),
            'request': f.get('request', ''),
            'response': f.get('response', ''),
            'matcher_name': f.get('parameter', ''),
            'source': 'assay',
        })
    return vulns


def restricted_env():
    """Current environment (HOME etc. kept) with PATH replaced by the allowlist dir alone.

    NOTE: assay's chromium lookup (go-rod) also uses PATH; the image ships no chromium, so
    headless checks fall back to rod's own download under HOME. If chromium is ever added,
    pass its location explicitly here instead of widening PATH."""
    return {**os.environ, 'PATH': ASSAY_BIN_DIR}


_LIST_NAME = re.compile(r'^ {1,4}([a-z0-9][\w.-]*)\s*$')
_CHECK_LINE = re.compile(r'^\s*([✓✗])\s+([a-z0-9][\w.-]*)')


def parse_available_tools(text):
    """Names of tools reported available by `assay tools list` (or `tools check`).
    Raises AssayError when no tool entry is recognised at all (fail closed)."""
    available, seen, current = set(), False, None
    for line in (text or '').splitlines():
        m = _CHECK_LINE.match(line)
        if m:
            seen = True
            if m.group(1) == '✓':
                available.add(m.group(2))
            continue
        m = _LIST_NAME.match(line)
        if m:
            current = m.group(1)
            seen = True
            continue
        if current and 'Status:' in line:
            if 'Available' in line and 'Not Available' not in line and '✗' not in line:
                available.add(current)
            current = None
    if not seen:
        raise AssayError(f'cannot parse `assay tools list` output: {(text or "")[:200]!r}')
    return available


def preflight(assay_bin, env, run=commands.run, now=time.monotonic):
    """Fail closed unless every tool assay can see (under env) is on the allowlist.
    Only a pass is cached (per worker process, PREFLIGHT_TTL)."""
    key = (assay_bin, env.get('PATH'))
    hit = _cache.get(key)
    if hit is not None and now() - hit < PREFLIGHT_TTL:
        return
    res = run([assay_bin, 'tools', 'list'], timeout=PREFLIGHT_TIMEOUT, env=env)
    if res.return_code != 0:
        raise AssayError(f'assay tools preflight failed (exit {res.return_code}): {res.output_tail}')
    extra = sorted(parse_available_tools(res.output) - set(ASSAY_TOOL_ALLOWLIST))
    if extra:
        raise AssayError('assay can see tools outside the allowlist, refusing to scan: '
                         + ', '.join(extra) + f' (allowed: {", ".join(ASSAY_TOOL_ALLOWLIST)})')
    _cache[key] = now()


def prepare():
    """-> (assay absolute path, restricted env), after a passing preflight."""
    assay_bin = shutil.which('assay')
    if not assay_bin:
        raise AssayError('assay binary not found on PATH')
    env = restricted_env()
    preflight(assay_bin, env)
    return assay_bin, env
