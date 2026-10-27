"""vigil (DAST) integration.

Tool allowlist. vigil dispatches to every external tool it finds on PATH (sqlmap, commix,
nikto, katana, gau, ...), and has no switch to turn that off. Limes runs vigil with a PATH that
holds ONLY /opt/limes/vigil-bin (symlinks to approved tools, built in web/Dockerfile) and
refuses to scan when `vigil tools list` reports any other tool as available. Limes runs
katana/gau itself with its own rate and identity controls, so vigil must not run them too.

To approve a tool: add it to VIGIL_TOOL_ALLOWLIST here AND add its symlink in the Dockerfile
"vigil-bin" step. Never approve exploit-class tools (sqlmap, commix, ghauri, tplmap, dalfox):
scheduled scans would then run them automatically against production targets.
"""
import os
import re
import shutil
import time

from limes import commands
from limes.integrations.severity import to_int

VIGIL_TOOL_ALLOWLIST = ('nuclei',)
VIGIL_BIN_DIR = '/opt/limes/vigil-bin'
PREFLIGHT_TTL = 600
PREFLIGHT_TIMEOUT = 30
_cache = {}

DESTRUCTIVE_FLAGS = frozenset({'--h2-reset', '--h2-continuation', '--h2-madeyoureset',
                               '--redos', '--mass-assign', '--proto-pollution-server', '--rate-limit'})


class VigilError(Exception):
    pass


def is_success(code):
    """vigil exit codes: 0 = clean, 2 = findings crossed a fail-on threshold
    (success-with-findings). Any other code (incl. 1) is a real failure."""
    return code in (0, 2)


def build_argv(targets_file, profile, identity_config_path, output_dir, extra_no_flags):
    argv = ['vigil', 'scan', '-l', targets_file, '--profile', profile,
            '--config', identity_config_path, '--output-dir', output_dir, '--json']
    argv += [f for f in extra_no_flags if f not in DESTRUCTIVE_FLAGS]
    return argv


def parse_report(report_json):
    result = (report_json or {}).get('scan_result') or {}
    vulns = []
    for f in result.get('findings') or []:
        # vigil puts both CVE and CWE ids in its `cwe` array; split by prefix.
        ids = f.get('cwe') or []
        vulns.append({
            'name': f.get('title') or f.get('type', 'vigil finding'),
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
            'source': 'vigil',
        })
    return vulns


# Allow-list, not deny-list: everything else (DB/Django secrets, vigil's own AI_GATEWAY_API_KEY,
# NVD_API_KEY, GITHUB_TOKEN ...) is dropped. Identity/auth reaches vigil through --config, not env.
ENV_PASSTHROUGH = ('HOME', 'LANG', 'LC_ALL', 'TMPDIR', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
                   'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy')

# Locations each vigil tool wrapper probes outside PATH (read from vigil's internal/tools/*).
# /go/bin is deliberately absent: vigil does not probe it, and Limes's katana/gau live there.
_BIN_DIRS = ('/usr/bin', '/usr/local/bin')
_GO_DIRS = ('/root/go/bin', '/home/kali/go/bin')
FIXED_TOOL_PATHS = {
    'arjun': ('/usr/bin/arjun', '/usr/local/bin/arjun', '/home/kali/.local/bin/arjun'),
    'commix': tuple(f'{d}/commix' for d in _BIN_DIRS) + ('/opt/commix/commix.py',),
    'dalfox': tuple(f'{d}/dalfox' for d in _BIN_DIRS + _GO_DIRS),
    'feroxbuster': tuple(f'{d}/feroxbuster' for d in _BIN_DIRS),
    'gau': tuple(f'{d}/gau' for d in _BIN_DIRS + _GO_DIRS),
    'ghauri': tuple(f'{d}/ghauri' for d in _BIN_DIRS) + ('/opt/ghauri/ghauri.py',),
    'katana': tuple(f'{d}/katana' for d in _BIN_DIRS + _GO_DIRS),
    'nikto': tuple(f'{d}/nikto' for d in _BIN_DIRS) + ('/opt/nikto/nikto.pl',),
    'nuclei': tuple(f'{d}/nuclei' for d in _BIN_DIRS) + ('/opt/nuclei/nuclei',),
    'sqlmap': tuple(f'{d}/sqlmap' for d in _BIN_DIRS) + ('/opt/sqlmap/sqlmap.py',),
    'tplmap': tuple(f'{d}/tplmap' for d in _BIN_DIRS) + ('/opt/tplmap/tplmap.py',),
    'wpscan': tuple(f'{d}/wpscan' for d in _BIN_DIRS) + ('/opt/wpscan/wpscan.rb',),
}


def restricted_env():
    """Minimal environment for vigil: PATH is the allowlist dir alone, plus ENV_PASSTHROUGH
    names that are set in the parent.

    NOTE: vigil's chromium lookup (go-rod) also uses PATH; the image ships no chromium, so
    headless checks fall back to rod's own download under HOME. If chromium is ever added,
    pass its location explicitly here instead of widening PATH."""
    env = {k: os.environ[k] for k in ENV_PASSTHROUGH if k in os.environ}
    env['PATH'] = VIGIL_BIN_DIR
    return env


def check_fixed_paths(exists=os.path.exists):
    """vigil also probes fixed paths outside PATH, and `tools list` hides some tools
    (katana, gau, ...). Fail closed if any non-allowlisted tool sits where vigil would find it."""
    found = sorted(p for name, paths in FIXED_TOOL_PATHS.items() if name not in VIGIL_TOOL_ALLOWLIST
                   for p in paths if exists(p))
    if found:
        raise VigilError('vigil would find non-allowlisted tools at fixed paths, refusing to scan: '
                         + ', '.join(found))


_LIST_NAME = re.compile(r'^  ([a-z0-9][\w.-]*)\s*$')
_STATUS = re.compile(r'^\s+Status:\s*(.*?)\s*$')
_CHECK_LINE = re.compile(r'^\s*([✓✗])\s+([a-z0-9][\w.-]*)')


def parse_available_tools(text):
    """Names of tools reported available by `vigil tools list` (or `tools check`).
    A listed tool is available unless its status explicitly says unavailable. Raises
    VigilError (fail closed) if nothing is recognised or a listed tool has no status."""
    available, seen, current = set(), False, None
    unparseable = VigilError(f'cannot parse `vigil tools list` output: {(text or "")[:200]!r}')
    for line in (text or '').splitlines():
        m = _CHECK_LINE.match(line)
        if m:
            seen = True
            if m.group(1) == '✓':
                available.add(m.group(2))
            continue
        m = _LIST_NAME.match(line)
        if m:
            if current is not None:
                raise unparseable
            current, seen = m.group(1), True
            continue
        m = _STATUS.match(line)
        if m and current:
            status = m.group(1)
            if not status:
                raise unparseable
            if '✗' not in status and 'not available' not in status.lower():
                available.add(current)
            current = None
    if not seen or current is not None:
        raise unparseable
    return available


def preflight(vigil_bin, env, run=commands.run, now=time.monotonic):
    """Fail closed unless every tool vigil can see (under env) is on the allowlist.
    Only a pass is cached (per worker process, PREFLIGHT_TTL)."""
    key = (vigil_bin, env.get('PATH'))
    hit = _cache.get(key)
    if hit is not None and now() - hit < PREFLIGHT_TTL:
        return
    res = run([vigil_bin, 'tools', 'list'], timeout=PREFLIGHT_TIMEOUT, env=env)
    if res.return_code != 0:
        raise VigilError(f'vigil tools preflight failed (exit {res.return_code}): {res.output_tail}')
    extra = sorted(parse_available_tools(res.output) - set(VIGIL_TOOL_ALLOWLIST))
    if extra:
        raise VigilError('vigil can see tools outside the allowlist, refusing to scan: '
                         + ', '.join(extra) + f' (allowed: {", ".join(VIGIL_TOOL_ALLOWLIST)})')
    _cache[key] = now()


def prepare(exists=os.path.exists):
    """-> (vigil absolute path, restricted env), after the fixed-path check and preflight."""
    vigil_bin = shutil.which('vigil')
    if not vigil_bin:
        raise VigilError('vigil binary not found on PATH')
    check_fixed_paths(exists)
    env = restricted_env()
    preflight(vigil_bin, env)
    return vigil_bin, env
