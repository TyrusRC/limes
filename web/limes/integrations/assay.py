from limes.integrations.severity import to_int

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
