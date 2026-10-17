MANTIS_SEVERITY = {'ERROR': 3, 'WARNING': 2, 'INFO': 0}


class MantisError(Exception):
    pass


def _audit(code_dir, packs, llm, engines):
    # Lazy import: mantis-sast is a runtime dep; keep module importable without it.
    from mantis import audit
    return audit(code_dir, packs=packs, llm=llm, engines=engines)


def audit_dir(code_dir, packs, llm=False):
    try:
        # engines='none': mantis >= 0.2 also runs trivy/grype by default, which reach the network
        return _audit(code_dir, packs=packs, llm=llm, engines='none')
    except Exception as e:
        raise MantisError(f'mantis audit failed: {e}') from e


def map_finding(finding, source_url):
    """Map a mantis finding dict to save_vulnerability kwargs."""
    # opengrep prefixes rule ids with the rule file's dotted install path; keep '<pack>.<rule>'
    rule_id = (finding.get('rule_id') or 'mantis').rsplit('.rules.', 1)[-1]
    message = finding.get('message') or ''
    cwe = (finding.get('metadata') or {}).get('cwe')
    where = finding.get('path') or ''
    if finding.get('start_line'):
        where += f":{finding['start_line']}"
    return {
        'name': f'{rule_id}: {message[:120]}',
        'type': rule_id,
        'template_id': rule_id,
        'severity': MANTIS_SEVERITY.get(str(finding.get('severity')).upper(), 0),
        'http_url': source_url,
        'description': f'{message}\n\nLocation: {where}' if where else message,
        'cwe_ids': [cwe] if cwe else [],
        'matcher_name': where,
        'source': 'mantis',
    }
