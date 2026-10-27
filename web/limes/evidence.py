"""The scanner evidence behind a finding issue: the open Vulnerability rows of the issue's asset with the same key."""
from limes import scoring
from startScan.models import Vulnerability

MAX_ROWS = 5
TEXT_CAP = 20000  # request/response bodies can be megabytes; the page shows the first part


def _cap(text, cap=TEXT_CAP):
    return (text or '')[:cap]


def issue_evidence(issue):
    """Newest-first evidence rows for a 'finding' issue; a check issue has none (its result lives on the RiskCheck)."""
    if issue.source != 'finding':
        return []
    rows = (Vulnerability.objects.filter(asset_id=issue.asset_id, open_status=True)
            .prefetch_related('cve_ids').order_by('-discovered_date', '-id'))
    out = []
    for v in rows.iterator():
        if scoring.issue_key(v.template_id or v.name) != issue.key:
            continue
        out.append({
            'name': v.name, 'template_id': v.template_id, 'matcher_name': v.matcher_name, 'http_url': v.http_url,
            'severity': v.severity, 'cvss_score': v.cvss_score, 'discovered_date': v.discovered_date,
            'description': _cap(v.description), 'impact': _cap(v.impact), 'remediation': _cap(v.remediation),
            'curl_command': _cap(v.curl_command, 2000), 'request': _cap(v.request), 'response': _cap(v.response),
            'extracted_results': [_cap(r, 2000) for r in (v.extracted_results or [])[:20]],
            'cves': sorted(c.name for c in v.cve_ids.all()), 'references': sorted(v.reference_urls or [])[:20],
        })
        if len(out) >= MAX_ROWS:
            break
    return out
