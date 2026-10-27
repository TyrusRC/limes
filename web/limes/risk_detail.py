"""Data for the risk detail page: one TrackedIssue, the same issue on the project's other assets, its evidence, notes,
waiver history and the score gain of fixing it everywhere. Plain data with a fixed number of queries; every string
that came from a scan or a user is escaped by the template."""
import json

from django.db.models import Q
from django.utils import timezone

from limes import scoring
from limes.checks.catalogue import CHECKS, PROVISIONAL
from startScan.models import IssueWaiver, RiskCheck, Vulnerability

AFFECTED_LIMIT = 200
NOTE_LIMIT = 100
WAIVER_LIMIT = 50
VALUE_MAX = 500
SEVERITY_LABELS = {4: 'Critical', 3: 'High', 2: 'Medium', 1: 'Low'}

# Check texts say what is wrong and how to fix it; why it matters is told per category.
WHY = {
    'web': 'Missing or weak web protections make it easier to attack the site\'s visitors or to intercept their traffic.',
    'tls': 'Certificate and protocol problems cause browser warnings, break trust and leave traffic open to interception.',
    'email': 'Weak mail authentication lets others send mail that looks like it comes from your domain.',
    'dns': 'DNS is the base everything else relies on; gaps make hijacking and spoofing easier.',
    'network': 'Services reachable from the internet are found by automated scans within hours and attacked.',
    'vulnerabilities': 'A known weakness on an internet-facing asset can be exploited by anyone who finds it.',
    'reputation': 'Listing on an abuse feed can mean the address is compromised, and it harms mail delivery and trust.',
    'data_leakage': 'Exposed secrets or breached credentials give attackers access without exploiting anything.',
}
NO_TEXT = 'No description is recorded for this finding. Open the asset to see the scanner output.'
NO_FIX = 'No remediation text is recorded for this finding. Check the references in the scanner output.'


def _show(value):
    text = value if isinstance(value, str) else json.dumps(value, default=str, sort_keys=True)
    return text if len(text) <= VALUE_MAX else text[:VALUE_MAX] + '...'


def _evidence(issue):
    """(expected/actual pairs, other evidence rows) for a check on its asset; empty for findings."""
    if issue.source != 'check':
        return [], []
    rc = RiskCheck.objects.filter(asset_id=issue.asset_id, check_id=issue.key).values_list('evidence', flat=True).first()
    ev = rc if isinstance(rc, dict) else {}
    pairs = [(label, _show(ev[k])) for label, k in (('Expected', 'expected'), ('Actual', 'actual')) if k in ev]
    rest = [(k, _show(v)) for k, v in sorted(ev.items()) if k not in ('expected', 'actual')]
    return pairs, rest


def _finding(issue):
    """The scanner's own record for a finding, newest first; None when it cannot be matched (a hashed key, a purged scan)."""
    return (Vulnerability.objects.filter(asset_id=issue.asset_id, open_status=True)
            .filter(Q(template_id=issue.key) | Q(template_id__isnull=True, name=issue.key) | Q(template_id='', name=issue.key))
            .order_by('-id').values('name', 'description', 'impact', 'remediation', 'http_url').first())


def detected_at(issue):
    return issue.reopened_at or issue.first_seen


def build(issue, now=None):
    """Everything the page shows for `issue` (a TrackedIssue with its asset loaded)."""
    now = now or timezone.now()
    check = CHECKS.get(issue.key) if issue.source == 'check' else None
    category = scoring.category_of(issue.key)
    finding = None if check else _finding(issue)
    out = {
        'issue': issue, 'title': check.title if check else (finding['name'] if finding and finding['name'] else issue.key),
        'severity_name': scoring.SEVERITY_NAMES.get(issue.severity, 'info'),
        'severity_label': SEVERITY_LABELS.get(issue.severity, 'Informational'),
        'category': category, 'category_label': scoring.CATEGORY_LABELS.get(category, category),
        'provisional': bool(check and check.provisional), 'detected': detected_at(issue),
        'detected_text': (check.title if check else (finding and finding['description'])) or NO_TEXT,
        'why': (finding['impact'] if finding and finding['impact'] else None) or WHY.get(category, ''),
        'action': (check.fix if check else (finding and finding['remediation'])) or NO_FIX,
        'finding_url': finding['http_url'] if finding else None,
    }
    out['expected_actual'], out['evidence'] = _evidence(issue)

    siblings = list(issue.__class__.objects.filter(project_id=issue.project_id, key=issue.key, source=issue.source, status='open')
                    .select_related('asset').order_by('first_seen', 'id')[:AFFECTED_LIMIT])
    if issue.status == 'open' and all(s.id != issue.id for s in siblings):
        siblings.append(issue)
    live = set(issue.__class__.objects.filter(id__in=[s.id for s in siblings] + [issue.id])
               .filter(IssueWaiver.waived_exists(now)).values_list('id', flat=True))
    out['affected'] = [{'id': s.id, 'asset': s.asset.value, 'kind': s.asset.kind, 'detected': detected_at(s),
                        'waived': s.id in live, 'current': s.id == issue.id} for s in siblings]

    # the issue's own waivers and the project-wide ones for its key, newest first
    waivers = list(IssueWaiver.objects.filter(Q(issue=issue) | Q(issue__isnull=True, project_id=issue.project_id, key=issue.key))
                   .select_related('created_by', 'revoked_by', 'approver').order_by('-created_at', '-id')[:WAIVER_LIMIT])

    def in_force(w):
        return w.revoked_at is None and not w.approval_pending and (w.expires_at is None or w.expires_at > now)

    active = next((w for w in waivers if in_force(w)), None)
    out['waivers'] = [{'w': w, 'state': 'active' if in_force(w) else 'revoked' if w.revoked_at else 'pending' if w.approval_pending else
                       'expired' if w.expires_at and w.expires_at <= now else 'replaced'} for w in waivers]
    out['active_waiver'] = active
    out['pending_waiver'] = next((w for w in waivers if w.approval_pending and w.revoked_at is None), None)
    newest = next((w for w in waivers if not w.approval_pending), None)
    out['expired_waiver'] = newest if not active and newest and not newest.revoked_at and newest.expires_at and newest.expires_at <= now else None
    out['status'] = ('Fixed' if issue.status == 'fixed' else 'Waived' if active else
                     'Open, waiver expired' if out['expired_waiver'] else 'Open')
    out['notes'] = list(issue.notes.select_related('author').order_by('created_at', 'id')[:NOTE_LIMIT])

    fixable = [a['id'] for a in out['affected'] if not a['waived']] if issue.status == 'open' else []
    out['remediate_ids'] = ','.join(str(i) for i in fixable[:200])  # the wizard's cap
    out['impact'] = None
    if fixable and issue.key not in PROVISIONAL:
        out['impact'] = scoring.forecast(issue.project, fixable, now)
    return out
