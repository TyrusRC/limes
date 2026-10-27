"""Template-only extras for a report: waiver and remediation-request figures, read from the same models the live
pages use (IssueWaiver.active_q, RemediationRequest). Only computed when a template asks for them."""
from datetime import timedelta

from django.db.models import Q

from startScan.models import IssueWaiver
from remediation.models import RemediationRequest

SOON = 30  # days: a waiver ending within this window is listed as expiring


def waivers(project, now, ids):
    """Active waivers by kind and how many end soon or await approval. With a tag filter, only waivers of tagged assets' issues."""
    base = IssueWaiver.objects.filter(Q(issue__project=project) | Q(issue__isnull=True, project=project))
    if ids is not None:
        base = base.filter(issue__asset_id__in=list(ids))
    active = base.filter(IssueWaiver.active_q(now))
    by_kind = {}
    for kind in active.values_list('kind', flat=True):
        by_kind[kind] = by_kind.get(kind, 0) + 1
    return {'active': sum(by_kind.values()), 'by_kind': sorted(by_kind.items()),
            'expiring': active.filter(expires_at__lte=now + timedelta(days=SOON)).count(),
            'pending': base.filter(approval_pending=True, revoked_at__isnull=True).count(), 'soon_days': SOON}


def remediation(project, now):
    """Remediation requests of the project (all assets: a request is not tied to a tag)."""
    qs = RemediationRequest.objects.filter(project=project)
    active = qs.filter(status='active')
    return {'active': active.count(), 'overdue': active.filter(due_date__lt=now.date()).count(),
            'completed': qs.filter(status='completed').count()}
