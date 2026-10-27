"""Top-bar search: a project's assets and issues, matched as literal text (never a pattern)."""
from django.db.models import Q

from limes.checks.catalogue import CHECKS
from limes.tasks.attribution import REVIEW
from startScan.models import Asset, TrackedIssue

MAX_RESULTS = 25


def search(project, query, limit=MAX_RESULTS):
    """Assets (value or page title) and issues (key or check title) of one project. icontains is a literal match.
    NOTE: sequential scan inside the project; upgrade path is a trigram index on asset value."""
    assets = (Asset.objects.filter(project=project).exclude(scope_tier='candidate', confidence__lt=REVIEW)
              .filter(Q(value__icontains=query) | Q(page_title__icontains=query)).order_by('value', 'id')[:limit])
    needle = query.lower()
    titled = [k for k, c in CHECKS.items() if needle in c.title.lower()]
    issues = (TrackedIssue.objects.filter(project=project).filter(Q(key__icontains=query) | Q(source='check', key__in=titled))
              .select_related('asset').order_by('-severity', 'id')[:limit])
    return {
        'assets': [{'id': a.id, 'kind': a.kind, 'value': a.value, 'scope_tier': a.scope_tier, 'page_title': a.page_title}
                   for a in assets],
        'issues': [{'id': i.id, 'asset': i.asset.value, 'title': CHECKS[i.key].title if i.source == 'check' and i.key in CHECKS else i.key,
                    'severity': i.severity, 'status': i.status} for i in issues],
    }
