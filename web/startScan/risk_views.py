from django.http import Http404
from django.shortcuts import render

from dashboard.models import Project
from limes import risk_detail
from remediation import notes
from startScan.models import TrackedIssue


def issue_detail(request, slug, issue_id):
    """One risk with its evidence, affected assets, notes and waivers. The issue must belong to the project in the URL."""
    project = Project.objects.filter(slug=slug).first()
    issue = TrackedIssue.objects.filter(id=issue_id, project=project).select_related('asset', 'project').first() if project else None
    if issue is None:
        raise Http404('issue not found')
    return render(request, 'startScan/issue_detail.html', {'issues_active': 'active', 'd': risk_detail.build(issue),
                                                              'notes': notes.timeline(project, 'issue', issue.pk, request.user)})
