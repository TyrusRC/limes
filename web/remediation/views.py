
from django.http import Http404
from django.shortcuts import render
from django.utils import timezone

from dashboard.models import Project
from limes import scoring
from limes.checks.catalogue import CHECKS
from remediation import api, notes, service
from remediation.models import RemediationRequest

TABS = ('active', 'completed', 'archived')
LIST_CAP = 200


def _project(slug):
    project = Project.objects.filter(slug=slug).first()
    if project is None:
        raise Http404('project not found')
    return project


def remediation_list(request, slug):
    project = _project(slug)
    tab = request.GET.get('status') if request.GET.get('status') in TABS else 'active'
    counts = {t: 0 for t in TABS}
    for status in RemediationRequest.objects.filter(project=project).values_list('status', flat=True):
        counts[status] = counts.get(status, 0) + 1
    rows = list(RemediationRequest.objects.filter(project=project, status=tab).select_related('created_by', 'assignee')
                .order_by('-updated_at', '-id')[:LIST_CAP])
    return render(request, 'remediation/list.html', {'remediation_active': 'active', 'tab': tab, 'rows': service.summaries(rows),
                                                      'tabs': [(t, counts[t]) for t in TABS]})


def remediation_new(request, slug):
    _project(slug)
    return render(request, 'remediation/new.html', {'remediation_active': 'active', 'max_issues': service.MAX_ISSUES,
                                                    'max_emails': service.MAX_EMAILS, 'today': timezone.localdate()})


def remediation_detail(request, slug, pk):
    project = _project(slug)
    req = RemediationRequest.objects.filter(pk=pk, project=project).select_related('created_by', 'assignee', 'project').first()
    if req is None:
        raise Http404('request not found')
    summary = service.summaries([req])[0]
    items = [{'i': it.issue, 'title': CHECKS[it.issue.key].title if it.issue.source == 'check' and it.issue.key in CHECKS else it.issue.key,
              'category': scoring.CATEGORY_LABELS[scoring.category_of(it.issue.key)]}
             for it in req.items.select_related('issue__asset').order_by('issue__asset__value', 'issue__key', 'id')[:service.MAX_ISSUES]]
    return render(request, 'remediation/detail.html', {
        'remediation_active': 'active', 'req': req, 's': summary, 'items': items, 'impact': service.impact(req),
        'notes': notes.timeline(project, 'request', req.pk, request.user),
        'events': req.events.select_related('actor').order_by('created_at', 'id')[:api.THREAD_CAP],
        'next_status': service.TRANSITIONS[req.status]})


def waivers_page(request, slug):
    project = _project(slug)
    now = timezone.now()
    current, past = api.project_waivers(project, now)
    current, past = [api.waiver_json(w, now) for w in current], [api.waiver_json(w, now) for w in past]
    return render(request, 'remediation/waivers.html', {'waivers_active': 'active',
                                                        'sections': [('Current', current, True), ('Past', past, False)]})


def waiver_detail(request, slug, pk):
    project = _project(slug)
    w = notes.target(project, 'waiver', pk)
    if w is None:
        raise Http404('waiver not found')
    return render(request, 'remediation/waiver.html', {
        'waivers_active': 'active', 'w': api.waiver_json(w, timezone.now()), 'notes': notes.timeline(project, 'waiver', w.pk, request.user)})
