"""Reports pages. Reading (summary, exports, list, download) is open to any signed-in user of the instance, like
the other project pages; creating schedules, generating and deleting need the scan-configuration permission.
Every object is looked up inside the project named in the URL, so another project's id is a 404."""
import logging

from django.conf import settings
from django.contrib import messages
from django.core.cache import cache
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from rolepermissions.checkers import has_permission
from rolepermissions.decorators import has_permission_decorator

from dashboard.models import Project
from limes import tags as tag_rules
from limes.definitions import FOUR_OH_FOUR_URL, PERM_MODIFY_SCAN_CONFIGURATIONS
from reporting import delivery, exports, sched, store, summary, validate
from reporting.models import DELIVERIES, FREQUENCIES, WEEKDAYS, ReportRun, ReportSchedule
from startScan.models import Tag

logger = logging.getLogger(__name__)
manage = has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
RUNS_SHOWN = 100
GENERATE_COOLDOWN = 15  # seconds between manual generations in one project


def _project(slug):
    return get_object_or_404(Project, slug=slug)


def _tag_options(project):
    return tag_rules.tag_counts(project)


def _days(raw):
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return summary.DEFAULT_DAYS
    return n if n in summary.DAYS else summary.DEFAULT_DAYS


def executive_summary(request, slug):
    project = _project(slug)
    d = summary.build(project, _days(request.GET.get('days')), request.GET.get('tag') or None)
    query = '?tag=' + d['tag'] if d['tag'] else ''
    return render(request, 'reporting/summary.html', {
        'project': project, 'd': d, 'day_options': summary.DAYS, 'tag_options': _tag_options(project), 'query': query})


def _members(request, project):
    tag = request.GET.get('tag') or None
    return None if tag is None else summary.members(project, tag)[1]


def export_issues(request, slug):
    project = _project(slug)
    return exports.issues_csv(project, _members(request, project))


def export_assets(request, slug):
    project = _project(slug)
    return exports.assets_csv(project, _members(request, project))


def reports(request, slug):
    project = _project(slug)
    tab = 'recurring' if request.GET.get('tab') == 'recurring' else 'generated'
    ctx = {'project': project, 'tab': tab, 'reports_enabled': settings.REPORTS_ENABLED, 'email_configured': delivery.email_configured(),
           'can_manage': has_permission(request.user, PERM_MODIFY_SCAN_CONFIGURATIONS), 'day_options': summary.DAYS,
           'tag_options': _tag_options(project)}
    if tab == 'generated':
        ctx['runs'] = ReportRun.objects.filter(project=project)[:RUNS_SHOWN]
    else:
        ctx['schedules'] = ReportSchedule.objects.filter(project=project).order_by('name', 'id')
    return render(request, 'reporting/reports.html', ctx)


def download(request, slug, run_id):
    run = get_object_or_404(ReportRun, id=run_id, project=_project(slug))
    f = store.open_for_download(run)
    if f is None:
        raise Http404
    resp = FileResponse(f, content_type='text/html; charset=utf-8', as_attachment=True,
                        filename=f'limes-report-{run.generated_at:%Y%m%d}-{run.id}.html')
    resp['X-Content-Type-Options'] = 'nosniff'
    resp['Cache-Control'] = 'no-store'
    resp['Content-Security-Policy'] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox"
    return resp


def _generate(request, project, **kw):
    if not cache.add(f'reporting:gen:{project.id}', 1, GENERATE_COOLDOWN):
        messages.error(request, 'A report was just generated for this project. Wait a few seconds and try again.')
        return None
    try:
        run = sched.generate(project, trigger='manual', user=request.user, **kw)
    except Exception as exc:
        logger.warning('Manual report failed for project %s: %s', project.pk, type(exc).__name__)
        messages.error(request, 'The report could not be generated.')
        return None
    messages.success(request, 'Report generated.')
    return run


@manage
@require_POST
def generate_now(request, slug):
    project = _project(slug)
    days = _days(request.POST.get('days'))
    tag = tag_rules.lookup(request.POST.get('tag') or '') if request.POST.get('tag') else None
    name = 'Executive summary' + (f' ({tag})' if tag else '')
    _generate(request, project, name=name, tag=tag or '', days=days)
    return redirect('reports', slug=slug)


@manage
@require_POST
def run_delete(request, slug, run_id):
    run = get_object_or_404(ReportRun, id=run_id, project=_project(slug))
    store.remove(run)
    run.delete()
    messages.success(request, 'Report deleted.')
    return redirect('reports', slug=slug)


def _int(post, key, lo, hi, label):
    try:
        n = int(post.get(key, ''))
    except ValueError:
        raise validate.ReportError(f'{label} must be a number.')
    if not lo <= n <= hi:
        raise validate.ReportError(f'{label} must be between {lo} and {hi}.')
    return n


def _parse(project, post):
    out = {'name': validate.name(post.get('name'))}
    out['frequency'] = post.get('frequency', '')
    if out['frequency'] not in dict(FREQUENCIES):
        raise validate.ReportError('Choose weekly, monthly or quarterly.')
    out['weekday'] = _int(post, 'weekday', 0, 6, 'Weekday')
    out['day_of_month'] = _int(post, 'day_of_month', 1, 28, 'Day of month')
    out['hour'] = _int(post, 'hour', 0, 23, 'Hour')
    tag = post.get('tag', '').strip()
    if tag:
        tag = tag_rules.lookup(tag) or ''
        if not Tag.objects.filter(project=project, name=tag).exists():
            raise validate.ReportError('That tag does not exist in this project.')
    out['tag'] = tag
    out['delivery'] = post.get('delivery', '')
    if out['delivery'] not in dict(DELIVERIES):
        raise validate.ReportError('Choose a delivery.')
    out['recipients'] = validate.recipients(post.get('recipients', ''))
    if out['delivery'] == 'email' and not out['recipients']:
        raise validate.ReportError('Add at least one recipient for email delivery.')
    out['enabled'] = post.get('enabled') == 'on'
    return out


@manage
def schedule_form(request, slug, schedule_id=None):
    project = _project(slug)
    obj = get_object_or_404(ReportSchedule, id=schedule_id, project=project) if schedule_id else None
    error = None
    if request.method == 'POST':
        f = request.POST.dict()
        try:
            data = _parse(project, request.POST)
            if obj is None:
                obj = ReportSchedule(project=project, created_by=request.user)
            for k, v in data.items():
                setattr(obj, k, v)
            obj.save()
            messages.success(request, 'Recurring report saved.')
            return _recurring(slug)
        except validate.ReportError as e:
            error = str(e)
    else:
        f = ({'name': obj.name, 'frequency': obj.frequency, 'weekday': obj.weekday, 'day_of_month': obj.day_of_month, 'hour': obj.hour,
              'tag': obj.tag, 'delivery': obj.delivery, 'recipients': ', '.join(obj.recipients), 'enabled': obj.enabled}
             if obj else {'name': '', 'frequency': 'monthly', 'weekday': 0, 'day_of_month': 1, 'hour': 6, 'tag': '',
                          'delivery': 'platform', 'recipients': '', 'enabled': True})
    f = dict(f)
    f['weekday'] = int(f['weekday']) if str(f.get('weekday', '')).isdigit() else 0
    if request.method == 'POST':
        f['enabled'] = f.get('enabled') == 'on'
    return render(request, 'reporting/schedule_form.html', {
        'project': project, 'schedule': obj, 'f': f, 'error': error, 'frequencies': FREQUENCIES, 'weekdays': WEEKDAYS,
        'deliveries': DELIVERIES, 'tag_options': _tag_options(project), 'email_configured': delivery.email_configured()})


def _recurring(slug):
    from django.urls import reverse
    return redirect(reverse('reports', kwargs={'slug': slug}) + '?tab=recurring')


@manage
@require_POST
def schedule_toggle(request, slug, schedule_id):
    s = get_object_or_404(ReportSchedule, id=schedule_id, project=_project(slug))
    s.enabled = not s.enabled
    s.save(update_fields=['enabled'])
    return _recurring(slug)


@manage
@require_POST
def schedule_delete(request, slug, schedule_id):
    get_object_or_404(ReportSchedule, id=schedule_id, project=_project(slug)).delete()
    return _recurring(slug)


@manage
@require_POST
def schedule_run(request, slug, schedule_id):
    project = _project(slug)
    s = get_object_or_404(ReportSchedule, id=schedule_id, project=project)
    _generate(request, project, name=s.name, schedule=s)
    return redirect('reports', slug=slug)
