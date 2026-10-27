"""Reports pages. Reading (summary, exports, list, download) is open to any signed-in user of the instance, like
the other project pages; creating schedules, generating and deleting need the scan-configuration permission.
Every object is looked up inside the project named in the URL, so another project's id is a 404."""
import logging

from django.conf import settings
from django.contrib import messages
from django.core.cache import cache
from django.http import FileResponse, Http404
from django.urls import reverse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from rolepermissions.checkers import has_permission
from rolepermissions.decorators import has_permission_decorator

from dashboard.models import Project
from limes import tags as tag_rules
from limes.definitions import FOUR_OH_FOUR_URL, PERM_MODIFY_SCAN_CONFIGURATIONS
from reporting import delivery, exports, sched, store, summary, validate
from reporting.models import COMMENTARY_MAX, DELIVERIES, FREQUENCIES, LAYOUTS, SECTIONS, WEEKDAYS, ReportRun, ReportSchedule, ReportTemplate
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


def _template(project, raw):
    """The project's template with this id, or None when none is asked for; another project's id is a 404."""
    if not raw:
        return None
    if not str(raw).isdigit():
        raise Http404
    return get_object_or_404(ReportTemplate, id=int(raw), project=project)


def executive_summary(request, slug):
    project = _project(slug)
    tpl = _template(project, request.GET.get('template'))
    d = summary.build(project, _days(request.GET.get('days')), request.GET.get('tag') or None, template=tpl)
    query = '?tag=' + d['tag'] if d['tag'] else ''
    return render(request, 'reporting/summary.html', {
        'project': project, 'd': d, 'day_options': summary.DAYS, 'tag_options': _tag_options(project), 'query': query,
        'templates': ReportTemplate.objects.filter(project=project)})


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
    tab = request.GET.get('tab') if request.GET.get('tab') in ('recurring', 'templates') else 'generated'
    ctx = {'project': project, 'tab': tab, 'reports_enabled': settings.REPORTS_ENABLED, 'email_configured': delivery.email_configured(),
           'can_manage': has_permission(request.user, PERM_MODIFY_SCAN_CONFIGURATIONS), 'day_options': summary.DAYS,
           'tag_options': _tag_options(project), 'templates': ReportTemplate.objects.filter(project=project)}
    if tab == 'generated':
        ctx['runs'] = ReportRun.objects.filter(project=project)[:RUNS_SHOWN]
    elif tab == 'templates':
        ctx['rows'] = ctx['templates']
    else:
        ctx['schedules'] = ReportSchedule.objects.filter(project=project).select_related('template').order_by('name', 'id')
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
    tpl = _template(project, request.POST.get('template'))
    name = (tpl.name if tpl else 'Executive summary') + (f' ({tag})' if tag else '')
    _generate(request, project, name=name, tag=tag or '', days=days, template=tpl)
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
    out['template'] = None
    if post.get('template'):
        # only this project's templates: another project's id is rejected like any unknown value
        out['template'] = ReportTemplate.objects.filter(project=project, id=int(post['template']) if post['template'].isdigit() else 0).first()
        if out['template'] is None:
            raise validate.ReportError('That template does not exist in this project.')
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
              'tag': obj.tag, 'template': obj.template_id or '', 'delivery': obj.delivery, 'recipients': ', '.join(obj.recipients), 'enabled': obj.enabled}
             if obj else {'name': '', 'frequency': 'monthly', 'weekday': 0, 'day_of_month': 1, 'hour': 6, 'tag': '', 'template': '',
                          'delivery': 'platform', 'recipients': '', 'enabled': True})
    f = dict(f)
    f['weekday'] = int(f['weekday']) if str(f.get('weekday', '')).isdigit() else 0
    if request.method == 'POST':
        f['enabled'] = f.get('enabled') == 'on'
    return render(request, 'reporting/schedule_form.html', {
        'project': project, 'schedule': obj, 'f': f, 'error': error, 'frequencies': FREQUENCIES, 'weekdays': WEEKDAYS,
        'deliveries': DELIVERIES, 'templates': ReportTemplate.objects.filter(project=project), 'tag_options': _tag_options(project), 'email_configured': delivery.email_configured()})


def _recurring(slug):
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


def _parse_template(post):
    sections = [k for k, _ in SECTIONS if k in post.getlist('sections')]
    layout = post.get('layout', '')
    if layout not in dict(LAYOUTS):
        raise validate.ReportError('Choose a layout.')
    if layout == 'full' and not sections:
        raise validate.ReportError('Pick at least one section.')
    return {'name': validate.name(post.get('name')), 'layout': layout, 'sections': sections,
            'commentary': validate.commentary(post.get('commentary'), COMMENTARY_MAX)}


@manage
def template_form(request, slug, template_id=None):
    project = _project(slug)
    obj = get_object_or_404(ReportTemplate, id=template_id, project=project) if template_id else None
    error = None
    if request.method == 'POST':
        f = {'name': request.POST.get('name', ''), 'layout': request.POST.get('layout', 'full'),
             'sections': request.POST.getlist('sections'), 'commentary': request.POST.get('commentary', '')}
        try:
            data = _parse_template(request.POST)
            if ReportTemplate.objects.filter(project=project, name=data['name']).exclude(id=obj.id if obj else None).exists():
                raise validate.ReportError('A template with that name already exists.')
            obj = obj or ReportTemplate(project=project, created_by=request.user)
            for k, v in data.items():
                setattr(obj, k, v)
            obj.save()
            messages.success(request, 'Template saved.')
            return redirect(reverse('reports', kwargs={'slug': slug}) + '?tab=templates')
        except validate.ReportError as e:
            error = str(e)
    else:
        f = ({'name': obj.name, 'layout': obj.layout, 'sections': obj.sections, 'commentary': obj.commentary} if obj
             else {'name': '', 'layout': 'full', 'sections': [k for k, _ in SECTIONS], 'commentary': ''})
    return render(request, 'reporting/template_form.html', {
        'project': project, 'tpl': obj, 'f': f, 'error': error, 'layouts': LAYOUTS, 'sections': SECTIONS, 'commentary_max': COMMENTARY_MAX})


@manage
@require_POST
def template_delete(request, slug, template_id):
    get_object_or_404(ReportTemplate, id=template_id, project=_project(slug)).delete()
    messages.success(request, 'Template deleted.')
    return redirect(reverse('reports', kwargs={'slug': slug}) + '?tab=templates')
