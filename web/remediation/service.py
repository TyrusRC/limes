"""Remediation requests: create, discuss, close. Every text is plain data (escaped where shown); every id is checked
against the project it is used in, so an id from elsewhere is simply not found."""
import logging
import smtplib
from datetime import date

from django.conf import settings
from django.core.mail import send_mass_mail
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.db import transaction
from django.urls import reverse
from django.utils import timezone

from limes import scoring, waivers
from limes.alerts.channels import clean
from remediation.models import RemediationEvent, RemediationItem, RemediationMessage, RemediationRequest
from startScan.models import TrackedIssue

logger = logging.getLogger(__name__)

MAX_ISSUES = 200
MAX_EMAILS = 10
TITLE_MAX = 200
TEXT_MAX = 5000
EMAIL_MAX = 254
NOT_CONFIGURED = 'email not configured'
TRANSITIONS = {'active': ('completed', 'archived'), 'completed': ('active', 'archived'), 'archived': ('active',)}
MAIL_ISSUES = 20  # issues named in the email body; the rest are counted


class RemediationError(ValueError):
    pass


def emails(raw):
    """Validated, lower-cased, de-duplicated recipients. No control characters, separators or display names, so one
    entry can only ever be one address and cannot add a header."""
    if raw in (None, ''):
        return []
    if not isinstance(raw, (list, tuple)):
        raise RemediationError('recipients must be a list of email addresses')
    out = []
    for item in raw:
        if not isinstance(item, str):
            raise RemediationError('recipients must be a list of email addresses')
        addr = item.strip().lower()
        if not addr:
            continue
        if len(addr) > EMAIL_MAX or any(c in addr for c in ' ,;<>"\r\n\t\x00') or any(ord(c) < 32 for c in addr):
            raise RemediationError('not a valid email address')
        try:
            validate_email(addr)
        except ValidationError:
            raise RemediationError('not a valid email address')
        if addr not in out:
            out.append(addr)
    if len(out) > MAX_EMAILS:
        raise RemediationError(f'at most {MAX_EMAILS} external recipients')
    return out


def _title(value):
    title = ' '.join(str(value or '').split()) if isinstance(value, str) else ''
    if not title:
        raise RemediationError('title is required')
    if len(title) > TITLE_MAX:
        raise RemediationError(f'title must be at most {TITLE_MAX} characters')
    return title


def _text(value, what, required=False):
    if value is None:
        value = ''
    if not isinstance(value, str):
        raise RemediationError(f'{what} must be text')
    value = value.strip()
    if required and not value:
        raise RemediationError(f'{what} is required')
    if len(value) > TEXT_MAX:
        raise RemediationError(f'{what} must be at most {TEXT_MAX} characters')
    return value


def event(req, kind, text, actor=None, now=None):
    RemediationEvent.objects.create(request=req, kind=kind, text=text[:300], actor=actor, created_at=now or timezone.now())


def issues_of(project, ids):
    """The open issues of this project for these ids, or an error: one unknown id refuses the whole request."""
    if not isinstance(ids, (list, tuple)) or not ids:
        raise RemediationError('select at least one issue')
    if len(ids) > MAX_ISSUES:
        raise RemediationError(f'at most {MAX_ISSUES} issues per request')
    if any(isinstance(i, bool) or not isinstance(i, int) for i in ids):
        raise RemediationError('issues must be a list of ids')
    wanted = set(ids)
    found = list(TrackedIssue.objects.filter(project=project, id__in=wanted, status='open').select_related('asset'))
    if len(found) != len(wanted):
        raise RemediationError('some of these issues were not found or are no longer open')
    return found


def create_request(project, user, title, message, due_date, issue_ids, assignee=None, external=None, today=None):
    title, message = _title(title), _text(message, 'message')
    external = emails(external)
    today = today or timezone.localdate()
    if due_date is not None:
        if not isinstance(due_date, date):
            raise RemediationError('due date must be a date')
        if due_date < today:
            raise RemediationError('due date cannot be in the past')
    if assignee is not None and not waivers.is_member(assignee, project.id):
        raise RemediationError('the assignee must be a member of this project')
    found = issues_of(project, issue_ids)
    now = timezone.now()
    with transaction.atomic():
        req = RemediationRequest.objects.create(project=project, title=title, message=message, due_date=due_date,
                                                created_by=user, assignee=assignee, external_emails=external,
                                                created_at=now, updated_at=now)
        RemediationItem.objects.bulk_create([RemediationItem(request=req, issue=i) for i in found])
        event(req, 'created', f'Created with {len(found)} {"issue" if len(found) == 1 else "issues"}', user, now)
    if external:
        req.email_status = send_email(req, found)
        req.save(update_fields=['email_status'])
        event(req, 'email', f'Email to {len(external)} {"recipient" if len(external) == 1 else "recipients"}: {req.email_status}', user)
    return req


def send_email(req, found):
    """One message per recipient (they never see each other). Returns the status stored on the request."""
    if not settings.EMAIL_HOST:
        return NOT_CONFIGURED
    lines = [f'- {clean(i.key, 120)} on {clean(i.asset.value, 120)}' for i in found[:MAIL_ISSUES]]
    if len(found) > MAIL_ISSUES:
        lines.append(f'... and {len(found) - MAIL_ISSUES} more')
    body = '\n'.join([
        f'You were asked to fix {len(found)} {"issue" if len(found) == 1 else "issues"} in project {clean(req.project.name, 100)}.',
        '', f'Request: {clean(req.title, TITLE_MAX)}', f'Due: {req.due_date or "no due date"}', '',
        _body_text(req.message), '', 'Issues:', *lines])
    subject = '[Limes] Remediation request: ' + clean(req.title, 120)
    try:
        send_mass_mail([(subject, body, settings.DEFAULT_FROM_EMAIL, [a]) for a in req.external_emails])
    except (smtplib.SMTPException, OSError):
        logger.exception('Could not email remediation request %s', req.pk)
        return 'failed'
    return 'sent'


def _body_text(text):
    """The message as plain lines: newlines stay, other control characters go."""
    return '\n'.join(clean(line, 1000) for line in text.splitlines())


def add_message(req, user, text):
    msg = RemediationMessage.objects.create(request=req, author=user, text=_text(text, 'message', required=True))
    touch(req)
    return msg


def touch(req, now=None):
    RemediationRequest.objects.filter(pk=req.pk).update(updated_at=now or timezone.now())


def set_status(req, user, status, now=None):
    now = now or timezone.now()
    with transaction.atomic():
        req = RemediationRequest.objects.select_for_update().get(pk=req.pk)
        if status not in TRANSITIONS.get(req.status, ()):
            raise RemediationError(f'a {req.status} request cannot become {status}')
        req.status, req.updated_at = status, now
        req.completed_at = now if status == 'completed' else None
        req.overdue_notified = req.overdue_notified and status != 'active'
        req.save(update_fields=['status', 'updated_at', 'completed_at', 'overdue_notified'])
        event(req, {'completed': 'completed', 'archived': 'archived', 'active': 'reopened'}[status],
              {'completed': 'Marked completed', 'archived': 'Archived', 'active': 'Reopened'}[status], user, now)
    return req


def complete_finished(project, now=None):
    """Complete the active requests whose issues are all fixed. Called after every issue sync, the one place that
    marks a TrackedIssue fixed, so a fix confirmed by a rescan closes its request."""
    now = now or timezone.now()
    open_items = RemediationItem.objects.filter(issue__status='open')
    ids = list(RemediationRequest.objects.filter(project=project, status='active').exclude(id__in=open_items.values('request_id'))
               .filter(items__isnull=False).values_list('id', flat=True).distinct())
    for pk in ids:
        done = RemediationRequest.objects.filter(pk=pk, status='active').update(status='completed', completed_at=now, updated_at=now)
        if done:
            RemediationEvent.objects.create(request_id=pk, kind='completed', text='All issues fixed: completed automatically',
                                            created_at=now)
    return len(ids)


def notify_overdue(now=None):
    """One in-app notification per overdue active request, claimed by flipping overdue_notified."""
    from limes.common_func import create_inappnotification
    from limes.definitions import PROJECT_LEVEL_NOTIFICATION
    now = now or timezone.now()
    due = RemediationRequest.objects.filter(status='active', overdue_notified=False, due_date__lt=timezone.localdate(now)) \
        .select_related('project')
    sent = 0
    for req in due:
        if not RemediationRequest.objects.filter(pk=req.pk, status='active', overdue_notified=False).update(overdue_notified=True):
            continue
        event(req, 'overdue', 'Past its due date', now=now)
        create_inappnotification(
            title=clean(f'Remediation request overdue: {req.title}', 250), description='Past its due date and still open.',
            notification_type=PROJECT_LEVEL_NOTIFICATION, project_slug=req.project.slug, icon='mdi-clock-alert-outline',
            status='warning', redirect_link=reverse('remediation_detail', args=[req.project.slug, req.pk]))
        sent += 1
    return sent


def summaries(requests):
    """list-page rows for a list of requests in a fixed number of queries: open issues, impacted assets, categories."""
    ids = [r.id for r in requests]
    rows = (RemediationItem.objects.filter(request_id__in=ids)
            .values_list('request_id', 'issue__status', 'issue__asset_id', 'issue__key', 'issue__source'))
    agg = {i: {'open': 0, 'total': 0, 'assets': set(), 'categories': set()} for i in ids}
    for rid, status, asset_id, key, _source in rows:
        a = agg[rid]
        a['total'] += 1
        a['open'] += status == 'open'
        a['assets'].add(asset_id)
        a['categories'].add(scoring.CATEGORY_LABELS[scoring.category_of(key)])
    return [{'req': r, 'open': agg[r.id]['open'], 'total': agg[r.id]['total'], 'assets': len(agg[r.id]['assets']),
             'categories': sorted(agg[r.id]['categories']), 'overdue': is_overdue(r)} for r in requests]


def is_overdue(req, today=None):
    return req.status == 'active' and req.due_date is not None and req.due_date < (today or timezone.localdate())


def impact(req, now=None):
    """The existing forecast, for the request's issues that are still open."""
    ids = list(RemediationItem.objects.filter(request=req, issue__status='open').values_list('issue_id', flat=True))
    return scoring.forecast(req.project, ids, now) if ids else None
