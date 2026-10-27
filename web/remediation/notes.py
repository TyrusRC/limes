"""Collaboration notes: plain text on a remediation request, a waiver or an issue. Every target is looked up inside
the project, so an id from another project is simply not found. Notes already left as issue notes or request messages
are read into the same timeline (read-only there); new ones are always Note rows."""
import logging

from django.db.models import Q
from django.urls import reverse

from limes.alerts.channels import clean
from limes.intel import ratelimit
from remediation.models import Note, RemediationItem, RemediationRequest
from startScan.models import IssueWaiver, TrackedIssue

logger = logging.getLogger(__name__)

TYPES = ('request', 'waiver', 'issue')
MAX_BODY = 2000
HOURLY_LIMIT = 30  # notes per user per hour; NOTE: counter lives in the cache (fails closed when it is down)
TIMELINE_CAP = 200


class NoteError(ValueError):
    pass


class NotFound(LookupError):
    pass


def target(project, kind, pk):
    """The object a note hangs on, or None when it is not in this project."""
    if kind == 'request':
        return RemediationRequest.objects.filter(pk=pk, project=project).select_related('assignee', 'created_by').first()
    if kind == 'issue':
        return TrackedIssue.objects.filter(pk=pk, project=project).first()
    if kind == 'waiver':
        return (IssueWaiver.objects.filter(pk=pk).filter(Q(issue__project=project) | Q(issue__isnull=True, project=project))
                .select_related('created_by', 'approver').first())
    return None


def _clean_body(value):
    if not isinstance(value, str):
        raise NoteError('the note must be text')
    value = ''.join(c for c in value if c in '\n\t' or ord(c) >= 32).strip()
    if not value:
        raise NoteError('the note is empty')
    if len(value) > MAX_BODY:
        raise NoteError(f'the note must be at most {MAX_BODY} characters')
    return value


def _link(project, kind, obj):
    if kind == 'request':
        return reverse('remediation_detail', args=[project.slug, obj.pk])
    if kind == 'waiver':
        return reverse('waiver_detail', args=[project.slug, obj.pk])
    return reverse('issue_detail', args=[project.slug, obj.pk])


def recipients(kind, obj):
    """Usernames to tell: the assignee and requester of a request, the owner and approver of a waiver; for an issue the
    owner of its waivers and the people on the requests that list it."""
    if kind == 'request':
        users = [obj.assignee, obj.created_by]
    elif kind == 'waiver':
        users = [obj.created_by, obj.approver]
    else:
        users = [w.created_by for w in IssueWaiver.objects.filter(Q(issue=obj) | Q(issue__isnull=True, project_id=obj.project_id, key=obj.key))
                 .select_related('created_by')[:20]]
        for r in (RemediationRequest.objects.filter(items__issue=obj, status='active').select_related('assignee', 'created_by')[:20]):
            users += [r.assignee, r.created_by]
    return sorted({u.username for u in users if u})


def _notify(project, kind, obj, author):
    """One in-app (project-level) notification naming who it is for. Never carries the note text."""
    who = [n for n in recipients(kind, obj) if n != author.username]
    if not who:
        return
    try:
        from limes.common_func import create_inappnotification
        from limes.definitions import PROJECT_LEVEL_NOTIFICATION
        create_inappnotification(
            title=clean(f'New note from {author.username}', 250),
            description=clean(f'On a {kind}. For: {", ".join(who[:10])}', 500),
            notification_type=PROJECT_LEVEL_NOTIFICATION, project_slug=project.slug, icon='mdi-message-text-outline',
            redirect_link=_link(project, kind, obj))
    except Exception:
        logger.exception('Could not notify about a note on %s %s', kind, obj.pk)  # the note is saved; do not fail the write


def add(project, user, kind, pk, body):
    obj = target(project, kind, pk) if kind in TYPES else None
    if obj is None:
        raise NotFound('not found')
    body = _clean_body(body)
    if not ratelimit.take_hourly(f'note:{user.pk}', HOURLY_LIMIT):
        raise NoteError('too many notes; try again later')
    note = Note.objects.create(project=project, target_type=kind, target_id=obj.pk, author=user, body=body)
    _notify(project, kind, obj, user)
    return note


def delete(project, user, note_id):
    """Only the author, and only inside the project. Another member's note is refused (PermissionError)."""
    note = Note.objects.filter(pk=note_id, project=project).first()
    if note is None:
        raise NotFound('not found')
    if note.author_id != user.pk:
        raise PermissionError('only the author can delete a note')
    note.delete()


def timeline(project, kind, pk, user=None):
    """Oldest first: dicts of id (None for a read-only older note), author, body, created_at, mine. Capped."""
    rows = [{'id': n.id, 'author': n.author.username if n.author else None, 'body': n.body, 'created_at': n.created_at,
             'mine': bool(user and n.author_id == user.pk)}
            for n in Note.objects.filter(project=project, target_type=kind, target_id=pk).select_related('author')
            .order_by('-created_at', '-id')[:TIMELINE_CAP]]
    legacy = []
    if kind == 'issue':
        legacy = TrackedIssue.objects.filter(pk=pk, project=project).values_list('notes__author__username', 'notes__text', 'notes__created_at')
    elif kind == 'request':
        legacy = RemediationRequest.objects.filter(pk=pk, project=project).values_list(
            'messages__author__username', 'messages__text', 'messages__created_at')
    rows += [{'id': None, 'author': a, 'body': t, 'created_at': c, 'mine': False} for a, t, c in list(legacy)[:TIMELINE_CAP] if t]
    return sorted(rows, key=lambda r: r['created_at'])[-TIMELINE_CAP:]
