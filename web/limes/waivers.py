import logging
from datetime import timedelta

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from dashboard.stats import invalidate
from limes.definitions import PERM_MODIFY_TARGETS
from rolepermissions.checkers import has_permission
from startScan.models import IssueNote, IssueWaiver, TrackedIssue

logger = logging.getLogger(__name__)

KINDS = ('accepted_risk', 'false_positive')
DEFAULT_DAYS = 90
MAX_DAYS = 365
MAX_TEXT = 5000
SCOPES = ('issue', 'all')
DEFAULT_REMIND_DAYS = 7
MAX_REMIND_DAYS = 90


class WaiverError(ValueError):
    pass


def active_waiver(issue, now=None):
    now = now or timezone.now()
    return issue.waivers.filter(IssueWaiver.active_q(now)).order_by('-created_at', '-id').first()


def _text(value, what):
    value = (value or '').strip()
    if not value:
        raise WaiverError(f'{what} is required')
    if len(value) > MAX_TEXT:
        raise WaiverError(f'{what} must be at most {MAX_TEXT} characters')
    return value


def _invalidate(project_id):
    # the write is committed; a cache outage must not turn it into an error (the 60 s TTL bounds the staleness)
    try:
        invalidate(project_id)
    except Exception:
        logger.exception('Could not invalidate the dashboard cache for project %s', project_id)


def is_member(user, project_id):
    """May this user act on a project's waivers, or be named its approver or assignee? An active user allowed to change
    targets who is a standard-or-better member of that project (a global admin counts as its admin). Fails closed."""
    from memberships import rules
    from memberships.models import STANDARD
    return bool(user and user.is_active and has_permission(user, PERM_MODIFY_TARGETS)
                and rules.at_least(rules.role_for(user, project_id), STANDARD))


def create_waiver(issue, kind, reason, user, expires_at=None, now=None, scope='issue', approver=None, shared=False,
                  remind_days=DEFAULT_REMIND_DAYS):
    """scope 'issue': this issue only. 'all': every issue of the project with this key, assets created later included
    (stored once, matched by key at read time). With an approver the waiver stays pending, and does not count,
    until that person approves it; the requester cannot be the approver."""
    given_now = now
    now = now or timezone.now()
    if kind not in KINDS:
        raise WaiverError('kind must be one of: ' + ', '.join(KINDS))
    if scope not in SCOPES:
        raise WaiverError('scope must be one of: ' + ', '.join(SCOPES))
    reason = _text(reason, 'reason')
    if not isinstance(remind_days, int) or isinstance(remind_days, bool) or not 1 <= remind_days <= MAX_REMIND_DAYS:
        raise WaiverError(f'remind_days must be a whole number from 1 to {MAX_REMIND_DAYS}')
    if approver is not None:
        if approver == user:
            raise WaiverError('you cannot approve your own waiver')
        if not is_member(approver, issue.project_id):
            raise WaiverError('the approver must be a member of this project')
    if expires_at is None and kind == 'accepted_risk':
        expires_at = now + timedelta(days=DEFAULT_DAYS)
    if expires_at is not None and not now < expires_at <= now + timedelta(days=MAX_DAYS):
        raise WaiverError(f'expiry must be in the future and within {MAX_DAYS} days')
    with transaction.atomic():
        # NOTE: this row lock is the only guard for one active waiver per issue (or per key, project-wide); a writer
        # bypassing create_waiver can leave two, and revoke_waiver revokes only the newest. Upgrade path: a partial
        # unique index on (issue) WHERE revoked_at IS NULL, which needs an expiry-aware design.
        TrackedIssue.objects.select_for_update().get(pk=issue.pk)
        if given_now is None:  # stamp after the lock so a waiting writer's timestamps follow the one it waited for
            now = timezone.now()
        where = _scope_q(issue, scope)
        pending = approver is not None
        if not pending:
            IssueWaiver.objects.filter(IssueWaiver.active_q(now)).filter(where).update(revoked_at=now, revoked_by=user)
        fields = {'issue': issue} if scope == 'issue' else {'project_id': issue.project_id, 'key': issue.key}
        w = IssueWaiver.objects.create(kind=kind, reason=reason, created_by=user, created_at=now, expires_at=expires_at,
                                       approver=approver, approval_pending=pending, shared=bool(shared),
                                       remind_days=remind_days, **fields)
    _invalidate(issue.project_id)
    return w


def _scope_q(issue, scope):
    if scope == 'issue':
        return Q(issue=issue)
    return Q(issue__isnull=True, project_id=issue.project_id, key=issue.key)


def _project_waiver(project, waiver_id):
    """The waiver, only if it belongs to the project (through its issue or as a project-wide one)."""
    return (IssueWaiver.objects.filter(pk=waiver_id).filter(Q(issue__project=project) | Q(issue__isnull=True, project=project))
            .select_related('issue', 'created_by').first())


def decide_waiver(project, waiver_id, user, approve, now=None):
    """The named approver approves (the waiver starts counting, replacing any it overrides) or rejects it."""
    now = now or timezone.now()
    with transaction.atomic():
        w = _project_waiver(project, waiver_id)
        if w is None:
            raise LookupError('waiver not found')
        w = IssueWaiver.objects.select_for_update().get(pk=w.pk)
        if not w.approval_pending or w.revoked_at is not None:
            raise WaiverError('this waiver is not waiting for approval')
        if w.approver_id != user.pk or not is_member(user, project.id):
            raise WaiverError('only the named approver can decide this waiver')
        if w.created_by_id == user.pk:
            raise WaiverError('you cannot approve your own waiver')
        if w.expires_at is not None and w.expires_at <= now:
            raise WaiverError('this waiver has already expired')
        if approve:
            where = Q(issue_id=w.issue_id) if w.issue_id else Q(issue__isnull=True, project_id=w.project_id, key=w.key)
            IssueWaiver.objects.filter(IssueWaiver.active_q(now)).filter(where).exclude(pk=w.pk).update(revoked_at=now, revoked_by=user)
            w.approval_pending, w.approved_at = False, now
            w.save(update_fields=['approval_pending', 'approved_at'])
        else:
            w.revoked_at, w.revoked_by = now, user
            w.save(update_fields=['revoked_at', 'revoked_by'])
    _invalidate(project.pk)
    return w


def revoke_waiver_id(project, waiver_id, user, now=None):
    """Revoke one waiver (active or pending) of the project by id: the Waivers page. False if it is already over."""
    now = now or timezone.now()
    with transaction.atomic():
        w = _project_waiver(project, waiver_id)
        if w is None:
            raise LookupError('waiver not found')
        n = IssueWaiver.objects.filter(pk=w.pk, revoked_at__isnull=True).filter(
            Q(expires_at__isnull=True) | Q(expires_at__gt=now)).update(revoked_at=now, revoked_by=user)
    if n:
        _invalidate(project.pk)
    return bool(n)


def revoke_waiver(issue, user, now=None):
    with transaction.atomic():
        TrackedIssue.objects.select_for_update().get(pk=issue.pk)
        now = now or timezone.now()
        w = active_waiver(issue, now)
        if not w:
            return False
        w.revoked_at, w.revoked_by = now, user
        w.save(update_fields=['revoked_at', 'revoked_by'])
    _invalidate(issue.project_id)
    return True


def add_note(issue, user, text):
    return IssueNote.objects.create(issue=issue, author=user, text=_text(text, 'note'))
