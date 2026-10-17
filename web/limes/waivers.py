import logging
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from dashboard.stats import invalidate
from startScan.models import IssueNote, IssueWaiver, TrackedIssue

logger = logging.getLogger(__name__)

KINDS = ('accepted_risk', 'false_positive')
DEFAULT_DAYS = 90
MAX_DAYS = 365
MAX_TEXT = 5000


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


def create_waiver(issue, kind, reason, user, expires_at=None, now=None):
    given_now = now
    now = now or timezone.now()
    if kind not in KINDS:
        raise WaiverError('kind must be one of: ' + ', '.join(KINDS))
    reason = _text(reason, 'reason')
    if expires_at is None and kind == 'accepted_risk':
        expires_at = now + timedelta(days=DEFAULT_DAYS)
    if expires_at is not None and not now < expires_at <= now + timedelta(days=MAX_DAYS):
        raise WaiverError(f'expiry must be in the future and within {MAX_DAYS} days')
    with transaction.atomic():
        # NOTE: this row lock is the only guard for one active waiver per issue; a writer bypassing create_waiver
        # can leave two, and revoke_waiver revokes only the newest. Upgrade path: a partial unique index on
        # (issue) WHERE revoked_at IS NULL, which needs an expiry-aware design.
        TrackedIssue.objects.select_for_update().get(pk=issue.pk)
        if given_now is None:  # stamp after the lock so a waiting writer's timestamps follow the one it waited for
            now = timezone.now()
        issue.waivers.filter(IssueWaiver.active_q(now)).update(revoked_at=now, revoked_by=user)
        w = IssueWaiver.objects.create(issue=issue, kind=kind, reason=reason, created_by=user,
                                       created_at=now, expires_at=expires_at)
    _invalidate(issue.project_id)
    return w


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
