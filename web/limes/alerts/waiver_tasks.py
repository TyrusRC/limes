"""Announce waivers that have lapsed, once each. Scoring and alerts already ignore an expired waiver at expires_at."""
import logging

from celery.exceptions import SoftTimeLimitExceeded
from django.db import transaction
from django.utils import timezone

from dashboard.stats import invalidate
from limes.alerts import events
from limes.celery import app
from startScan.models import IssueWaiver

logger = logging.getLogger(__name__)


@app.task(name='expire_waivers', bind=False)
def expire_waivers(now=None):
    now = now or timezone.now()
    due = IssueWaiver.objects.filter(revoked_at__isnull=True, expires_at__lte=now, expiry_notified=False) \
        .select_related('issue', 'issue__asset', 'issue__project')
    done, projects = 0, set()
    for w in due:
        try:
            with transaction.atomic():
                # conditional claim: only the run that flips the flag records the event
                if not IssueWaiver.objects.filter(pk=w.pk, expiry_notified=False).update(expiry_notified=True):
                    continue
                issue = w.issue
                events.record(issue.project, 'waiver_expired', f'Waiver expired for {issue.key} on {issue.asset.value}',
                              severity=issue.severity if issue.status == 'open' else None, asset=issue.asset, key=issue.key,
                              detail={'key': issue.key, 'waiver': w.id, 'kind': w.kind})
                done += 1
                projects.add(issue.project_id)
        except SoftTimeLimitExceeded:
            raise
        except Exception:
            logger.exception('Could not announce expired waiver %s', w.pk)
    for pid in projects:
        invalidate(pid)
    return {'expired': done}
