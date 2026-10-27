"""Announce waivers that have lapsed, once each (scoring and alerts already ignore an expired waiver at expires_at), and
remind people shortly before a waiver ends."""
import logging
from datetime import timedelta

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
    from limes.alerts.deliver import deliver_immediate
    now = now or timezone.now()
    due = IssueWaiver.objects.filter(revoked_at__isnull=True, expires_at__lte=now, expiry_notified=False) \
        .select_related('issue', 'issue__asset', 'issue__project')
    done, projects = 0, {}
    for w in due:
        try:
            with transaction.atomic():
                # conditional claim: only the run that flips the flag records the event
                if not IssueWaiver.objects.filter(pk=w.pk, expiry_notified=False, revoked_at__isnull=True).update(expiry_notified=True):
                    continue
                issue = w.issue
                events.record(issue.project, 'waiver_expired', f'Waiver expired for {issue.key} on {issue.asset.value}',
                              severity=issue.severity if issue.status == 'open' else None, asset=issue.asset, key=issue.key,
                              detail={'key': issue.key, 'waiver': w.id, 'kind': w.kind})
                done += 1
                projects[issue.project_id] = issue.project
        except SoftTimeLimitExceeded:
            raise
        except Exception:
            logger.exception('Could not announce expired waiver %s', w.pk)
    for pid in projects:
        # a cache outage or one project's delivery failure must not stop the others
        try:
            invalidate(pid)
        except Exception:
            logger.exception('Could not invalidate the dashboard cache for project %s', pid)
    for project in projects.values():
        try:
            deliver_immediate(project)
        except SoftTimeLimitExceeded:
            raise
        except Exception:
            logger.exception('Could not deliver expired-waiver alerts for project %s', project.pk)
    return {'expired': done}


REMINDER_BATCH = 1000
MAX_LEAD = timedelta(days=90)  # waivers.MAX_REMIND_DAYS


@app.task(name='remind_waivers', bind=False)
def remind_waivers(now=None):
    """One in-app notification per waiver, remind_days before it ends. Claimed by setting reminded_at, so a rerun (or
    two workers) never repeats it; a waiver revoked, rejected, still pending or already over is never reminded."""
    from django.urls import reverse
    from limes.alerts.channels import clean
    from limes.common_func import create_inappnotification
    from limes.definitions import PROJECT_LEVEL_NOTIFICATION
    now = now or timezone.now()
    near = (IssueWaiver.objects.filter(IssueWaiver.active_q(now), reminded_at__isnull=True, expires_at__lte=now + MAX_LEAD)
            .select_related('issue__project', 'project').order_by('expires_at', 'id')[:REMINDER_BATCH])
    sent = 0
    for w in near:
        if w.expires_at > now + timedelta(days=w.remind_days):
            continue
        try:
            with transaction.atomic():
                claimed = (IssueWaiver.objects.filter(pk=w.pk, reminded_at__isnull=True, revoked_at__isnull=True,
                                                      approval_pending=False, expires_at__gt=now)
                           .update(reminded_at=now))
                if not claimed:
                    continue
                project = w.project if w.issue_id is None else w.issue.project
                key = w.key if w.issue_id is None else w.issue.key
                days = max(0, (w.expires_at - now).days)
                create_inappnotification(
                    title=clean(f'Waiver ends in {days} {"day" if days == 1 else "days"}: {key}', 250),
                    description='Renew it or revoke it on the Waivers page; once it ends the issue counts toward the score again.',
                    notification_type=PROJECT_LEVEL_NOTIFICATION, project_slug=project.slug, icon='mdi-clock-alert-outline',
                    status='warning', redirect_link=reverse('waivers_page', args=[project.slug]))
                sent += 1
        except SoftTimeLimitExceeded:
            raise
        except Exception:
            logger.exception('Could not remind about waiver %s', w.pk)
    return {'reminded': sent}
