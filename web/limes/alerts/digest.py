"""Daily digest of change events that were not delivered immediately."""
import logging
from datetime import timedelta

from celery.exceptions import SoftTimeLimitExceeded
from django.db.models import Q
from django.urls import reverse
from django.utils import timezone

from limes.celery import app
from limes.definitions import PROJECT_LEVEL_NOTIFICATION
from startScan.models import Asset, ChangeEvent

logger = logging.getLogger(__name__)
OWNED_TIERS = ('owned_root', 'owned_host')


def _pending(project):
    # everything not yet delivered: digest-only events, plus immediate ones the hourly cap held back
    return ChangeEvent.objects.filter(project=project, digested_at__isnull=True).filter(
        Q(immediate=False) | Q(notified_at__isnull=True)).order_by('created_at', 'id')


def _counts(project, now):
    recent = Asset.objects.filter(project=project, first_seen__gt=now - timedelta(hours=24))
    return recent.filter(scope_tier__in=OWNED_TIERS).count(), recent.filter(scope_tier='candidate').count()


def _compose(events, owned, candidates):
    lines = [e.title for e in events]
    if owned:
        lines.append('%d new owned asset%s' % (owned, '' if owned == 1 else 's'))
    if candidates:
        lines.append('%d new candidate%s' % (candidates, '' if candidates == 1 else 's'))
    return '\n'.join(lines) or None


def build_digest(project, now=None):
    """Message text for the project's undelivered changes, or None when there is nothing to report."""
    return _compose(list(_pending(project)), *_counts(project, now or timezone.now()))


@app.task(name='send_digest', bind=False)
def send_digest(chat=None):
    from dashboard.models import Project
    from limes.common_func import create_inappnotification
    if chat is None:
        from limes.tasks.notifications import send_notif as chat
    now = timezone.now()
    sent = 0
    for project in Project.objects.all():
        try:
            # Claim before sending (at-most-once), so a concurrent deliver/digest never double-sends.
            claimed = [e for e in _pending(project) if ChangeEvent.objects.filter(
                pk=e.pk, digested_at__isnull=True).filter(Q(immediate=False) | Q(notified_at__isnull=True))
                .update(digested_at=now)]
            msg = _compose(claimed, *_counts(project, now))
            if not msg:
                continue
            sent += 1
            title = 'Limes daily digest: %s' % project.name
            try:
                create_inappnotification(
                    title=title, description=msg, notification_type=PROJECT_LEVEL_NOTIFICATION,
                    project_slug=project.slug, icon='mdi-newspaper-variant-outline', status='info',
                    redirect_link=reverse('dashboardIndex', kwargs={'slug': project.slug}))
            except SoftTimeLimitExceeded:
                raise
            except Exception:
                logger.exception('In-app digest failed for project %s', project.pk)
            chat(msg, title=title)
        except SoftTimeLimitExceeded:
            raise
        except Exception:
            logger.exception('Digest failed for project %s', project.pk)
    return {'projects': Project.objects.count(), 'sent': sent}
