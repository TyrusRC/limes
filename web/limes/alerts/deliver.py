"""Immediate delivery of change events: in-app, chat, then a signed webhook. One attempt, no retries."""
import hashlib
import hmac
import json
import logging
from datetime import timedelta

import requests
from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.urls import reverse
from django.utils import timezone

from limes.definitions import PROJECT_LEVEL_NOTIFICATION
from startScan.models import ChangeEvent

logger = logging.getLogger(__name__)
ALERT_HOURLY_CAP = 10
WEBHOOK_TIMEOUT = 5


def sign(body, secret):
    return 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def payload(event):
    return {'id': event.id, 'event': event.kind, 'project': event.project.slug, 'severity': event.severity,
            'title': event.title, 'asset': event.asset.value if event.asset else None, 'detail': event.detail,
            'created_at': event.created_at.isoformat()}


def _in_app(event):
    from limes.common_func import create_inappnotification
    create_inappnotification(
        title=event.title, description=event.title, notification_type=PROJECT_LEVEL_NOTIFICATION,
        project_slug=event.project.slug, icon='mdi-alert-circle-outline',
        status='error' if (event.severity or 0) >= 3 else 'warning',
        redirect_link=reverse('dashboardIndex', kwargs={'slug': event.project.slug}))


def _webhook(event, post):
    url, secret = settings.ALERT_WEBHOOK_URL, settings.ALERT_WEBHOOK_SECRET
    if not url or not secret:
        return
    if not url.startswith('https://') and not settings.ALERT_WEBHOOK_ALLOW_HTTP:
        logger.warning('Alert webhook refused: URL is not https and LIMES_ALERT_WEBHOOK_ALLOW_HTTP is off')
        return
    body = json.dumps(payload(event), sort_keys=True).encode()
    try:
        post(url, data=body, timeout=WEBHOOK_TIMEOUT,
             headers={'Content-Type': 'application/json', 'X-Limes-Signature': sign(body, secret)})
    except requests.exceptions.RequestException:
        logger.exception('Alert webhook failed for change event %s', event.id)


def deliver_immediate(project, now=None, chat=None, post=None):
    """Send undelivered, undigested immediate events (oldest first) up to the hourly cap; returns how many."""
    if chat is None:
        from limes.tasks.notifications import send_notif as chat
    post = post or requests.post
    now = now or timezone.now()
    room = ALERT_HOURLY_CAP - ChangeEvent.objects.filter(
        project=project, notified_at__gt=now - timedelta(hours=1)).count()
    if room <= 0:
        return 0
    pending = ChangeEvent.objects.filter(project=project, immediate=True, notified_at__isnull=True,
                                         digested_at__isnull=True).select_related('project', 'asset') \
        .order_by('created_at', 'id')[:room]
    sent = 0
    for event in pending:
        for channel in (_in_app, lambda e: chat(e.title, title=e.title), lambda e: _webhook(e, post)):
            try:
                channel(event)
            except SoftTimeLimitExceeded:
                raise
            except Exception:
                logger.exception('Alert channel failed for change event %s', event.id)
        event.notified_at = now
        event.save(update_fields=['notified_at'])
        sent += 1
    return sent
