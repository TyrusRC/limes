"""Sending one event to one channel of its matching rules, with retries; the outcome lands on the rules."""
import logging

from celery.exceptions import SoftTimeLimitExceeded
from django.utils import timezone

from limes.alerts import channels, outbound
from limes.celery import app
from startScan.models import AlertRule, ChangeEvent

logger = logging.getLogger(__name__)
MAX_RETRIES = 3
BACKOFF = 30  # seconds; doubles per retry


def record_result(rules, channel, error=None):
    """last_sent on success; last_error 'channel: reason' on failure. A success clears only that channel's old error."""
    now = timezone.now()
    for rule in rules:
        if error:
            AlertRule.objects.filter(pk=rule.pk).update(last_error=f'{channel}: {error}'[:300], last_error_at=now)
        else:
            AlertRule.objects.filter(pk=rule.pk).update(last_sent=now)
            AlertRule.objects.filter(pk=rule.pk, last_error__startswith=f'{channel}:').update(last_error='')


def run_channel(project, channel, rules, msg, **kw):
    """Send now; returns None on success or the reason text on a final failure. Raises OutboundError when transient."""
    try:
        channels.SENDERS[channel](project, rules, msg, **kw)
    except channels.NotConfigured as exc:
        return f'not configured: {exc}'
    except outbound.OutboundError as exc:
        if exc.transient:
            raise
        return str(exc)
    return None


@app.task(name='send_rule_alert', bind=True, max_retries=MAX_RETRIES)
def send_rule_alert(self, event_id, channel, rule_ids):
    event = ChangeEvent.objects.filter(pk=event_id).select_related('project', 'asset').first()
    rules = list(AlertRule.objects.filter(pk__in=rule_ids, enabled=True).select_related('project'))
    if event is None or not rules or channel not in channels.SENDERS:
        return None
    try:
        err = run_channel(event.project, channel, rules, channels.message(event))
    except SoftTimeLimitExceeded:
        raise
    except outbound.OutboundError as exc:
        if self.request.retries < MAX_RETRIES:
            raise self.retry(countdown=BACKOFF * 2 ** self.request.retries, exc=None)
        err = f'{exc} (gave up after {MAX_RETRIES} retries)'
    except Exception as exc:  # never log exc text: it can carry a URL
        logger.warning('Alert rule send failed for event %s: %s', event_id, type(exc).__name__)
        err = f'unexpected error ({type(exc).__name__})'
    record_result(rules, channel, err)
    return err
