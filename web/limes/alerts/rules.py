"""Alert rules: which change events go to which channels, on top of the default delivery (limes.alerts.deliver), which
stays exactly as it is. A rule never delays or replaces a default alert; with no enabled rule nothing here runs."""
import logging
from datetime import timedelta

from celery.exceptions import SoftTimeLimitExceeded
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.utils import timezone

from limes import tags as tag_rules
from limes.alerts import events
from limes.alerts.deliver import ALERT_WINDOW
from startScan.models import AlertRule, ChangeEvent, ScoreSnapshot
from startScan.alert_models import CHANNELS

logger = logging.getLogger(__name__)
MAX_RULES = 50
MAX_TAGS = 20
MAX_RECIPIENTS = 10
SCORE_KINDS = ('score_dropped', 'score_changed')
# NOTE: events handled per dispatch run; the rest wait for the next run (still inside ALERT_WINDOW) and are then
# dropped. Ceiling: a burst of more than this many events in an hour; upgrade path: a per-rule "N more" summary.
DISPATCH_CAP = 100


class RuleError(ValueError):
    """The rule data is invalid (a 400)."""


def _int(value, field, lo, hi):
    if value in (None, ''):
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise RuleError(f'{field} must be a whole number from {lo} to {hi}')
    return value


def _list(value, field, cap):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > cap:
        raise RuleError(f'{field} must be a list of at most {cap} items')
    return value


def clean_rule(data, partial_of=None):
    """Validated column values for an AlertRule from request data. `partial_of` = the rule being edited: absent
    fields keep its values. Raises RuleError."""
    if not isinstance(data, dict):
        raise RuleError('expected a JSON object')
    base = {} if partial_of is None else {
        'name': partial_of.name, 'enabled': partial_of.enabled, 'kinds': partial_of.kinds, 'min_severity': partial_of.min_severity,
        'tags': partial_of.tags, 'score_drop_points': partial_of.score_drop_points,
        'score_window_days': partial_of.score_window_days, 'channels': partial_of.channels, 'email_to': partial_of.email_to}
    d = {**base, **{k: v for k, v in data.items() if k in ('name', 'enabled', 'kinds', 'min_severity', 'tags', 'score_drop_points',
                                                           'score_window_days', 'channels', 'email_to')}}
    name = d.get('name')
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100:
        raise RuleError('name is 1-100 characters')
    if not isinstance(d.get('enabled', True), bool):
        raise RuleError('enabled must be true or false')
    kinds = sorted(set(_list(d.get('kinds'), 'kinds', len(events.KINDS))))
    if not kinds or any(k not in events.KINDS for k in kinds):
        raise RuleError('kinds must be one or more of: ' + ', '.join(events.KINDS))
    channels = sorted(set(_list(d.get('channels'), 'channels', len(CHANNELS))))
    if not channels or any(c not in CHANNELS for c in channels):
        raise RuleError('channels must be one or more of: ' + ', '.join(CHANNELS))
    if 'jira' in channels and 'issue_new' not in kinds:
        raise RuleError('the jira channel needs the issue_new event kind')
    try:
        tags = sorted({tag_rules.normalise(t) for t in _list(d.get('tags'), 'tags', MAX_TAGS)})
    except tag_rules.TagError as e:
        raise RuleError(str(e))
    emails = []
    for a in _list(d.get('email_to'), 'email_to', MAX_RECIPIENTS):
        try:
            if not isinstance(a, str) or len(a) > 254 or '\n' in a or '\r' in a:
                raise ValidationError('x')
            validate_email(a.strip())
        except ValidationError:
            raise RuleError('email_to must hold valid email addresses')
        emails.append(a.strip().lower())
    emails = sorted(set(emails))
    if 'email' in channels and not emails:
        raise RuleError('the email channel needs at least one recipient')
    points = _int(d.get('score_drop_points'), 'score_drop_points', 1, 1000)
    window = _int(d.get('score_window_days'), 'score_window_days', 1, 90)
    if points and window is None:
        window = 7
    return {'name': name.strip(), 'enabled': d.get('enabled', True), 'kinds': kinds, 'min_severity': _int(d.get('min_severity'), 'min_severity', 1, 4),
            'tags': tags, 'score_drop_points': points, 'score_window_days': window if points else None,
            'channels': channels, 'email_to': emails}


def score_drop_ok(rule, event):
    """A score rule with a threshold needs the score to be that many points below its peak in the window."""
    if rule.score_drop_points is None or event.kind not in SCORE_KINDS:
        return True
    today = event.created_at.date()
    now_score = (event.detail or {}).get('to')
    if not isinstance(now_score, int):
        return False
    peak = ScoreSnapshot.objects.filter(project=rule.project_id, score__isnull=False, date__lte=today,
                                        date__gte=today - timedelta(days=rule.score_window_days or 1)) \
        .order_by('-score').values_list('score', flat=True).first()
    return peak is not None and peak - now_score >= rule.score_drop_points


def matches(rule, event, asset_tags):
    """Whether an enabled rule wants this event. `asset_tags` = tag names of the event's asset (a set).
    An event without an asset (a project score) can never satisfy a tag condition: fail closed."""
    if not rule.enabled or event.kind not in rule.kinds or event.created_at < rule.created_at:
        return False
    if rule.min_severity is not None and event.severity is not None and event.severity < rule.min_severity:
        return False
    if rule.tags and not (set(rule.tags) & asset_tags):
        return False
    return score_drop_ok(rule, event)


def plan(rules, event, asset_tags):
    """{channel: [rules]}: each channel once per event, with every rule that asked for it (email unions recipients)."""
    out = {}
    for rule in sorted(rules, key=lambda r: r.id):
        if matches(rule, event, asset_tags):
            for ch in rule.channels:
                out.setdefault(ch, []).append(rule)
    return out


def dispatch(project, now=None, enqueue=None):
    """Queue each recent, unclaimed event of the project to the channels of its matching rules; returns how many
    sends were queued. Never raises: the caller is the scan pipeline."""
    try:
        rules = list(AlertRule.objects.filter(project=project, enabled=True))
        if not rules:
            return 0
        if enqueue is None:
            from limes.alerts.rule_tasks import send_rule_alert
            enqueue = send_rule_alert.delay
        now = now or timezone.now()
        pending = ChangeEvent.objects.filter(project=project, rules_dispatched_at__isnull=True,
                                             created_at__gte=now - ALERT_WINDOW).select_related('asset', 'project') \
            .order_by('created_at', 'id')[:DISPATCH_CAP]
        queued = 0
        for ev in pending:
            if not ChangeEvent.objects.filter(pk=ev.pk, rules_dispatched_at__isnull=True).update(rules_dispatched_at=now):
                continue  # another run claimed it (at-most-once)
            tags = set(ev.asset.tags.values_list('name', flat=True)) if ev.asset_id else set()
            for channel, hit in plan(rules, ev, tags).items():
                if channel == 'in_app' and ev.immediate and ev.notified_at is not None:
                    continue  # the default delivery already put this one in the app
                try:
                    enqueue(ev.id, channel, [r.id for r in hit])
                    queued += 1
                except SoftTimeLimitExceeded:
                    raise
                except Exception as exc:
                    logger.warning('Alert rule send not queued for event %s: %s', ev.id, type(exc).__name__)
        return queued
    except SoftTimeLimitExceeded:
        raise
    except Exception as exc:
        logger.warning('Alert rules failed for project %s: %s', project.pk, type(exc).__name__)
        return 0
