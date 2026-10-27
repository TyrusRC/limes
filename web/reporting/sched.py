"""Recurring reports: which period a schedule is in, whether it is due, and generating one report."""
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone as dt_tz

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from reporting import delivery, render, store, summary
from reporting.models import ReportRun, ReportSchedule

logger = logging.getLogger(__name__)


def current_period(s, now):
    """(period key, due moment) of the period `now` falls in, in UTC. The key names the period, so one report per key."""
    now = now.astimezone(dt_tz.utc)
    if s.frequency == 'weekly':
        iso = now.isocalendar()
        monday = datetime(now.year, now.month, now.day, tzinfo=dt_tz.utc) - timedelta(days=now.weekday())
        return f'{iso[0]}-W{iso[1]:02d}', monday + timedelta(days=s.weekday, hours=s.hour)
    if s.frequency == 'quarterly':
        quarter = (now.month - 1) // 3 + 1
        return f'{now.year}-Q{quarter}', datetime(now.year, 3 * quarter - 2, s.day_of_month, s.hour, tzinfo=dt_tz.utc)
    return f'{now.year}-{now.month:02d}', datetime(now.year, now.month, s.day_of_month, s.hour, tzinfo=dt_tz.utc)


def _exists(s, key):
    return ReportRun.objects.filter(schedule=s, period_key=key).exists()


def generate(project, name, now=None, schedule=None, trigger='manual', period_key='', tag='', days=None, user=None):
    """Build the summary, store the snapshot, record the run, deliver. Returns the ReportRun, or None when another
    worker already recorded this (schedule, period): its row wins and our file is removed."""
    now = now or timezone.now()
    if schedule is not None:
        tag, days = schedule.tag, days or schedule.window_days
    d = summary.build(project, days or summary.DEFAULT_DAYS, tag or None, now)
    file = store.write(project, render.snapshot(d))
    size = os.path.getsize(os.path.join(store.root(project.id), file))
    try:
        with transaction.atomic():
            run = ReportRun.objects.create(
                project=project, schedule=schedule, name=name, trigger=trigger, tag=d['tag'] or '', days=d['days'],
                period_key=period_key or f'manual-{uuid.uuid4().hex[:12]}', generated_at=now, file=file, size=size, created_by=user)
    except IntegrityError:
        store.remove(file, project.id)
        return None
    run.delivery_note = delivery.deliver(run, d, schedule)
    run.save(update_fields=['delivery_note'])
    return run


def run_due(now=None):
    """Generate every enabled schedule's report for its current period if due and not yet made. Returns the count."""
    if not settings.REPORTS_ENABLED:
        return 0
    now = now or timezone.now()
    made = 0
    for s in ReportSchedule.objects.filter(enabled=True).select_related('project'):
        key, due = current_period(s, now)
        if now < due or s.created_at > due or _exists(s, key):
            continue  # not yet, or created after this period's moment (the first report is the next period's)
        try:
            if generate(s.project, s.name, now=now, schedule=s, trigger='schedule', period_key=key):
                made += 1
        except Exception as exc:  # one broken schedule must not stop the others
            logger.warning('Report schedule %s failed: %s', s.pk, type(exc).__name__)
    return made
