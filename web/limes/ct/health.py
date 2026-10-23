"""Certificate watch health: one state (off/idle/healthy/degraded) from the watcher's heartbeat, a once-per-change
alert, and the card data the dashboard shows. The heartbeat and everything in it are read as untrusted JSON."""
import json
import logging
import math
from datetime import timedelta, timezone as dt_tz

from django.conf import settings
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django_redis import get_redis_connection
from redis.exceptions import LockError, RedisError

from dashboard.models import Project
from limes import event_queue
from limes.alerts import events
from limes.alerts.deliver import deliver_immediate
from limes.ct import watch
from startScan.models import Asset, CertSighting, ChangeEvent

logger = logging.getLogger(__name__)

STATE_KEY = 'limes:ct:state'
REASONS = {'no_heartbeat': 'The watcher has not reported', 'stale_heartbeat': 'The watcher stopped reporting',
           'process_down': 'certspotter is not running', 'restart_storm': 'certspotter keeps restarting',
           'watcher_error': 'certspotter reported an error', 'spool_backlog': 'Certificate backlog is growing'}
ERROR_WINDOW = watch.ERROR_WINDOW
SPOOL_LIMIT = 1000
RESTART_LIMIT = 3
SAMPLE_MAX = 1000
SKEW = 60  # seconds a heartbeat may claim to be from the future


def mode():
    if not settings.CONTINUOUS_SCANS:
        return 'cadence'
    if settings.CT_WATCH:
        return 'real-time'
    return 'api' if settings.CERTSPOTTER_API_KEY else 'cadence'


def _when(v):
    try:
        t = parse_datetime(v) if isinstance(v, str) else None
    except ValueError:
        return None
    if t is not None and timezone.is_naive(t):
        t = t.replace(tzinfo=dt_tz.utc)
    return t


def _count(v):
    """A non-negative int, or None for anything else (a bool, a string, a float): callers fail closed on None."""
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


def _int(v):
    return _count(v) or 0


class Unreadable(Exception):
    """Redis could not be asked: the watch's state is unknown, which is not the same as the watch being down."""


def _heartbeat():
    """The heartbeat dict, or None when missing or malformed. Raises Unreadable when Redis is down."""
    try:
        raw = get_redis_connection('default').get(watch.HEARTBEAT)
    except RedisError as e:
        raise Unreadable from e
    try:
        hb = json.loads(raw or b'')
    except (ValueError, RecursionError):
        return None
    return hb if isinstance(hb, dict) else None


def evaluate(now):
    """Unreadable Redis shows as degraded (never healthy) with 'unreadable' set, so transition() can skip it."""
    if not (settings.CT_WATCH and settings.CONTINUOUS_SCANS):
        return {'state': 'off', 'reasons': [], 'heartbeat': None}
    try:
        hb, unreadable = _heartbeat(), False
    except Unreadable:
        hb, unreadable = None, True
    at = _when(hb.get('at')) if hb else None
    if hb is None:
        reasons = ['no_heartbeat']
    elif at is None or not -SKEW <= (now - at).total_seconds() <= settings.CT_WATCH_STALE:
        reasons = ['stale_heartbeat']  # unparsable, too old, or from the future
    elif hb.get('state') == 'idle':  # an empty watchlist is nothing to watch, not a fault
        return {'state': 'idle', 'reasons': [], 'heartbeat': hb, 'unreadable': False}
    else:
        err, raw_err = _when(hb.get('last_error_at')), hb.get('last_error_at')
        restarts, spool = _count(hb.get('restarts_10m')), _count(hb.get('spool_depth'))
        flags = {'process_down': hb.get('pid_alive') is not True,
                 'restart_storm': restarts is None or restarts > RESTART_LIMIT,
                 'watcher_error': (raw_err is not None and err is None) or (err is not None and now - err <= ERROR_WINDOW),
                 'spool_backlog': spool is None or spool > SPOOL_LIMIT}
        reasons = [c for c in REASONS if flags.get(c)]
    return {'state': 'degraded' if reasons else 'healthy', 'reasons': reasons, 'heartbeat': hb, 'unreadable': unreadable}


def _fan_out(kind, title, immediate_delivery):
    for project in Project.objects.all():
        events.safe_record(project, kind, title)
        if immediate_delivery:
            try:
                deliver_immediate(project)
            except Exception as e:
                logger.warning('ct health: delivery for project %s failed (%s)', project.id, type(e).__name__)


def transition(now):
    """Store the current state; record one alert per project when the watch goes healthy/idle -> degraded, or when it
    has been degraded for CT_DEGRADED_GRACE_MIN without ever alerting (a watch that never came up, a restart that lost
    the key), and one digest note when an alerted outage recovers. Returns the kind recorded or None. Fails closed:
    with Redis down nothing is sent, and an unreadable heartbeat skips the evaluation altogether."""
    cur = evaluate(now)
    if cur.get('unreadable'):
        return None
    try:
        r = get_redis_connection('default')
        lock = r.lock('limes:ct:transition', timeout=60, blocking=False)
        if not lock.acquire():
            return None
    except RedisError as e:
        logger.warning('ct health: state not stored (%s)', type(e).__name__)
        return None
    try:
        return _transition(r, cur, now)
    except RedisError as e:
        logger.warning('ct health: state not stored (%s)', type(e).__name__)
        return None
    finally:
        try:
            lock.release()
        except (LockError, RedisError):
            pass


def _transition(r, cur, now):
    try:
        old = json.loads(r.get(STATE_KEY) or b'')
        old = old if isinstance(old, dict) else {}
    except (ValueError, RecursionError):
        old = {}
    prev, state = old.get('state'), cur['state']
    since = _when(old.get('since')) or now
    if prev == state and state != 'degraded':
        return None
    if prev != state:
        since = now
    was_alerted = bool(old.get('alerted'))
    grace = timedelta(minutes=settings.CT_DEGRADED_GRACE_MIN)
    alert = state == 'degraded' and not was_alerted and (prev in ('healthy', 'idle') or now - since >= grace)
    # the flag survives degraded <-> idle (an idle watcher is not a recovery) and ends on healthy or off
    alerted = alert or (was_alerted and prev in ('degraded', 'idle') and state in ('degraded', 'idle'))
    r.set(STATE_KEY, json.dumps({'state': state, 'reasons': cur['reasons'], 'since': since.isoformat(), 'alerted': alerted}))
    if alert:
        _fan_out('monitoring_degraded', 'Certificate watch degraded: ' + '; '.join(REASONS[c] for c in cur['reasons']), True)
        return 'monitoring_degraded'
    if state == 'healthy' and was_alerted and prev in ('degraded', 'idle'):
        _fan_out('monitoring_restored', 'Certificate watch restored', False)
        return 'monitoring_restored'
    return None


# --- card -------------------------------------------------------------------------------------------------------

def _age(now, t):
    t = _when(t) if isinstance(t, str) else t
    return None if t is None else max(0, int((now - t).total_seconds()))


def _round(v):
    return round(v) if isinstance(v, (int, float)) and math.isfinite(v) else None


def _samples(prefix, now):
    out = []
    try:
        r = get_redis_connection('default')
        for day in (now, now - timedelta(days=1)):
            out += [max(0.0, v) for v in (float(x) for x in r.lrange(f'{prefix}:{day.astimezone(dt_tz.utc):%Y%m%d}', 0, -1))
                    if math.isfinite(v)]
    except (RedisError, ValueError):
        pass
    return out


def _pct(values):
    return (_round(event_queue.percentile(values, 0.5)), _round(event_queue.percentile(values, 0.95)))


def card(project, now):
    cur = evaluate(now)
    hb = cur['heartbeat'] or {}
    wl = hb.get('watchlist_size')
    err = hb.get('last_error_summary')
    api_only = CertSighting.objects.filter(project=project, source='certspotter_api', api_while_watch_ok=True,
                                           watch_seen_at__isnull=True, first_seen_at__lte=now - timedelta(hours=1),
                                           first_seen_at__gt=now - timedelta(days=7)).count()
    snap = event_queue.snapshot(now)
    t1, t1u = _pct(_samples('limes:ct:lat', now)), _pct(_samples('limes:ct:age', now))
    t2 = _pct(snap['latency'])
    t3_rows = (ChangeEvent.objects.filter(project=project, notified_at__gte=now - timedelta(hours=24))
               .order_by('-notified_at').values_list('created_at', 'notified_at')[:SAMPLE_MAX])
    t3 = _pct([max(0.0, (n - c).total_seconds()) for c, n in t3_rows])
    dns_at = list(Asset.objects.filter(project=project, cadence_tier='crown_jewel', scope_tier__in=('owned_root', 'owned_host'),
                                       kind__in=('root_domain', 'hostname')).exclude(state='retired')
                  .values_list('enrichment__dns__watched_at', flat=True)[:SAMPLE_MAX])
    ages = [_age(now, t) for t in dns_at]
    watched = [a for a in ages if a is not None]
    return {
        'mode': mode(), 'state': cur['state'], 'reasons': [{'code': c, 'label': REASONS[c]} for c in cur['reasons']],
        'watch': {'heartbeat_age': _age(now, hb.get('at')), 'last_match_age': _age(now, hb.get('last_match_at')),
                  'watchlist_size': _int(wl) if hb else None, 'watchlist_dropped': _int(hb.get('watchlist_dropped')),
                  'restarts_10m': _int(hb.get('restarts_10m')), 'spool_depth': _int(hb.get('spool_depth')),
                  'last_error_summary': err[:300] if isinstance(err, str) and err else None, 'api_only_7d': api_only},
        'queue': {'depth': snap['depth'], 'oldest_age': snap['oldest_age'], 'counts': snap['counts']},
        'latency': {'t1_p50': t1[0], 't1_p95': t1[1], 't1_upper_p50': t1u[0], 't2_p50': t2[0], 't2_p95': t2[1],
                    't3_p50': t3[0], 't3_p95': t3[1]},
        'dns': {'watched': len(watched), 'oldest_age': max(watched) if watched else None},
        'api': api_card(project, now),
    }


def api_card(project, now):
    if not settings.CERTSPOTTER_API_KEY:
        return None
    from limes.ct import api
    return api.card(project, now)
