"""Certificate watch health: one state (off/idle/healthy/degraded) from the watcher's heartbeat, a once-per-change
alert, and the card data the dashboard shows. The heartbeat and everything in it are read as untrusted JSON."""
import json
import logging
from datetime import datetime, timedelta, timezone as dt_tz

from django.conf import settings
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django_redis import get_redis_connection
from redis.exceptions import RedisError

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
ERROR_WINDOW = timedelta(hours=1)
SPOOL_LIMIT = 1000
RESTART_LIMIT = 3
SAMPLE_MAX = 1000


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


def _int(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else 0


def _heartbeat():
    """The heartbeat dict, or None when missing, unreadable or Redis is down (never a reason to look healthy)."""
    try:
        hb = json.loads(get_redis_connection('default').get(watch.HEARTBEAT) or b'')
    except (RedisError, ValueError, RecursionError):
        return None
    return hb if isinstance(hb, dict) else None


def evaluate(now):
    if not (settings.CT_WATCH and settings.CONTINUOUS_SCANS):
        return {'state': 'off', 'reasons': [], 'heartbeat': None}
    hb = _heartbeat()
    at = _when(hb.get('at')) if hb else None
    if hb is None:
        reasons = ['no_heartbeat']
    elif at is None or (now - at).total_seconds() > settings.CT_WATCH_STALE:
        reasons = ['stale_heartbeat']
    elif hb.get('state') == 'idle':  # an empty watchlist is nothing to watch, not a fault
        return {'state': 'idle', 'reasons': [], 'heartbeat': hb}
    else:
        err = _when(hb.get('last_error_at'))
        flags = {'process_down': not hb.get('pid_alive'), 'restart_storm': _int(hb.get('restarts_10m')) > RESTART_LIMIT,
                 'watcher_error': err is not None and now - err <= ERROR_WINDOW,
                 'spool_backlog': _int(hb.get('spool_depth')) > SPOOL_LIMIT}
        reasons = [c for c in REASONS if flags.get(c)]
    return {'state': 'degraded' if reasons else 'healthy', 'reasons': reasons, 'heartbeat': hb}


def _fan_out(kind, title, immediate_delivery):
    for project in Project.objects.all():
        events.safe_record(project, kind, title)
        if immediate_delivery:
            try:
                deliver_immediate(project)
            except Exception as e:
                logger.warning('ct health: delivery for project %s failed (%s)', project.id, type(e).__name__)


def transition(now):
    """Store the current state; record one alert per project when the watch goes healthy/idle -> degraded and one
    digest note when it recovers. Returns the kind recorded or None. Fails closed: with Redis down nothing is sent.
    NOTE: callers hold the poll_ct_api tick lock, so the read-then-set is not racy. Upgrade path: GETSET."""
    cur = evaluate(now)
    try:
        r = get_redis_connection('default')
        try:
            old = json.loads(r.get(STATE_KEY) or b'')
            old = old if isinstance(old, dict) else {}
        except (ValueError, RecursionError):
            old = {}
        prev = old.get('state')
        if prev == cur['state'] and prev != 'degraded':
            return None
        alert = prev in ('healthy', 'idle') and cur['state'] == 'degraded'
        stored = {'state': cur['state'], 'reasons': cur['reasons'], 'since': now.isoformat(),
                  'alerted': alert or (prev == 'degraded' and cur['state'] == 'degraded' and bool(old.get('alerted')))}
        if prev == cur['state'] and old.get('since'):
            stored['since'] = old['since']
        r.set(STATE_KEY, json.dumps(stored))
    except RedisError as e:
        logger.warning('ct health: state not stored (%s)', type(e).__name__)
        return None
    if alert:
        _fan_out('monitoring_degraded', 'Certificate watch degraded: ' + '; '.join(REASONS[c] for c in cur['reasons']), True)
        return 'monitoring_degraded'
    if prev == 'degraded' and cur['state'] == 'healthy' and old.get('alerted'):
        _fan_out('monitoring_restored', 'Certificate watch restored', False)
        return 'monitoring_restored'
    return None


# --- card -------------------------------------------------------------------------------------------------------

def _age(now, t):
    t = _when(t) if isinstance(t, str) else t
    return None if t is None else max(0, int((now - t).total_seconds()))


def _round(v):
    return None if v is None else round(v)


def _samples(prefix, now):
    out = []
    try:
        r = get_redis_connection('default')
        for day in (now, now - timedelta(days=1)):
            out += [max(0.0, float(x)) for x in r.lrange(f'{prefix}:{day.astimezone(dt_tz.utc):%Y%m%d}', 0, -1)]
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
               .values_list('created_at', 'notified_at')[:SAMPLE_MAX])
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
