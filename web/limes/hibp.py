"""Opt-in Have I Been Pwned domain breaches for owned roots (LIMES_HIBP_API_KEY; empty = off).

Only breach names and per-breach address COUNTS are kept: the aliases HIBP returns are never stored, logged or
put in an event. The key is read from settings, sent only in the hibp-api-key header, and never logged.
leak.hibp_breach is provisional (0 points). Breach data: Have I Been Pwned (CC BY 4.0), https://haveibeenpwned.com/.
NOTE: only the latest-breach name gates a re-query (plus a 7-day refresh), and the 50/day budget bounds work per day;
with many roots the rest wait for the next day. Upgrade path: a per-root rotation cursor."""
import logging
import re
from datetime import datetime, timedelta, timezone as dt_timezone
from urllib.parse import quote

from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime

from limes.celery import app
from limes.continuous import tick_lock
from limes.intel import http, ratelimit
from startScan.models import Asset, DomainBreach

log = logging.getLogger(__name__)

HIBP_DAILY_BUDGET = 50
API = 'https://haveibeenpwned.com/api/v3/'
REFRESH = timedelta(days=7)
RECENT = timedelta(days=365)
MAX_WAIT = 30  # seconds a call may wait for its rate-limit slot
MAX_NAMES = 200  # breaches kept per root per sync
NAME_RE = re.compile(r'[A-Za-z0-9_.-]{1,100}')


class _Stop(Exception):
    """Budget spent or provider busy: end the run (state unchanged, so the next run retries)."""


def _call(path, key):
    if not ratelimit.take_daily('hibp', HIBP_DAILY_BUDGET):
        raise _Stop('budget')
    status, body = http.get_json(API + path, provider='hibp', headers={'hibp-api-key': key}, max_wait=MAX_WAIT)
    if status is None:
        raise _Stop('busy')
    return status, body


def _due(root, latest, now):
    state = (root.enrichment or {}).get('hibp') or {}
    try:
        stamp = datetime.fromisoformat(state.get('fetched_at') or '')
    except ValueError:
        return True
    return state.get('latest') != latest or now - stamp >= REFRESH


def _counts(body):
    counts = {}
    if isinstance(body, dict):
        for names in body.values():
            for n in set(names) if isinstance(names, list) else ():
                if isinstance(n, str) and NAME_RE.fullmatch(n) and (n in counts or len(counts) < MAX_NAMES):
                    counts[n] = counts.get(n, 0) + 1
    return counts


def _dates(name, key):
    status, body = _call(f'breach/{quote(name, safe="")}', key)
    if status != 200 or not isinstance(body, dict):
        return None, None
    added = parse_datetime(str(body.get('AddedDate') or ''))
    if added is not None and timezone.is_naive(added):
        added = added.replace(tzinfo=dt_timezone.utc)
    return parse_date(str(body.get('BreachDate') or '')), added


def _sync_root(root, latest, key, now):
    """Returns True when the root was updated."""
    from limes.alerts import events
    from limes.checks.catalogue import Result
    from limes.checks.run import _write
    from limes.tasks import intel
    status, body = _call(f'breachedDomain/{quote(root.value, safe="")}', key)
    state = (root.enrichment or {}).get('hibp') or {}
    if status == 403:
        _write(root, [Result('leak.hibp_breach', 'error', {'reason': 'domain not verified with HIBP'})], now)
        intel._store(root, 'hibp', {'latest': latest, 'baselined': bool(state.get('baselined'))}, now)
        return True
    if status == 404:
        body = {}
    elif status != 200:
        return False
    counts = _counts(body)
    rows = {b.breach_name: b for b in DomainBreach.objects.filter(root=root)}
    fresh = {}
    for name in counts:
        if name not in rows or rows[name].published is None:
            fresh[name] = _dates(name, key)
    new = [n for n in counts if n not in rows]
    for name, n in counts.items():
        defaults = {'project': root.project, 'addresses': n}
        if name in fresh:
            defaults.update(breach_date=fresh[name][0], published=fresh[name][1])
        DomainBreach.objects.update_or_create(root=root, breach_name=name, defaults=defaults)
    recent = DomainBreach.objects.filter(root=root, published__gte=now - RECENT).exists()
    _write(root, [Result('leak.hibp_breach', 'fail' if recent else 'pass', {})], now)
    if state.get('baselined'):
        for name in new:
            events.safe_record(root.project, 'breach_new', f'New breach {name} affects {counts[name]} addresses at {root.value}',
                               asset=root, detail={'breach': name, 'addresses': counts[name]})
    intel._store(root, 'hibp', {'latest': latest, 'baselined': True}, now)
    return True


@app.task(name='hibp_sync', bind=False)
def hibp_sync():
    """Daily beat tick: breaches of owned roots. Returns counts only."""
    key = settings.HIBP_API_KEY
    if not key:
        return {'reason': 'no key'}
    if not settings.CONTINUOUS_SCANS:
        return {'reason': 'disabled'}
    from dashboard.stats import invalidate
    from limes.alerts.deliver import deliver_immediate
    from limes.alerts.issues import sync_issues
    with tick_lock('hibp_sync') as got:
        if not got:
            return {'reason': 'locked'}
        now = timezone.now()
        done, touched, stopped = 0, {}, None
        try:
            status, body = _call('latestbreach', key)
            latest = body.get('Name') if status == 200 and isinstance(body, dict) else None
            if not isinstance(latest, str):
                return {'roots': 0, 'reason': 'no latest breach'}
            for root in Asset.objects.filter(kind='root_domain', scope_tier='owned_root').exclude(state='retired') \
                    .select_related('project').order_by('id'):
                if not _due(root, latest, now):
                    continue
                try:
                    if _sync_root(root, latest, key, now):
                        done += 1
                        touched[root.project_id] = root.project
                except (SoftTimeLimitExceeded, _Stop):
                    raise
                except Exception:  # noqa: BLE001 - one root must not stop the rest; no message (may echo data)
                    log.exception('hibp sync failed for a root')
        except _Stop as e:
            stopped = str(e)
        for project in touched.values():
            try:
                for job in (sync_issues, deliver_immediate):
                    job(project)
                invalidate(project.id)
            except SoftTimeLimitExceeded:
                raise
            except Exception:  # noqa: BLE001
                log.exception('hibp issue sync failed for project %s', project.id)
        log.info('hibp sync: %d roots updated%s', done, f' (stopped: {stopped})' if stopped else '')
        return {'roots': done, 'stopped': stopped}
