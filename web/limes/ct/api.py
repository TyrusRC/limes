"""Cert Spotter API fallback: opt-in (LIMES_CERTSPOTTER_API_KEY), one request per budget slot, fixed https URL.
The key lives only in the environment and is sent only as a bearer header; neither it, the headers nor a response
body is ever logged. Responses are untrusted: size- and time-capped, then validated like any spool record."""
import json
import logging
import math
import re
import time
from datetime import datetime, timedelta, timezone as dt_tz

import requests
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django_redis import get_redis_connection
from redis.exceptions import RedisError

from dashboard.stats import invalidate
from limes.alerts.deliver import deliver_immediate
from limes.celery import app
from limes.continuous import tick_lock
from limes.ct import health, ingest
from limes.intel import http
from dashboard.models import Project
from startScan.models import Asset

logger = logging.getLogger(__name__)

URL = 'https://api.certspotter.com/v1/issuances'
SLOT_KEY = 'limes:ct:api:slot'
MAX_BYTES = 4 * 1024 * 1024
DEADLINE = http.TIMEOUT  # seconds for the whole response body, not per read
BACKOFF = 3600
ERROR_BACKOFF = 900
RETRY_AFTER = (60, 86400)
_ID = re.compile(r'[0-9]{1,20}')
KEY = 'certspotter'
# NOTE: one request per 3600/budget seconds (about 514 s at 7), shared by all roots, so each root is polled about every
# ceil(roots/7) hours; a large root's silent baseline takes several slots. Upgrade path: a paid plan's budget.


def count_key(hour):
    return f'limes:ct:api:count:{hour:%Y%m%d%H}'


def _roots():
    """value -> [(asset id, cursor dict)] for the roots the match index also watches."""
    rows = (Asset.objects.filter(scope_tier='owned_root', kind='root_domain').exclude(cadence_tier='off')
            .exclude(state='retired').values_list('id', 'value', 'enrichment__certspotter'))
    out = {}
    for aid, value, cur in rows:
        out.setdefault(value, []).append((aid, cur if isinstance(cur, dict) else {}))
    return out


def _t(v):
    try:
        t = datetime.fromisoformat(v)
        return t if t.tzinfo else t.replace(tzinfo=dt_tz.utc)
    except (TypeError, ValueError):
        return None


def _pick(now):
    """(root value, shared cursor) with the oldest poll that is due, or None. A cursor is shared only when every
    project's root agrees on it; otherwise the root starts over (silently), so a late project gets its baseline."""
    best = None
    for value, rows in _roots().items():
        if not ingest.domains.registrable(value):
            continue
        retry = max((_t(c.get('retry_at')) or datetime.min.replace(tzinfo=dt_tz.utc) for _, c in rows))
        if retry > now:
            continue
        polled = min((_t(c.get('polled_at')) or datetime.min.replace(tzinfo=dt_tz.utc) for _, c in rows))
        if best is None or (polled, value) < best[0]:
            same = all(c.get('after') == rows[0][1].get('after') and c.get('baseline_done') == rows[0][1].get('baseline_done')
                       and c.get('after') for _, c in rows)
            best = ((polled, value), value, rows[0][1] if same else {}, [a for a, _ in rows])
    return best[1:] if best else None


def _store(ids, cursor):
    with transaction.atomic():
        for a in Asset.objects.select_for_update().filter(pk__in=ids).order_by('pk'):
            a.enrichment = {**(a.enrichment or {}), KEY: cursor}
            a.save(update_fields=['enrichment'])


def _body(resp):
    """The parsed JSON of a response read within MAX_BYTES and DEADLINE, or None."""
    end, buf = time.monotonic() + DEADLINE, bytearray()
    try:
        for chunk in resp.iter_content(65536):
            buf += chunk
            if len(buf) > MAX_BYTES or time.monotonic() > end:
                return None
        return json.loads(bytes(buf))
    except (ValueError, RecursionError):
        return None
    finally:
        resp.close()


def _record(item):
    if not isinstance(item, dict):
        return None, None
    iid = item.get('id')
    iid = str(iid) if isinstance(iid, (int, str)) and not isinstance(iid, bool) and _ID.fullmatch(str(iid)) else None
    issuer = item.get('issuer')
    raw = json.dumps({'tbs_sha256': item.get('tbs_sha256'), 'cert_sha256': item.get('cert_sha256'),
                      'dns_names': item.get('dns_names'), 'not_before': item.get('not_before'),
                      'not_after': item.get('not_after'),
                      'issuer_dn': issuer.get('name') if isinstance(issuer, dict) else None}).encode()
    return iid, ingest.parse_record(raw)


def _retry_after(resp):
    try:
        v = int(resp.headers.get('Retry-After'))
    except (TypeError, ValueError):
        v = ERROR_BACKOFF
    return min(max(v, RETRY_AFTER[0]), RETRY_AFTER[1])


def poll_once(now, session=requests):
    """One request for the least recently polled owned root, if this budget slot is free. Returns what happened."""
    key = settings.CERTSPOTTER_API_KEY
    if not key:
        return None
    try:
        r = get_redis_connection('default')
        if not r.set(SLOT_KEY, 1, nx=True, ex=math.ceil(3600 / settings.CERTSPOTTER_HOURLY_BUDGET)):
            return None  # one request per slot, never a sleep
        pipe = r.pipeline()
        pipe.incr(count_key(now.astimezone(dt_tz.utc)))
        pipe.expire(count_key(now.astimezone(dt_tz.utc)), 7200)
        pipe.execute()
    except RedisError as e:
        logger.warning('ct api: budget unavailable (%s); not polling', type(e).__name__)
        return None
    picked = _pick(now)
    if picked is None:
        return None
    root, cur, ids = picked
    after = cur.get('after') if isinstance(cur.get('after'), str) and _ID.fullmatch(cur['after']) else None
    base_done = bool(cur.get('baseline_done')) and after is not None
    params = [('domain', root), ('include_subdomains', 'true'), ('match_wildcards', 'true'),
              ('expand', 'dns_names'), ('expand', 'issuer')] + ([('after', after)] if after else [])
    state = {'after': after, 'polled_at': now.isoformat(), 'retry_at': None, 'baseline_done': base_done}
    status = 'error'
    try:
        resp = session.get(URL, params=params, headers={'Authorization': f'Bearer {key}', 'User-Agent': http.HEADERS['User-Agent']},
                           timeout=http.TIMEOUT, allow_redirects=False, stream=True)
    except requests.RequestException as e:
        logger.warning('ct api: request failed (%s)', type(e).__name__)
        state['retry_at'] = (now + timedelta(seconds=ERROR_BACKOFF)).isoformat()
        _store(ids, state)
        return {'root': root, 'status': status, 'count': 0}
    code, retry = resp.status_code, _retry_after(resp)
    body = _body(resp)
    if code == 429 or (isinstance(body, dict) and body.get('code') == 'rate_limited') or 400 <= code < 500:
        status = 'limited' if code == 429 else 'rejected'
        state['retry_at'] = (now + timedelta(seconds=BACKOFF)).isoformat()
        logger.warning('ct api: %s (HTTP %s)', status, code)
    elif code != 200 or not isinstance(body, list):
        state['retry_at'] = (now + timedelta(seconds=ERROR_BACKOFF)).isoformat()
        logger.warning('ct api: unusable response (HTTP %s)', code)
    elif not body:
        status = 'empty'
        state.update(baseline_done=True, retry_at=(now + timedelta(seconds=retry)).isoformat())
    else:
        status = 'ok'
        touched = _ingest(body, state, now, base_done)
        for pid in sorted(touched):
            try:
                project = Project.objects.filter(pk=pid).first()
                if project is not None:
                    deliver_immediate(project)
                invalidate(pid)
            except Exception as e:
                logger.warning('ct api: delivery for project %s failed (%s)', pid, type(e).__name__)
    _store(ids, state)
    return {'root': root, 'status': status, 'count': len(body) if isinstance(body, list) else 0}


def _ingest(items, state, now, base_done):
    index = ingest.load_index()
    ok = health.evaluate(now)['state'] == 'healthy'
    touched = set()
    for item in items:
        iid, record = _record(item)
        if iid:
            state['after'] = iid
        if record is None:
            continue
        try:
            touched |= ingest.ingest(record, 'certspotter_api', index, now, silent=not base_done, api_ok=ok)
        except Exception as e:
            logger.warning('ct api: ingest failed (%s)', type(e).__name__)
    return touched


def card(project, now):
    """API budget use and the age of the oldest poll across the project's owned roots."""
    used = 0
    try:
        used = int(get_redis_connection('default').get(count_key(now.astimezone(dt_tz.utc))) or 0)
    except (RedisError, ValueError):
        pass
    polled = [_t(c) for c in Asset.objects.filter(project=project, scope_tier='owned_root', kind='root_domain')
              .exclude(cadence_tier='off').exclude(state='retired').values_list('enrichment__certspotter__polled_at', flat=True)[:1000]]
    oldest = None if not polled or None in polled else max(0, int(now.timestamp() - min(polled).timestamp()))
    return {'used_this_hour': used, 'budget': settings.CERTSPOTTER_HOURLY_BUDGET, 'oldest_poll_age': oldest}


@app.task(name='poll_ct_api')
def poll_ct_api():
    out = {'transition': None, 'polled': None}
    with tick_lock('poll_ct_api') as got:
        if not got:
            return out
        now = timezone.now()
        out['transition'] = health.transition(now)
        if settings.CERTSPOTTER_API_KEY and settings.CONTINUOUS_SCANS:
            res = poll_once(now)
            out['polled'] = res['root'] if res else None
    return out
