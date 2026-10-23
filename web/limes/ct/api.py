"""Cert Spotter API fallback: opt-in (LIMES_CERTSPOTTER_API_KEY), one request per budget slot, fixed https URL.
The key lives only in the environment and is sent only as a bearer header; neither it, the headers nor a response
body is ever logged. Responses are untrusted: size- and time-capped, then validated like any spool record."""
import json
import logging
import math
import os
import re
import socket
import threading
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
DEADLINE = 20  # seconds for the whole response body; a watchdog cuts the socket, so a slow drip cannot outlast it
PAGE_MAX = 100
POISON = 3
BACKOFF = 3600
ERROR_BACKOFF = 900
RETRY_AFTER = (60, 86400)
_ID = re.compile(r'[0-9]{1,20}')
KEY = 'certspotter'
# NOTE: a large root's silent baseline walks from the oldest issuance. Seeding `after` with a recent id would shorten
# it, but the API has no "latest id" call and skipping history would leave the sightings that dedupe the watcher's and
# crt.sh's certificates unrecorded. Upgrade path: a paid plan's budget (or crt.sh seeding the recent ids).
# NOTE: one request per 3600/budget seconds (about 514 s at 7), shared by all roots, so each root is polled about every
# ceil(roots/7) hours; a large root's silent baseline takes several slots. Upgrade path: a paid plan's budget.


def count_key(hour):
    return f'limes:ct:api:count:{hour:%Y%m%d%H}'


def _roots():
    """value -> [(asset id, project id, cursor dict)] for the roots the match index also watches."""
    rows = (Asset.objects.filter(scope_tier='owned_root', kind='root_domain').exclude(cadence_tier='off')
            .exclude(state='retired').values_list('id', 'project_id', 'value', 'enrichment__certspotter'))
    out = {}
    for aid, pid, value, cur in rows:
        out.setdefault(value, []).append((aid, pid, cur if isinstance(cur, dict) else {}))
    return out


_NEVER = datetime.min.replace(tzinfo=dt_tz.utc)


def _t(v):
    try:
        t = datetime.fromisoformat(v)
        return t if t.tzinfo else t.replace(tzinfo=dt_tz.utc)
    except (TypeError, ValueError):
        return None


def _id(v):
    return v if isinstance(v, str) and _ID.fullmatch(v) else None


def _pick(now):
    """(root value, walk position, {asset id: project id}, project ids still baselining, failure memo) for the root
    with the oldest due poll, or None. The walk restarts from the beginning while any project's root has no baseline
    (a project that added an already-polled root); the others keep their baseline and stay loud, because ingestion
    of a certificate they already hold is a no-op."""
    best = None
    for value, rows in _roots().items():
        if not ingest.domains.registrable(value):
            continue
        if max(_t(c.get('retry_at')) or _NEVER for _, _, c in rows) > now:
            continue
        polled = min(_t(c.get('polled_at')) or _NEVER for _, _, c in rows)
        if best is None or (polled, value) < best[0]:
            quiet = {pid for _, pid, c in rows if not c.get('baseline_done')}
            walkers = [c for _, pid, c in rows if pid in quiet] or [c for _, _, c in rows]
            after = min((_id(c.get('after')) for c in walkers), key=lambda a: int(a) if a else -1)
            fail = next((c['fail'] for _, _, c in rows if isinstance(c.get('fail'), dict)), None)
            best = ((polled, value), value, after, {a: (pid, bool(c.get('baseline_done'))) for a, pid, c in rows}, quiet, fail)
    return best[1:] if best else None


def _store(rows, cursor):
    """Write the shared walk state to every project's root; each keeps its own baseline_done."""
    with transaction.atomic():
        for a in Asset.objects.select_for_update().filter(pk__in=list(rows)).order_by('pk'):
            a.enrichment = {**(a.enrichment or {}), KEY: {**cursor, 'baseline_done': cursor.get('baseline_done') or rows[a.pk][1]}}
            a.save(update_fields=['enrichment'])


class _Watchdog:
    """Cuts the connection at the deadline, so a server dripping a byte at a time cannot hold a worker: the read
    timeout alone restarts with every byte."""
    def __init__(self, resp, seconds):
        self.resp = resp
        self.timer = threading.Timer(seconds, self._cut)
        self.timer.daemon = True

    def _cut(self):
        """shutdown() on a duplicate of the response's descriptor: it wakes the blocked read in the other thread, and
        works although http.client has already detached the connection's own socket."""
        try:
            fd = os.dup(self.resp.raw._fp.fp.raw.fileno())
            with socket.socket(fileno=fd) as s:
                s.shutdown(socket.SHUT_RDWR)
        except (OSError, AttributeError, ValueError):
            pass

    def __enter__(self):
        self.timer.start()

    def __exit__(self, *exc):
        self.timer.cancel()


def _body(resp):
    """The parsed JSON of a response read within MAX_BYTES and DEADLINE, or None. Network errors propagate."""
    end, buf = time.monotonic() + DEADLINE, bytearray()
    try:
        with _Watchdog(resp, DEADLINE):
            for chunk in resp.iter_content(8192):
                buf += chunk
                if len(buf) > MAX_BYTES or time.monotonic() > end:
                    return None
            if time.monotonic() > end:
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
    iid = _id(str(iid)) if isinstance(iid, (int, str)) and not isinstance(iid, bool) else None
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
    key = settings.CERTSPOTTER_API_KEY.strip()
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
    root, after, rows, quiet, fail = picked
    params = [('domain', root), ('include_subdomains', 'true'), ('match_wildcards', 'true'),
              ('expand', 'dns_names'), ('expand', 'issuer')] + ([('after', after)] if after else [])
    state = {'after': after, 'polled_at': now.isoformat(), 'retry_at': None, 'baseline_done': False, 'fail': fail}
    status, body = 'error', None
    try:
        resp = session.get(URL, params=params, headers={'Authorization': f'Bearer {key}', 'User-Agent': http.HEADERS['User-Agent']},
                           timeout=http.TIMEOUT, allow_redirects=False, stream=True)
        code, retry = resp.status_code, _retry_after(resp)
        body = _body(resp)
    except (requests.RequestException, OSError) as e:
        logger.warning('ct api: request failed (%s)', type(e).__name__)
        state['retry_at'] = (now + timedelta(seconds=ERROR_BACKOFF)).isoformat()
        _store(rows, state)
        return {'root': root, 'status': status, 'count': 0}
    if code == 429 or (isinstance(body, dict) and body.get('code') == 'rate_limited') or 400 <= code < 500:
        status = 'limited' if code == 429 else 'rejected'
        state['retry_at'] = (now + timedelta(seconds=BACKOFF)).isoformat()
        logger.warning('ct api: %s (HTTP %s)', status, code)
    elif code != 200 or not isinstance(body, list):
        state['retry_at'] = (now + timedelta(seconds=ERROR_BACKOFF)).isoformat()
        logger.warning('ct api: unusable response (HTTP %s)', code)
    elif not body:
        status = 'empty'
        state.update(baseline_done=True, retry_at=(now + timedelta(seconds=retry)).isoformat(), fail=None)
    else:
        status = 'ok'
        touched = _ingest(body[:PAGE_MAX], state, now, quiet)
        for pid in sorted(touched):
            try:
                project = Project.objects.filter(pk=pid).first()
                if project is not None:
                    deliver_immediate(project)
                invalidate(pid)
            except Exception as e:
                logger.warning('ct api: delivery for project %s failed (%s)', pid, type(e).__name__)
    _store(rows, state)
    return {'root': root, 'status': status, 'count': len(body) if isinstance(body, list) else 0}


def _ingest(items, state, now, quiet):
    """Ingest in order. A certificate that fails stops the page there (`after` stays before it) and is retried next
    slot; after POISON failures it is skipped, so one bad certificate cannot stall the root."""
    index = ingest.load_index()
    ok = health.evaluate(now)['state'] == 'healthy'
    touched = set()
    for item in items:
        iid, record = _record(item)
        if record is not None:
            try:
                touched |= ingest.ingest(record, 'certspotter_api', index, now, silent=quiet, api_ok=ok)
            except Exception as e:
                memo = state.get('fail') if isinstance(state.get('fail'), dict) else {}
                n = (memo.get('n', 0) + 1) if memo.get('id') == iid else 1
                logger.warning('ct api: ingest of one certificate failed (%s, attempt %s)', type(e).__name__, n)
                if n < POISON:
                    state['fail'] = {'id': iid, 'n': n}
                    break
                logger.error('ct api: skipping a certificate after %s failures', n)
        if iid:
            state['after'] = iid
        state['fail'] = None if (state.get('fail') or {}).get('id') == iid else state.get('fail')
    return touched


def card(project, now):
    """API budget use and the age of the oldest poll across the project's owned roots."""
    used = 0
    try:
        used = int(get_redis_connection('default').get(count_key(now.astimezone(dt_tz.utc))) or 0)
    except (RedisError, ValueError):
        pass
    polled = [_t(c) for c in Asset.objects.filter(project=project, scope_tier='owned_root', kind='root_domain')
              .exclude(cadence_tier='off').exclude(state='retired').order_by('id')
              .values_list('enrichment__certspotter__polled_at', flat=True)[:1000]]
    seen = [t for t in polled if t is not None]
    unpolled = len(polled) - len(seen)  # a root never polled has no age: the card says so instead of hiding it
    oldest = max(0, int(now.timestamp() - min(seen).timestamp())) if seen and not unpolled else None
    return {'used_this_hour': used, 'budget': settings.CERTSPOTTER_HOURLY_BUDGET, 'oldest_poll_age': oldest,
            'unpolled': unpolled}


@app.task(name='poll_ct_api')
def poll_ct_api():
    """The health transition runs first and outside the fetch lock, so a stalled fetch never delays a degraded alert."""
    out = {'transition': health.transition(timezone.now()), 'polled': None}
    if not (settings.CERTSPOTTER_API_KEY.strip() and settings.CONTINUOUS_SCANS):
        return out
    with tick_lock('poll_ct_api') as got:
        if got:
            res = poll_once(timezone.now())
            out['polled'] = res['root'] if res else None
    return out
