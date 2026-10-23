"""Event queue (near-real-time checks): a capped Redis zset of assets due for an immediate monitor check.

NOTE: the queue is capped at EVENT_QUEUE_MAX, with a per-asset cooldown and a per-project hourly burst. A dropped
request falls back to the cadence, where a never-checked asset already sorts first. Upgrade path: a per-project
share of the cap.
"""
import logging
import math
from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from django_redis import get_redis_connection
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)

REASONS = ('ct_new', 'ct_cert', 'ct_recheck_1h', 'ct_recheck_24h', 'asset_new', 'manual', 'exposed', 'dns_change')
QUEUE = 'limes:evq'
WHY = 'limes:evq:why'
DAY_TTL = 2 * 86400
LAT_MAX = 1000

# KEYS: queue, why. ARGV: member, score, why, cap. An earlier score wins (and takes its reason); a full queue refuses.
ENQUEUE_LUA = """
local old = redis.call('ZSCORE', KEYS[1], ARGV[1])
if old then
  if tonumber(ARGV[2]) < tonumber(old) then
    redis.call('ZADD', KEYS[1], ARGV[2], ARGV[1])
    redis.call('HSET', KEYS[2], ARGV[1], ARGV[3])
  end
  return 'dup'
end
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[4]) then return 'overflow' end
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[1])
redis.call('HSET', KEYS[2], ARGV[1], ARGV[3])
return 'queued'
"""


def cool_key(asset_id):
    return f'limes:evq:cool:{asset_id}'


def burst_key(project_id, hour):
    return f'limes:evq:burst:{project_id}:{hour:%Y%m%d%H}'


def stats_key(day):
    return f'limes:evq:stats:{day:%Y%m%d}'


def lat_key(day):
    return f'limes:evq:lat:{day:%Y%m%d}'


def _utc(now):
    return (now or timezone.now()).astimezone(timezone.utc)


def _text(v):
    return v.decode() if isinstance(v, bytes) else v


def _fail(e):
    logger.warning('event queue: redis error %s', type(e).__name__)  # class only: messages can carry hosts


def count(outcome, n=1, now=None):
    now = _utc(now)
    try:
        r = get_redis_connection('default')
        key = stats_key(now)
        pipe = r.pipeline()
        pipe.hincrby(key, outcome, n)
        pipe.expire(key, DAY_TTL)
        pipe.execute()
    except RedisError as e:
        _fail(e)


def enqueue(asset, reason, delay=0, now=None):
    if reason not in REASONS:
        raise ValueError(f'unknown event reason {reason!r}')
    if not settings.CONTINUOUS_SCANS or not settings.EVENT_CHECKS:
        return 'off'
    from limes import monitor  # lazy: monitor imports this module's callers
    if not monitor._ours(asset):
        count('skipped', now=now)
        return 'skipped'
    now = _utc(now)
    cool = None
    try:
        r = get_redis_connection('default')
        if settings.EVENT_COOLDOWN > 0 and not reason.startswith('ct_recheck_'):  # 0 = no cooldown (EX 0 is invalid)
            cool = cool_key(asset.id)
            if not r.set(cool, 1, nx=True, ex=settings.EVENT_COOLDOWN):
                count('cooled', now=now)
                return 'cooled'
        bk = burst_key(asset.project_id, now)
        pipe = r.pipeline()
        pipe.incr(bk)
        pipe.expire(bk, 3600)
        n = pipe.execute()[0]
        if n > settings.EVENT_BURST:
            outcome = 'burst'
        else:
            outcome = _text(r.eval(ENQUEUE_LUA, 2, QUEUE, WHY, str(asset.id),
                                   (now + timedelta(seconds=delay)).timestamp(),
                                   f'{reason}|{int(now.timestamp())}', settings.EVENT_QUEUE_MAX))
        if outcome in ('burst', 'overflow') and cool:
            r.delete(cool)  # a dropped request must not make the next one 'cooled'
        count(outcome, now=now)
        return outcome
    except RedisError as e:
        _fail(e)
        return 'error'


def due_count(now):
    try:
        return int(get_redis_connection('default').zcount(QUEUE, '-inf', _utc(now).timestamp()))
    except RedisError as e:
        _fail(e)
        return 0


def claim_due(now, limit):
    """Pop up to `limit` due entries as (asset_id, reason, enqueued_unix); a member another claimer took is skipped."""
    out = []
    try:
        r = get_redis_connection('default')
        for m in r.zrangebyscore(QUEUE, '-inf', _utc(now).timestamp(), start=0, num=limit):
            if r.zrem(QUEUE, m) != 1:
                continue
            why = _text(r.hget(WHY, m)) or ''
            r.hdel(WHY, m)
            reason, _, at = why.partition('|')
            out.append((int(_text(m)), reason, float(at or 0)))
    except RedisError as e:
        _fail(e)
        return []
    return out


def record_latency(seconds, now=None):
    now = _utc(now)
    if seconds < 0:
        seconds = 0
        count('skew', now=now)
    try:
        r = get_redis_connection('default')
        key = lat_key(now)
        pipe = r.pipeline()
        pipe.lpush(key, seconds)
        pipe.ltrim(key, 0, LAT_MAX - 1)
        pipe.expire(key, DAY_TTL)
        pipe.execute()
    except RedisError as e:
        _fail(e)


def snapshot(now):
    now = _utc(now)
    snap = {'depth': 0, 'due': 0, 'oldest_age': None, 'counts': {}, 'latency': []}
    try:
        r = get_redis_connection('default')
        snap['depth'] = int(r.zcard(QUEUE))
        snap['due'] = int(r.zcount(QUEUE, '-inf', now.timestamp()))
        first = r.zrange(QUEUE, 0, 0, withscores=True)
        if first:
            snap['oldest_age'] = max(0, int(now.timestamp() - first[0][1]))
        for day in (now, now - timedelta(days=1)):
            for k, v in r.hgetall(stats_key(day)).items():
                k = _text(k)
                snap['counts'][k] = snap['counts'].get(k, 0) + int(v)
            snap['latency'] += [float(x) for x in r.lrange(lat_key(day), 0, -1)]
    except RedisError as e:
        _fail(e)
    return snap


def percentile(values, q):
    """Nearest rank."""
    if not values:
        return None
    s = sorted(values)
    return s[max(0, math.ceil(len(s) * q) - 1)]
