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

# KEYS: queue, why, burst. ARGV: member, score, why, cap, burst limit (-1 = not charged), burst ttl.
# An earlier score wins (and takes its reason), except that a pending ct_recheck_* keeps its reason so the chain
# is not lost (it then runs early). NOTE: a recheck pulled forward by another event leaves the later recheck of the
# chain undone. Upgrade path: keep two members. Only a request that would be queued is charged to the burst budget,
# and a refused one is not.
ENQUEUE_LUA = """
local old = redis.call('ZSCORE', KEYS[1], ARGV[1])
if old then
  if tonumber(ARGV[2]) < tonumber(old) then
    redis.call('ZADD', KEYS[1], ARGV[2], ARGV[1])
    local prev = redis.call('HGET', KEYS[2], ARGV[1]) or ''
    local why = string.match(prev, '^(ct_recheck_[^|]*)|')
    if why then
      redis.call('HSET', KEYS[2], ARGV[1], why .. '|' .. ARGV[2])  -- a pending recheck keeps its reason
    else
      redis.call('HSET', KEYS[2], ARGV[1], ARGV[3])
    end
  end
  return 'dup'
end
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[4]) then return 'overflow' end
local lim = tonumber(ARGV[5])
if lim >= 0 then
  local used = tonumber(redis.call('GET', KEYS[3]) or '0')
  if used >= lim then return 'burst' end
  redis.call('INCR', KEYS[3])
  redis.call('EXPIRE', KEYS[3], ARGV[6])
end
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[1])
redis.call('HSET', KEYS[2], ARGV[1], ARGV[3])
return 'queued'
"""

# KEYS: queue, why. ARGV: now, limit. Pops due members with their reasons in one step: a concurrent enqueue cannot
# slip between the pop and the reason read. NOTE: delivery is at-most-once; a claimed item whose check dies is not
# retried (the cadence picks the asset up again).
CLAIM_LUA = """
local out = {}
local ms = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[1], 'LIMIT', 0, ARGV[2])
for _, m in ipairs(ms) do
  redis.call('ZREM', KEYS[1], m)
  out[#out + 1] = m
  out[#out + 1] = redis.call('HGET', KEYS[2], m) or ''
  redis.call('HDEL', KEYS[2], m)
end
return out
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


def _push(r, asset_id, project_id, reason, now, delay=0):
    """The Redis half of enqueue: one atomic script. The WHY timestamp is the due time, so latency stays >= 0."""
    due = now.timestamp() + delay
    charged = not reason.startswith('ct_recheck_')  # rechecks are ours, not new events: they must not starve ct_new
    return _text(r.register_script(ENQUEUE_LUA)(
        keys=[QUEUE, WHY, burst_key(project_id, now)],
        args=[str(asset_id), due, f'{reason}|{due}', settings.EVENT_QUEUE_MAX,
              settings.EVENT_BURST if charged else -1, 3600]))


def enqueue(asset, reason, delay=0, now=None):
    if reason not in REASONS:
        raise ValueError(f'unknown event reason {reason!r}')
    if not settings.CONTINUOUS_SCANS or not settings.EVENT_CHECKS:
        return 'off'
    from limes import monitor  # lazy: monitor imports this module's callers
    # NOTE: this DB read runs before any Redis gate, so a flood of requests costs one query each. Upgrade path: a
    # cheap cooldown check first, then _ours.
    if not monitor._ours(asset):
        count('skipped', now=now)
        return 'skipped'
    if reason == 'ct_new':
        monitor.mark_pending(asset, 'ct_new')  # before any queue gate: a dropped item must not lose the discovery
    now = _utc(now)
    cool = None
    try:
        r = get_redis_connection('default')
        if settings.EVENT_COOLDOWN > 0 and not reason.startswith('ct_recheck_'):  # 0 = no cooldown (EX 0 is invalid)
            if not r.set(cool_key(asset.id), 1, nx=True, ex=settings.EVENT_COOLDOWN):
                count('cooled', now=now)
                return 'cooled'
            cool = cool_key(asset.id)
        outcome = _push(r, asset.id, asset.project_id, reason, now, delay)
        if outcome in ('burst', 'overflow') and cool:
            r.delete(cool)  # a dropped request must not make the next one 'cooled'
        count(outcome, now=now)
        return outcome
    except RedisError as e:
        _fail(e)
        if cool:
            try:
                get_redis_connection('default').delete(cool)
            except RedisError:
                pass
        return 'error'


def due_count(now):
    try:
        return int(get_redis_connection('default').zcount(QUEUE, '-inf', _utc(now).timestamp()))
    except RedisError as e:
        _fail(e)
        return 0


def claim_due(now, limit):
    """Pop up to `limit` due entries as (asset_id, reason, due_unix); [] on a Redis error (nothing is lost)."""
    try:
        r = get_redis_connection('default')
        flat = r.register_script(CLAIM_LUA)(keys=[QUEUE, WHY], args=[_utc(now).timestamp(), limit])
    except RedisError as e:
        _fail(e)
        return []
    out = []
    for m, why in zip(flat[::2], flat[1::2]):
        reason, _, at = (_text(why) or '').partition('|')
        out.append((int(_text(m)), reason, float(at or 0)))
    return out


def record_latency(seconds, now=None):
    if not math.isfinite(seconds):
        return
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
    return s[max(0, -(-len(s) * round(q * 1000) // 1000) - 1)]  # integer ceil: no float edge
