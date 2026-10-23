"""Redis token bucket: one Lua script, so the read-refill-take cycle is atomic across processes."""
import time
from django_redis import get_redis_connection

# KEYS[1] bucket hash {tokens, ts}; ARGV capacity, refill per second, now, ttl. Returns 0 (allowed) or seconds to wait.
LUA = """
local cap, rate, now, ttl = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3]), tonumber(ARGV[4])
local d = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens, ts = tonumber(d[1]), tonumber(d[2])
if tokens == nil or ts == nil then tokens, ts = cap, now end
tokens = math.min(cap, tokens + math.max(0, now - ts) * rate)
local wait = 0
if tokens >= 1 then
  tokens = tokens - 1
else
  wait = math.max(1, math.ceil((1 - tokens) / rate))
end
redis.call('HSET', KEYS[1], 'tokens', string.format('%.6f', tokens), 'ts', string.format('%.6f', now))
redis.call('EXPIRE', KEYS[1], ttl)
return wait
"""


def take(key, capacity, per_seconds=60, now=None, conn=None):
    """0 when a call is allowed, else the seconds to wait (>= 1). RedisError propagates: the caller fails closed."""
    conn = conn or get_redis_connection('default')
    now = time.time() if now is None else now
    script = conn.register_script(LUA)
    return int(script(keys=[key], args=[capacity, capacity / per_seconds, '%.6f' % now, 2 * per_seconds]))
