"""Provider rate limits shared by every worker process, plus per-day call budgets. Never raises into a caller.

NOTE: reserve() assumes worker clocks agree to within one interval. Upgrade path: a Redis Lua token bucket
on Redis TIME.
"""
import logging
import math
from datetime import datetime, timezone

from django.core.cache import cache as default_cache

logger = logging.getLogger(__name__)

SLOTS = 120
_local = {}  # provider -> last slot time handed out by this process (cache-down fallback only)
_warned = False


def _cache_down(exc):
    global _warned
    if not _warned:
        _warned = True
        logger.warning('rate limiter cache unavailable (%s); falling back to per-process limits', exc)


def reserve(provider, interval, now, cache=default_cache):
    """Seconds the caller must wait before contacting `provider`. `now` is wall time (comparable across processes)."""
    base = math.floor(now / interval)
    try:
        for k in range(SLOTS):
            slot = base + k
            if cache.add(f'limes:rl:{provider}:{slot}', 1, int(interval * (SLOTS + 5)) + 10):
                return max(0.0, slot * interval - now)
        return max(0.0, (base + SLOTS - 1) * interval - now)
    except Exception as e:
        _cache_down(e)
    at = max(now, _local.get(provider, float('-inf')) + interval)
    _local[provider] = at
    return at - now


def take_daily(provider, limit, today=None, cache=default_cache):
    """Count one call against today's (UTC) budget; False once it is spent.
    Fails closed when the cache is down, so a broken cache cannot overspend a provider."""
    today = today or datetime.now(timezone.utc).date()
    key = f'limes:daily:{provider}:{today.isoformat()}'
    try:
        cache.add(key, 0, 2 * 86400)
        return cache.incr(key) <= limit
    except Exception as e:
        _cache_down(e)
        return False


def per_tick(limit, tick_seconds=60):
    """The share of a daily budget one beat tick may spend (at least 1)."""
    return max(1, math.ceil(limit * tick_seconds / 86400))
