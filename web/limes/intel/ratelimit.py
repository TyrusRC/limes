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
# NOTE: _local is not thread-safe and only grows by one entry per provider; it is the cache-down fallback only.
_local = {}  # provider -> last slot time handed out by this process (cache-down fallback only)
_warned = False


def _cache_down(exc, consequence):
    global _warned
    if not _warned:
        _warned = True
        logger.warning('rate limiter cache unavailable (%s); %s', exc, consequence)


def reserve(provider, interval, now, cache=default_cache):
    """Seconds to wait before contacting `provider`, or None when all SLOTS upcoming slots are taken
    (saturated: the caller should treat the provider as busy and try later). `now` is wall time (comparable
    across processes). Claimed slots start at least `interval` apart, and the caller sleeps until its slot start."""
    base = math.ceil(now / interval)
    try:
        for k in range(SLOTS):
            slot = base + k
            if cache.add(f'limes:rl:{provider}:{slot}', 1, int(interval * (SLOTS + 5)) + 10):
                return max(0.0, slot * interval - now)
        return None
    except Exception as e:
        _cache_down(e, 'falling back to per-process spacing')
    at = max(now, _local.get(provider, float('-inf')) + interval)
    _local[provider] = at
    return at - now


def take_daily(provider, limit, today=None, cache=default_cache):
    """Count one call against today's (UTC) budget; False once it is spent.
    Fails closed when the cache is down, so a broken cache cannot overspend a provider.
    NOTE: the counter lives in the cache, so an eviction or flush resets the day's count. Upgrade path: a
    persistent counter (database row) or a Redis Lua token bucket."""
    today = today or datetime.now(timezone.utc).date()
    key = f'limes:daily:{provider}:{today.isoformat()}'
    try:
        cache.add(key, 0, 2 * 86400)
        return cache.incr(key) <= limit
    except Exception as e:
        _cache_down(e, 'budgeted calls are paused (failing closed)')
        return False


def per_tick(limit, tick_seconds=60):
    """The share of a daily budget one beat tick may spend (at least 1)."""
    return max(1, math.ceil(limit * tick_seconds / 86400))


PROJECT_SHARE = 0.25


def take_shared(provider, limit, project_id, today=None, cache=default_cache):
    """take_daily against a global budget AND the project's share of it (a quarter), so one project with many roots
    cannot spend the day's calls for every other. Both fail closed."""
    mine = max(1, int(limit * PROJECT_SHARE))
    return take_daily(f'{provider}:p{project_id}', mine, today, cache) and take_daily(provider, limit, today, cache)
