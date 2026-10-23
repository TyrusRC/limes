import logging

import requests
from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

from limes import reputation
from limes.celery import app
from limes.continuous import tick_lock
from limes.feeds import sources, store
from limes.intel import ratelimit
from startScan.models import FeedState

logger = logging.getLogger(__name__)

SESSION = requests  # tests swap in a fake; feeds are public third-party URLs, never targets


def _daily_limit(feed):
    # Backstop behind store.due(): exactly as many downloads a day as the cadence allows (24 h feeds: one).
    return max(1, int(86400 // feed.cadence.total_seconds()))


@app.task(name='refresh_feeds', bind=False)
def refresh_feeds():
    """Beat tick (hourly): fetch each enabled feed whose cadence has elapsed.
    NOTE: a failed fetch also waits a full cadence before the next try (fetched_at is stamped either way); the UI
    shows the stale/error status meanwhile. Upgrade path: a shorter retry interval after errors."""
    if not settings.CONTINUOUS_SCANS:
        return {'fetched': [], 'changed': [], 'reason': 'disabled'}
    with tick_lock('refresh_feeds') as got:
        if not got:
            return {'fetched': [], 'changed': [], 'reason': 'locked'}
        now = timezone.now()
        states = {s.name: s for s in FeedState.objects.all()}
        fetched, changed = [], []
        for feed in sources.FEEDS.values():
            if not sources.enabled(feed) or not store.due(feed, states.get(feed.name), now):
                continue
            if not ratelimit.take_daily(f'feed:{feed.name}', _daily_limit(feed)):
                logger.warning('feed %s: daily download budget spent or cache down; skipped', feed.name)
                continue
            fetched.append(feed.name)
            if store.fetch(feed, now, SESSION) == 'ok':
                changed.append(feed.name)
        _reputation(changed)
        return {'fetched': fetched, 'changed': changed}


EVALUATED = 'limes:reputation:evaluated'


def _reputation(changed):
    """Re-check owned IPs, ranges and ASNs when a reputation feed changed, and at least daily (DQS lookups are daily).
    NOTE: a cache flush only causes one extra evaluation."""
    try:
        if not (set(changed) & set(sources.REPUTATION)) and cache.get(EVALUATED) is not None:
            return
        reputation.evaluate_reputation()
        cache.set(EVALUATED, 1, 24 * 3600)
    except SoftTimeLimitExceeded:
        raise
    except Exception as e:  # noqa: BLE001 - the downloads are done; a failed evaluation retries next tick
        logger.warning('reputation evaluation failed: %s', type(e).__name__)  # type only: never a message


def refresh_one(name, force=False):
    """Operator path (manage.py refresh_feeds): fetch one feed now. The daily budget and the tick lock still apply;
    `force` skips only the shrink and count checks."""
    feed = sources.FEEDS[name]
    with tick_lock('refresh_feeds') as got:
        if not got:
            return 'locked'
        if not ratelimit.take_daily(f'feed:{feed.name}', _daily_limit(feed)):
            return 'budget'
        return store.fetch(feed, timezone.now(), SESSION, force=force)
