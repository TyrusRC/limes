import logging

import requests
from django.conf import settings
from django.utils import timezone

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
        return {'fetched': fetched, 'changed': changed}
