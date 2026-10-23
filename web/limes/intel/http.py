"""Polite JSON fetches from passive third-party providers. Never contacts a target.

NOTE: crt.sh is often slow or down. Upgrade path: a local CT mirror/certstream. Rate limits are shared
across workers through the cache (see ratelimit).
"""
import logging
import time

import requests

from limes.intel import ratelimit

logger = logging.getLogger(__name__)

TIMEOUT = 30
RETRIES = 2
MIN_INTERVAL = {'crtsh': 5.0, 'internetdb': 1.0, 'ripestat': 0.25, 'hibp': 7.0}
HEADERS = {'User-Agent': 'Limes-ASM'}


def get_json(url, *, provider, session=requests, clock=time.time, sleep=time.sleep, headers=None, max_wait=None, budget=None):
    """(status, parsed JSON | None); (None, None) after retries or when the provider is saturated, or when the
    reserved slot is further away than `max_wait` seconds (no sleep). A 429's Retry-After is honoured (a longer wait than
    `max_wait`, when set, gives up); `budget()` is called before each retry and a False ends the call. `headers` are merged over HEADERS. Never raises."""
    headers = {**HEADERS, **(headers or {})}
    for attempt in range(RETRIES + 1):
        retry_after = None
        wait = ratelimit.reserve(provider, MIN_INTERVAL.get(provider, 1.0), clock())
        if wait is None:  # provider saturated: same outcome as exhausted retries, without a long sleep
            logger.warning(f'{provider}: rate-limit slots exhausted, skipping')
            return None, None
        if max_wait is not None and wait > max_wait:
            logger.warning(f'{provider}: next slot {wait:.0f}s away, skipping')
            return None, None
        if wait > 0:
            sleep(wait)
        try:
            resp = session.get(url, timeout=TIMEOUT, headers=headers, allow_redirects=False)
        except requests.RequestException as e:
            logger.warning(f'{provider}: request failed: {e}')
        else:
            if resp.status_code != 429 and resp.status_code < 500:
                try:
                    return resp.status_code, resp.json()
                except ValueError:
                    logger.warning(f'{provider}: non-JSON response ({resp.status_code})')
                    return resp.status_code, None
            logger.warning(f'{provider}: HTTP {resp.status_code}')
            if resp.status_code == 429:
                try:
                    delay = float(getattr(resp, 'headers', {}).get('Retry-After', ''))
                except (TypeError, ValueError):
                    delay = None
                if delay is not None and delay > 0:
                    if max_wait is not None and delay > max_wait:
                        return None, None
                    retry_after = min(delay, 300)
        if attempt < RETRIES:
            if budget is not None and not budget():
                return None, None
            sleep(retry_after if retry_after is not None else 2 ** attempt)
    return None, None
