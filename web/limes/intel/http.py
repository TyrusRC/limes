"""Polite JSON fetches from passive third-party providers. Never contacts a target.

NOTE: rate state is per process (prefork workers each keep their own); crt.sh is often
slow or down. Upgrade path: a shared rate limiter in Redis and a local CT mirror/certstream.
"""
import logging
import time

import requests

logger = logging.getLogger(__name__)

TIMEOUT = 30
RETRIES = 2
MIN_INTERVAL = {'crtsh': 5.0, 'internetdb': 1.0, 'ripestat': 0.25}
HEADERS = {'User-Agent': 'Limes-ASM'}
_last = {}


def get_json(url, *, provider, session=requests, clock=time.monotonic, sleep=time.sleep):
    """(status, parsed JSON | None); (None, None) after retries. Never raises."""
    for attempt in range(RETRIES + 1):
        wait = MIN_INTERVAL.get(provider, 1.0) - (clock() - _last.get(provider, float('-inf')))
        if wait > 0:
            sleep(wait)
        _last[provider] = clock()
        try:
            resp = session.get(url, timeout=TIMEOUT, headers=HEADERS, allow_redirects=False)
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
        if attempt < RETRIES:
            sleep(2 ** attempt)
    return None, None
