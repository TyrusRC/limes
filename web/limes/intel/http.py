"""Polite JSON fetches from passive third-party providers. Never contacts a target.

NOTE: crt.sh is often slow or down. Upgrade path: a local CT mirror/certstream. Rate limits are shared
across workers through the cache (see ratelimit).
"""
import json
import logging
import socket
import threading
import time

import requests

from limes.intel import ratelimit

logger = logging.getLogger(__name__)

TIMEOUT = 30
RETRIES = 2
MIN_INTERVAL = {'crtsh': 5.0, 'internetdb': 1.0, 'ripestat': 0.25, 'hibp': 7.0, 'rdap': 2.0}
HEADERS = {'User-Agent': 'Limes-ASM'}
MAX_BODY = 5 * 1024 * 1024  # the cap callers of untrusted, unbounded providers pass as max_bytes (as feeds.parse._json)
BODY_DEADLINE = 30  # seconds the whole body may take when a cap is set


class _Refused(Exception):
    """A capped body was too big or too slow: an error, never a partial parse."""


def _read_capped(resp, max_bytes, deadline):
    """The body as bytes, at most max_bytes, within `deadline` seconds in total. A watchdog shuts the socket down at
    the deadline, so a trickle that keeps each read under the per-read timeout still ends."""
    # the socket sits on the connection (urllib3 1.x) or only under the response's buffered file (2.x)
    sock = getattr(getattr(resp.raw, '_connection', None), 'sock', None) \
        or getattr(getattr(getattr(getattr(resp.raw, '_fp', None), 'fp', None), 'raw', None), '_sock', None)
    fired = []

    def expire():
        fired.append(1)
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except (OSError, AttributeError):
            pass
    timer = threading.Timer(deadline, expire)
    timer.daemon = True
    timer.start()
    try:
        chunks, size = [], 0
        for chunk in resp.iter_content(chunk_size=65536):
            size += len(chunk)
            if size > max_bytes:
                raise _Refused('too big')
            chunks.append(chunk)
        if fired:
            raise _Refused('too slow')
        return b''.join(chunks)
    except (requests.RequestException, OSError):
        if fired:
            raise _Refused('too slow')
        raise
    finally:
        timer.cancel()
        resp.close()


def get_json(url, *, provider, session=requests, clock=time.time, sleep=time.sleep, headers=None, max_wait=None, budget=None, max_bytes=None, deadline=BODY_DEADLINE):
    """(status, parsed JSON | None); (None, None) after retries or when the provider is saturated, or when the
    reserved slot is further away than `max_wait` seconds (no sleep). A 429's Retry-After is honoured (a longer wait than
    `max_wait`, when set, gives up); `budget()` is called before each retry and a False ends the call. `headers` are merged over HEADERS. With `max_bytes` the body is streamed: one over that size, or taking longer than
    `deadline` seconds in all, is an error (None, None) and is not retried. Never raises."""
    headers = {**HEADERS, **(headers or {})}
    for attempt in range(RETRIES + 1):
        retry_after = None
        wait = ratelimit.reserve(provider, MIN_INTERVAL.get(provider.split(':', 1)[0], 1.0), clock())
        if wait is None:  # provider saturated: same outcome as exhausted retries, without a long sleep
            logger.warning(f'{provider}: rate-limit slots exhausted, skipping')
            return None, None
        if max_wait is not None and wait > max_wait:
            logger.warning(f'{provider}: next slot {wait:.0f}s away, skipping')
            return None, None
        if wait > 0:
            sleep(wait)
        try:
            resp = session.get(url, timeout=TIMEOUT, headers=headers, allow_redirects=False,
                               **({'stream': True} if max_bytes else {}))
            if max_bytes and resp.status_code != 429 and resp.status_code < 500:
                raw = _read_capped(resp, max_bytes, deadline)
        except _Refused as e:
            logger.warning(f'{provider}: response {e}, skipping')
            return None, None
        except requests.RequestException as e:
            logger.warning(f'{provider}: request failed: {e}')
        else:
            if resp.status_code != 429 and resp.status_code < 500:
                try:
                    return resp.status_code, json.loads(raw) if max_bytes else resp.json()
                except (ValueError, RecursionError):
                    logger.warning(f'{provider}: non-JSON response ({resp.status_code})')
                    return resp.status_code, None
            if max_bytes:
                resp.close()
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
