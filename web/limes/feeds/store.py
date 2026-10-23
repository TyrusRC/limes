"""Download, validate and keep third-party feeds. One conditional GET per call; a failed, oversize, unparsable or
empty download never replaces the last good copy (it only records a status the UI can show)."""
import hashlib
import logging
import os
import re
import threading
import time
from datetime import timedelta
from urllib.parse import urljoin, urlsplit

import requests
from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings

from limes.feeds import parse, sources
from startScan.models import FeedState

logger = logging.getLogger(__name__)

MAX_BYTES = 50 * 1024 * 1024
CHUNK = 64 * 1024
TIMEOUT = 30
DEADLINE = 180  # seconds for the whole download, so a slow drip cannot hold a worker
SHRINK_FLOOR = 50  # below this many previous entries a smaller copy is not treated as a collapse
SHRINK_RATIO = 0.5
MAX_REDIRECTS = 3
HEADERS = {'User-Agent': 'Limes-ASM'}
_REDIRECTS = (301, 302, 303, 307, 308)
_HEADER_VALUE = re.compile(r'^[\x20-\x7e]{1,200}$')

# NOTE: one parsed copy per feed per worker process; EPSS is never loaded this way (read + parse(wanted)).
# Upgrade path: a shared cache
_CACHE = {}


class FetchError(Exception):
    """Carries only a short, header-free reason."""


def feed_path(name):
    if name not in sources.FEEDS:
        raise KeyError(name)
    return os.path.join(settings.LIMES_RESULTS, 'feeds', name)


def read(name):
    try:
        with open(feed_path(name), 'rb') as f:
            return f.read()
    except (OSError, KeyError):
        return None


def load(name):
    """(data, meta) of the stored feed, parsed once per (name, sha256); None when nothing good is stored."""
    state = FeedState.objects.filter(name=name).first()
    blob = read(name) if state and state.sha256 else None
    if blob is None:
        return None
    hit = _CACHE.get(name)
    if hit and hit[0] == state.sha256:
        return hit[1]
    result = parse.PARSERS[sources.FEEDS[name].parser](blob)
    _CACHE[name] = (state.sha256, result)
    return result


def is_stale(feed, state, now):
    return state is None or state.last_good_at is None or state.last_good_at < now - 3 * feed.cadence


def due(feed, state, now):
    return state is None or state.fetched_at is None or state.fetched_at <= now - feed.cadence


def _same_host(url, origin):
    a, b = urlsplit(url), urlsplit(origin)
    return (a.scheme == 'https' and a.hostname == b.hostname and a.port in (None, 443)
            and not a.username and not a.password)


def _headers(feed, url, state, have_file):
    h = dict(HEADERS)
    host = urlsplit(url).hostname or ''
    if settings.ABUSECH_AUTH_KEY and (host == 'abuse.ch' or host.endswith('.abuse.ch')):
        h['Auth-Key'] = settings.ABUSECH_AUTH_KEY
    if state and have_file:  # without the file a 304 would leave us with nothing
        if state.etag and _HEADER_VALUE.match(state.etag):
            h['If-None-Match'] = state.etag
        if state.last_modified and _HEADER_VALUE.match(state.last_modified):
            h['If-Modified-Since'] = state.last_modified
    return h


def _download(feed, state, session):
    """(status_code, response headers, body) after at most MAX_REDIRECTS same-host https redirects."""
    if not feed.url.startswith('https://'):
        raise FetchError('NotHttps')
    url, started = feed.url, time.monotonic()
    have_file = os.path.exists(feed_path(feed.name))
    for _ in range(MAX_REDIRECTS + 1):
        resp = session.get(url, headers=_headers(feed, url, state, have_file), timeout=TIMEOUT, stream=True,
                           allow_redirects=False)
        try:
            code = resp.status_code
            if code in _REDIRECTS:
                nxt = urljoin(url, resp.headers.get('Location', ''))
                if not _same_host(nxt, feed.url):
                    raise FetchError('RedirectRejected')
                url = nxt
                continue
            if code != 200:
                return code, resp.headers, b''
            body = bytearray()
            # The deadline is total wall-clock: the timer closes the connection even while a read is blocked on a
            # server that drips one byte at a time (the per-chunk check alone would never fire).
            timer = threading.Timer(DEADLINE, resp.close)
            timer.daemon = True
            timer.start()
            try:
                for chunk in resp.iter_content(CHUNK):
                    body += chunk
                    if len(body) > MAX_BYTES:
                        raise FetchError('TooLarge')
                    if time.monotonic() - started > DEADLINE:
                        raise FetchError('Timeout')
            except FetchError:
                raise
            except Exception:
                if time.monotonic() - started >= DEADLINE:
                    raise FetchError('Timeout') from None
                raise
            finally:
                timer.cancel()
            return code, resp.headers, bytes(body)
        finally:
            resp.close()
    raise FetchError('TooManyRedirects')


def _write(path, blob):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'wb') as f:
        f.write(blob)
    os.replace(tmp, path)


def _problem(feed, state, meta):
    """Why a parsed copy must not replace the last good one, or ''."""
    rows, dropped = meta['rows'], meta['dropped']
    if rows == 0 and (dropped > 0 or not feed.allow_empty):
        return 'EmptyFeed'  # also an error page of garbage lines on feeds that may legitimately be empty
    if 'declared' in meta and meta['declared'] != rows + dropped:
        return 'CountMismatch'  # truncated, or the publisher's trailer/count is missing
    if state.entries >= SHRINK_FLOOR and state.last_good_at and rows < SHRINK_RATIO * state.entries:
        return 'shrank'
    return ''


def fetch(feed, now, session=requests):
    """One conditional GET of `feed`; returns and records the status (ok|not_modified|error|rejected)."""
    state, _ = FeedState.objects.get_or_create(name=feed.name, defaults={'url': feed.url})
    state.url, state.fetched_at = feed.url, now
    try:
        code, headers, body = _download(feed, state, session)
        if code == 304:
            state.status, state.error = 'not_modified', ''
            if os.path.exists(feed_path(feed.name)):
                state.last_good_at = now  # confirmed unchanged: it is as fresh as a new copy
        elif code != 200:
            raise FetchError(f'HTTP {code}')
        else:
            data, meta = parse.PARSERS[feed.parser](body)
            problem = _problem(feed, state, meta)
            if problem:
                state.status, state.error = 'rejected', problem
            else:
                _write(feed_path(feed.name), body)
                tag = lambda k: headers.get(k, '') if _HEADER_VALUE.match(headers.get(k, '')) else ''  # noqa: E731
                state.sha256, state.entries = hashlib.sha256(body).hexdigest(), meta['rows']
                state.etag, state.last_modified = tag('ETag'), tag('Last-Modified')
                state.source_date, state.last_good_at = meta.get('source_date'), now
                state.status, state.error = 'ok', ''
    except SoftTimeLimitExceeded:
        raise
    except Exception as e:  # noqa: BLE001 - hostile input: any failure keeps the last good copy
        # Only the HTTP status or the exception class: never headers, URLs or messages (they can echo a key).
        reason = str(e) if isinstance(e, FetchError) else type(e).__name__
        state.status, state.error = 'error', reason[:300]
    if state.status in ('error', 'rejected'):
        logger.warning('feed %s: %s %s', feed.name, state.status, state.error)
    state.save()
    return state.status
