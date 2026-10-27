"""leak.public_code (opt-in): public code that mentions an owned root next to a credential on the SAME line.

Needs LIMES_CODE_SEARCH_TOKEN (a GitHub token for code search); without it nothing runs and nothing is written. For
each owned root: the exact domain string is searched through api.github.com (the only host allowlisted here,
safe_fetch.allowlisted_get: vetted, pinned, no redirect), at most MAX_PAGES pages, rate limited and under a daily
budget that fails closed. The matched text fragments GitHub returns are UNTRUSTED: each line holding the domain is run
through the shape detectors of limes.checks.leak.scan_text, and only a hit keeps anything, and only the repository name,
the path (both validated or clipped) and a masked shape. Fragments and files are never stored or logged; the token
travels in one header and appears in no log line, URL, exception message or evidence. Provisional (0 points).
NOTE: the detectors are the Supabase key shapes of checks/leak.py. Upgrade path: more provider shapes there, with a
test per shape."""
import json
import logging
import re
import time
from datetime import timedelta
from urllib.parse import quote

import requests
from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.utils import timezone

from limes import safe_fetch
from limes.checks.catalogue import Result
from limes.checks.leak import scan_text
from limes.checks.run import _write
from limes.intel import ratelimit
from startScan.models import RiskCheck

log = logging.getLogger(__name__)

CHECK = 'leak.public_code'
HOST = 'api.github.com'
PROVIDER = 'github_code'
MAX_PAGES = 3
PER_PAGE = 30
MAX_HITS = 10
MAX_LINE = 16384
BODY_CAP = 1024 * 1024
TIMEOUT = 10
# NOTE: GitHub allows about 10 code-search calls a minute per token; one slot per 7 s stays under it. The daily budget
# is shared by all projects. Upgrade path: a setting.
INTERVAL = 7.0
MAX_WAIT = 30
DAILY_BUDGET = 60
REFRESH = timedelta(hours=23)
REPO_RE = re.compile(r'[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}')


class Stop(Exception):
    """Budget spent, rate-limited or refused: end the search (the root's row says 'error', never 'pass')."""


def clip(value, n=200):
    return ''.join(c for c in value if c.isprintable())[:n] if isinstance(value, str) else None


def hits_in(items, root):
    """[{'repo', 'path', 'shape'}] for search items whose matched text has the root and a credential on one line."""
    needle, out = root.lower(), []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        repo = (item.get('repository') or {}).get('full_name') if isinstance(item.get('repository'), dict) else None
        path = clip(item.get('path'))
        if not isinstance(repo, str) or not REPO_RE.fullmatch(repo) or not path:
            continue
        for match in item.get('text_matches') or []:
            fragment = match.get('fragment') if isinstance(match, dict) else None
            shape = None
            for line in (fragment if isinstance(fragment, str) else '').splitlines():
                if needle in line.lower() and len(line) <= MAX_LINE:
                    found = scan_text(line)['secrets']
                    if found:
                        shape = found[0]['shape']
                        break
            if shape:
                out.append({'repo': repo, 'path': path, 'shape': shape})
                break  # one hit per file
    return out


def _page(get, root, page, token, ua, sleep, clock=time.time):
    if not ratelimit.take_daily(PROVIDER, DAILY_BUDGET):
        raise Stop('budget')
    wait = ratelimit.reserve(PROVIDER, INTERVAL, clock())
    if wait is None or wait > MAX_WAIT:
        raise Stop('busy')
    if wait:
        sleep(wait)
    url = f'https://{HOST}/search/code?q={quote(chr(34) + root + chr(34))}&per_page={PER_PAGE}&page={page}'
    headers = {'User-Agent': ua, 'Accept': 'application/vnd.github.text-match+json',
               'X-GitHub-Api-Version': '2022-11-28', 'Authorization': f'Bearer {token}'}
    try:
        resp = get(url, headers=headers, timeout=TIMEOUT, allow_redirects=False, stream=True)
        try:
            if resp.status_code != 200:
                raise Stop(f'status {resp.status_code}')
            buf = b''
            for chunk in resp.iter_content(chunk_size=65536):
                buf += chunk[:BODY_CAP - len(buf)]
                if len(buf) >= BODY_CAP:
                    break
            return json.loads(buf)
        finally:
            resp.close()
    except (Stop, SoftTimeLimitExceeded):
        raise
    except (requests.exceptions.RequestException, OSError, TimeoutError, ValueError, RecursionError):
        raise Stop('request failed')  # the type only is worth knowing; the message may echo the request


def search_root(root, token, now, get, ua, sleep=time.sleep):
    """Search one root and write its leak.public_code row. Returns {'pages', 'hits'}."""
    hits, pages, complete = [], 0, True
    try:
        for page in range(1, MAX_PAGES + 1):
            body = _page(get, root.value, page, token, ua, sleep)
            pages += 1
            items = body.get('items') if isinstance(body, dict) else None
            hits += hits_in(items, root.value)
            if not isinstance(items, list) or len(items) < PER_PAGE:
                break
    except Stop as e:
        complete = False
        log.warning('code search: stopped for a root (%s)', e)
    seen, unique = set(), []
    for h in hits:
        if (h['repo'], h['path']) not in seen:
            seen.add((h['repo'], h['path']))
            unique.append(h)
    if unique:
        result = Result(CHECK, 'fail', {'hits': unique[:MAX_HITS], 'count': len(unique)})
    elif complete:
        result = Result(CHECK, 'pass', {'pages': pages})
    else:
        result = Result(CHECK, 'error', {'reason': 'search cut short', 'pages': pages})
    _write(root, [result], now)
    return {'pages': pages, 'hits': len(unique)}


def discover(project, root, now=None, make_get=None, sleep=time.sleep):
    """leak.public_code for one owned root; off without LIMES_CODE_SEARCH_TOKEN. Never raises into the stage."""
    token = settings.CODE_SEARCH_TOKEN
    if not token:
        return {'reason': 'no token'}
    if root.kind != 'root_domain' or root.scope_tier != 'owned_root' or root.state == 'retired':
        return {'reason': 'not an owned root'}
    now = now or timezone.now()
    row = RiskCheck.objects.filter(asset=root, check_id=CHECK).first()
    if row and row.status != 'error' and now - row.last_checked < REFRESH:
        return {'reason': 'fresh'}
    get = (make_get or (lambda: safe_fetch.allowlisted_get((HOST,))))()
    try:
        return search_root(root, token, now, get, 'Limes-ASM', sleep)
    except SoftTimeLimitExceeded:
        raise
    except Exception as e:  # noqa: BLE001 - type only: a message could carry request data
        log.error('code search failed: %s', type(e).__name__)
        return {'reason': 'failed'}
