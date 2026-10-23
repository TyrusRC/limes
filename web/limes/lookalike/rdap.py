"""RDAP (RFC 9083) lookups through the IANA bootstrap. https servers only; every string from a registry is
untrusted: capped on parse, escaped on display."""
import re
from urllib.parse import quote, urlsplit

from django.utils.dateparse import parse_datetime

from limes.intel import http

MAX_STR = 200
MAX_STATUSES = 10
MAX_ENTITIES = 50
# Deliberately narrower than RFC 5322 atext: no ? & = # % and friends, which could smuggle mailto: parameters.
EMAIL_RE = re.compile(r'[A-Za-z0-9](?:(?:[A-Za-z0-9+_-]|\.(?!\.)){0,62}[A-Za-z0-9])?@'
                      r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,6}[A-Za-z]{2,24}')
# C0 and C1 controls, line/paragraph separators, bidi overrides and isolates, zero-width and BOM characters
CTRL = re.compile('[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]+')
WAIT = 10


def server_for(domain, bootstrap):
    base = (bootstrap or {}).get((domain or '').rsplit('.', 1)[-1].lower())
    try:
        parts = urlsplit(base) if isinstance(base, str) else None
    except ValueError:
        return None
    if not parts or parts.scheme != 'https' or not parts.hostname:
        return None
    return base if base.endswith('/') else base + '/'


def _text(v):
    return CTRL.sub(' ', v).strip()[:MAX_STR] if isinstance(v, str) else ''


def _vcard(entity, prop):
    card = entity.get('vcardArray')
    rows = card[1] if isinstance(card, list) and len(card) == 2 and isinstance(card[1], list) else []
    for row in rows[:50]:
        if isinstance(row, list) and len(row) >= 4 and row[0] == prop:
            return _text(row[3])
    return ''


def _entities(obj, depth=0):
    """Every entity, nested ones included, bounded in depth and count."""
    out = []
    for e in (obj.get('entities') if isinstance(obj, dict) else None) or []:
        if isinstance(e, dict) and len(out) < MAX_ENTITIES:
            out.append(e)
            if depth < 3:
                out += _entities(e, depth + 1)[:MAX_ENTITIES]
    return out[:MAX_ENTITIES]


def _role(entities, role):
    return next((e for e in entities if role in (e.get('roles') if isinstance(e.get('roles'), list) else [])), None)


def parse(obj):
    out = {'registrar': '', 'created': '', 'abuse_email': '', 'statuses': []}
    if not isinstance(obj, dict):
        return out
    ents = _entities(obj)
    registrar = _role(ents, 'registrar')
    if registrar:
        out['registrar'] = _vcard(registrar, 'fn')
    abuse = _role(ents, 'abuse')
    email = _vcard(abuse, 'email') if abuse else ''
    out['abuse_email'] = email if EMAIL_RE.fullmatch(email) else ''
    for ev in (obj.get('events') if isinstance(obj.get('events'), list) else [])[:50]:
        if isinstance(ev, dict) and ev.get('eventAction') == 'registration':
            try:
                when = parse_datetime(str(ev.get('eventDate') or '')[:40])
            except ValueError:
                when = None
            if when is not None and when.tzinfo is not None:
                out['created'] = when.isoformat()
            break
    statuses = obj.get('status') if isinstance(obj.get('status'), list) else []
    out['statuses'] = [s for s in (_text(x) for x in statuses[:MAX_STATUSES * 3]) if s][:MAX_STATUSES]
    return out


def lookup(domain, bootstrap, get):
    """('registered' | 'unregistered' | 'unknown', parsed info). 404 is the registry saying it does not exist."""
    base = server_for(domain, bootstrap)
    if not base:
        return 'unknown', {}
    host = urlsplit(base).hostname
    status, body = get(f'{base}domain/{quote(domain, safe="")}', provider=f'rdap:{host}', max_wait=WAIT, max_bytes=http.MAX_BODY)
    if status == 404:
        return 'unregistered', {}
    if status == 200 and isinstance(body, dict):
        return 'registered', parse(body)
    return 'unknown', {}
