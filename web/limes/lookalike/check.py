"""Checks of one lookalike row: DNS (NS, then A/AAAA/MX), RDAP, CT, and the opt-in HTTP look. All network access is
injected. DNS and RDAP calls are counted through `spend`, and a refusal raises Stop before the row is saved, so a
half-checked row is never stored. Lookalikes are never Assets and never pass through scope.may_attack: the
opt-in GET is a single vetted, pinned request, not a scan."""
import html
import logging
import re
from datetime import timedelta
from urllib.parse import urlsplit

import requests
from django.conf import settings

from limes import safe_fetch
from limes.checks import collect
from limes.identity import ScanIdentity
from limes.intel import crtsh, http, ratelimit
from limes.lookalike import generate, rdap
from limes.lookalike.rdap import CTRL
from startScan.models import Lookalike

log = logging.getLogger(__name__)

D = timedelta(days=1)
NEXT = {'unregistered': 7 * D, 'registered': D, 'watching': D, 'reported': D, 'ignored': 30 * D, 'gone': 30 * D,
        'unchecked': timedelta(0)}
RDAP_EVERY = 30 * D
CT_WATCHING, CT_OTHER = D, 30 * D
DNS_RETRY = timedelta(hours=1)
HTTP_EVERY = 7 * D
HTTP_DAILY = 50
BODY_CAP = 256 * 1024
FRESH = 30 * D  # RDAP creation this recent makes a registration "phishing ready" when it also has mail or a certificate
DECIDED = ('watching', 'ignored', 'ours', 'reported')
MAX_LIST, MAX_STR, MAX_CERTS = 10, 253, 10
HEAD_BYTES = 16 * 1024  # the title is searched for in the head of the page only
FORM_BYTES = 64 * 1024
# bounded quantifiers: a hostile page of repeated "<input " or "<title " must not make the search quadratic
TITLE_RE = re.compile(r'<title[^>]{0,200}>(.{0,1000}?)</title>', re.I | re.S)
PASSWORD_RE = re.compile(r'<input[^>]{0,300}?type\s{0,10}=\s{0,10}["\']?password', re.I)
BACKOFF_CAP = 24 * 3600


class Stop(Exception):
    """A spend was refused (budget or tick share spent): end the tick. `events` are those already earned."""
    def __init__(self, events=()):
        super().__init__('budget')
        self.events = list(events)


def defang(domain):
    return domain.replace('.', '[.]')


CREATED_RE = r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?[+-]\d\d:\d\d$'


def with_created(qs):
    """Annotate `created`: the RDAP registration time as a timestamp, NULL when RDAP has none. Only the exact
    shape rdap.parse writes (isoformat with an offset) is cast, so a stray value can never break the query."""
    from django.db.models import Case, DateTimeField, When
    from django.db.models.fields.json import KeyTextTransform
    from django.db.models.functions import Cast
    return qs.annotate(created=Case(
        When(rdap__created__regex=CREATED_RE, then=Cast(KeyTextTransform('created', 'rdap'), DateTimeField())),
        default=None, output_field=DateTimeField()))


def due_rows(now, limit):
    return list(Lookalike.objects.filter(next_check__lte=now, root__kind='root_domain', root__scope_tier='owned_root')
                .exclude(status='ours').exclude(root__state='retired').select_related('root', 'project')
                .order_by('next_check', 'id')[:limit])


def _records(found):
    return [str(r)[:MAX_STR] for r in found[:MAX_LIST]]


def _query(resolve, name, rdtype, spend):
    if not spend('dns'):
        raise Stop
    return collect._lookup(resolve, name, rdtype)


def _ct_summary(rows, domain):
    certs = []
    for row in rows[:5000] if isinstance(rows, list) else []:
        if not isinstance(row, dict) or not isinstance(row.get('id'), int):
            continue
        names = crtsh.parse([row])
        if any(n == domain or n.endswith('.' + domain) for c in names for n in c['names']):
            stamp = str(row.get('not_before') or row.get('entry_timestamp') or '')[:10]
            certs.append({'id': row['id'], 'date': stamp if re.fullmatch(r'\d{4}-\d\d-\d\d', stamp) else ''})
    certs.sort(key=lambda c: (c['date'], c['id']))
    dates = [c['date'] for c in certs if c['date']]
    return {'count': len(certs), 'first_seen': dates[0] if dates else '', 'last_seen': dates[-1] if dates else '',
            'certs': certs[:MAX_CERTS]}


def covered(domain, owned):
    """True when `domain` is an owned value or a name under one."""
    labels = domain.lower().split('.')
    return any('.'.join(labels[i:]) in owned for i in range(len(labels) - 1))


def analyse(text, label):
    """(title, has password field, brand label present) of a fetched page; every search is bounded."""
    m = TITLE_RE.search(text[:HEAD_BYTES])
    title = CTRL.sub('', re.sub(r'\s+', ' ', html.unescape(m.group(1))).strip()) if m else ''
    return title[:200], bool(PASSWORD_RE.search(text[:FORM_BYTES])), label in text.lower()


def _due(stamp, now, every):
    return stamp is None or now - stamp >= every


def check_row(row, now, resolve, get, bootstrap, spend):
    """Check one row and save it; returns [(kind, title, key)] events for the caller to record (or drop, when the
    root has no baseline yet)."""
    if row.status == 'ours':
        return []
    if not generate.valid_fqdn(row.domain):  # hostile or malformed name: never resolved
        row.next_check, row.last_checked = now + NEXT['gone'], now
        row.save(update_fields=['next_check', 'last_checked'])
        return []
    was_registered, was_status = row.registered, row.status
    # an earlier attempt failed before any answer: the registration is part of the baseline, not news
    silent = row.last_checked is not None and was_registered is None
    had = {'mx': row.has_mx, 'a': bool((row.dns or {}).get('a')), 'cert': bool((row.ct or {}).get('count'))}

    ns = _query(resolve, row.domain, 'NS', spend)
    answers = {}
    if ns != 'error' and ns:
        for rdtype in ('A', 'AAAA', 'MX'):
            answers[rdtype] = _query(resolve, row.domain, rdtype, spend)
    if ns == 'error' or 'error' in answers.values():
        try:
            fails = int((row.dns or {}).get('fails', 0)) + 1
        except (TypeError, ValueError):
            fails = 1
        delay = min(DNS_RETRY.total_seconds() * 2 ** min(fails - 1, 10), BACKOFF_CAP)
        row.dns = {**(row.dns or {}), 'fails': fails}
        row.next_check, row.last_checked = now + timedelta(seconds=delay), now
        row.save(update_fields=['dns', 'next_check', 'last_checked'])
        return []

    registered = bool(ns)
    dns = {'ns': [], 'a': [], 'aaaa': [], 'mx': []}
    if registered:
        dns = {'ns': _records(ns), 'a': _records(answers['A']), 'aaaa': _records(answers['AAAA']),
               'mx': _records(answers['MX'])}
    stop, gone = False, False
    rdap_info, rdap_at = row.rdap, row.rdap_checked_at
    if registered or was_registered is True:  # a known-registered row with no NS needs the registry to say if it is gone
        needed = not registered or not row.rdap or _due(row.rdap_checked_at, now, RDAP_EVERY)
        if needed and rdap.server_for(row.domain, bootstrap):
            if not spend('rdap'):
                if not registered:
                    raise Stop  # nothing earned yet: leave the row for the next tick
                stop = True
            else:
                state, info = rdap.lookup(row.domain, bootstrap, get)
                if state == 'registered':
                    rdap_info, rdap_at = info, now
                gone = state == 'unregistered' and not registered
        registered = registered or not gone  # an unknown answer or no RDAP server never flips a known registration
    ct, ct_at = row.ct, row.ct_checked_at
    if registered and not gone and not stop and _due(ct_at, now, CT_WATCHING if row.status == 'watching' else CT_OTHER):
        status, body = get(crtsh.exact_url(row.domain), provider='crtsh', max_wait=rdap.WAIT, max_bytes=http.MAX_BODY)
        if status == 200 and isinstance(body, list):
            # Live sightings from the certificate watch (limes.ct.lookalikes) are written by another process while
            # this check runs: read the stored value now, not the copy loaded at the start of the tick.
            # NOTE: the row is saved whole below, so a sighting landing between this read and the save is lost
            # (one count). Upgrade: save with update_fields and a locked read of ct.
            stored = Lookalike.objects.filter(pk=row.pk).values_list('ct', flat=True).first()
            live = (stored if isinstance(stored, dict) else {}).get('live')
            ct, ct_at = _ct_summary(body, row.domain), now
            if isinstance(live, dict):
                ct = dict(ct, live=live)

    if gone:
        status = 'gone'
    elif not registered:
        status = was_status if was_status in DECIDED else 'unregistered'
    elif was_status in ('unchecked', 'unregistered', 'gone'):
        status = 'registered'
    else:
        status = was_status
    row.registered = registered
    row.status, row.dns, row.rdap, row.rdap_checked_at, row.ct, row.ct_checked_at = status, dns, rdap_info, rdap_at, ct, ct_at
    row.has_mx = bool(collect._mx_hosts(dns['mx']))
    row.last_checked = now
    row.next_check = now + NEXT[status]

    events = []
    title_domain = defang(row.domain)
    cert = bool((ct or {}).get('count'))
    if silent:
        pass
    elif row.registered and was_registered is not True and was_status != 'ignored':
        created = None
        try:
            from django.utils.dateparse import parse_datetime
            created = parse_datetime((rdap_info or {}).get('created') or '')
        except ValueError:
            pass
        ready = created is not None and now - created <= FRESH and (row.has_mx or cert)
        events.append(('lookalike_new', f'New lookalike {title_domain} of {row.root.value}', 'phishing_ready' if ready else None))
    elif row.registered and status == 'watching' and (
            (row.has_mx and not had['mx']) or (dns['a'] and not had['a']) or (cert and not had['cert'])):
        events.append(('lookalike_active', f'Lookalike {title_domain} of {row.root.value} gained mail, an address or a certificate', None))
    row.save()
    if stop:
        raise Stop(events)
    return events


def _http_record(now, status=None, title='', brand=False, password=False, location=None):
    return {'status': status, 'title': title[:200], 'brand_in_page': brand, 'password_field': password,
            'location_host': location, 'checked_at': now.isoformat()}


def _body(resp):
    chunks, size = [], 0
    for chunk in resp.iter_content(chunk_size=16384):
        chunks.append(chunk)
        size += len(chunk)
        if size >= BODY_CAP:
            break
    return b''.join(chunks)[:BODY_CAP].decode('utf-8', 'replace')


def check_http(row, now, get_factory=safe_fetch.pinned_get, resolve=collect._resolve, spend=None):
    """Opt-in (LOOKALIKE_HTTP): one GET https://<domain>/ at most weekly for a registered row with an A record, through
    a vetted public IP, no redirects, no scan identity headers beyond the User-Agent. Never contacts anything else."""
    if not settings.LOOKALIKE_HTTP or row.status in ('ignored', 'ours') or not row.registered or not (row.dns or {}).get('a'):
        return None
    try:
        from django.utils.dateparse import parse_datetime
        last = parse_datetime((row.http or {}).get('checked_at') or '')
    except ValueError:
        last = None
    if last is not None and now - last < HTTP_EVERY:
        return None
    if not ratelimit.take_daily('lookalike_http', HTTP_DAILY):
        return None
    record = _http_record(now)
    def metered(name, rdtype):  # the vetting lookups spend the same DNS budget as every other lookalike query
        if spend is not None and not spend('dns'):
            raise Stop
        return resolve(name, rdtype)
    ip, reason = safe_fetch.resolve_vetted(row.domain, metered)
    if reason:
        log.info('lookalike http: address refused, not contacted')
    else:
        from targetApp.models import Domain
        ua = ScanIdentity.for_domain(Domain.objects.filter(project_id=row.project_id, name=row.root.value).first()).ua
        deadline = safe_fetch.Deadline()
        try:
            resp = get_factory(row.domain, ip, deadline=deadline)(
                f'https://{row.domain}/', headers={'User-Agent': ua}, timeout=collect.TIMEOUT,
                allow_redirects=False, stream=True)
            try:
                text = _body(resp)
                title, password, brand = analyse(text, generate._EXTRACT(row.root.value).domain)
                location = None
                if 300 <= resp.status_code < 400:
                    try:
                        host = urlsplit(resp.headers.get('Location') or '').hostname
                    except ValueError:
                        host = None
                    location = host.lower()[:253] if host else None
                record = _http_record(now, resp.status_code, title, brand, password, location)
            finally:
                resp.close()
        except (requests.RequestException, OSError, ValueError):
            pass  # unreachable or hostile: recorded as "looked, nothing usable"
    row.http = record
    row.save(update_fields=['http'])
    return record
