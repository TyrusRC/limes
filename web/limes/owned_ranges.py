"""Owned address ranges: the one place addresses are counted against the size caps, plus the beat task that
refreshes ASN prefixes (RIPEstat) and walks owned ranges per IP (PTR + Shodan InternetDB).

NOTE: IP enumeration is an operator opt-in (settings.RANGE_ENUMERATION, default off). InternetDB says it is "free
for non-commercial use" and that using it "to make money" needs an enterprise license; its terms are only partly
published (no full ToS page, no stated rate limit; the 1 req/s is Limes's own throttle). Upgrade path: a paid
Shodan key or Limes's own scanner. Calls are capped per day (INTERNETDB_DAILY_BUDGET / PTR_DAILY_BUDGET) and
spread over 60 s ticks (ratelimit.per_tick).
"""
import ipaddress
import logging
import re
import time
from datetime import datetime, timedelta, timezone as dt_timezone

import dns.exception
import dns.resolver
import dns.reversename
import validators
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from limes import scope
from limes.alerts import events
from limes.alerts.deliver import deliver_immediate
from limes.celery import app
from limes.checks import collect
from limes.continuous import CADENCE_INTERVALS, tick_lock
from limes.intel import domains, http, internetdb, ratelimit, ripestat
from limes.tasks import inventory
from limes.tasks.intel import _store
from startScan.inventory_migrate import normalize_host
from dashboard.models import Project
from startScan.models import Asset, ChangeEvent

logger = logging.getLogger(__name__)

MAX_ENTRY_ADDRESSES = 4096  # per entry, applied to the total after a start-end range is summarised
TICK_BUDGET = 45  # seconds of work per tick; beat expires at 55 and the next tick is 60 s away
OWNED = ('owned_root', 'owned_host')
MAX_STEP_FAILURES = 3  # InternetDB failing on the same address this many ticks in a row: skip it this pass
ASN_RETRY_AFTER = timedelta(hours=6)  # after a failed RIPEstat lookup
ASN_RE = re.compile(r'AS\d{1,10}')


def addresses(value):
    """Number of addresses in an ip or CIDR string."""
    return ipaddress.ip_network(value, strict=False).num_addresses


def range_addresses(project, exclude_parent=None):
    """Addresses held by the project's owned, non-retired cidr rows; exclude_parent leaves out one ASN's children.

    NOTE: overlapping ranges are counted twice (conservative: errs toward refusing).
    Upgrade path: collapse with ipaddress.collapse_addresses before summing.
    """
    from startScan.models import Asset
    rows = Asset.objects.filter(project=project, kind='cidr', scope_tier__in=('owned_root', 'owned_host')
                                ).exclude(state='retired')
    if exclude_parent is not None:
        rows = rows.exclude(parent=exclude_parent)
    return sum(addresses(v) for v in rows.values_list('value', flat=True))


def _still_ours(asset):
    """The asset as stored now, or None unless it is still ours to act on: owned tier, not retired, cadence not
    off, and its parent (an ASN or a range) the same. Re-read right before every action."""
    a = Asset.objects.select_related('parent').filter(pk=asset.pk).first()
    ok = a is not None and a.scope_tier in OWNED and a.state != 'retired' and a.cadence_tier in CADENCE_INTERVALS
    p = a.parent if ok else None
    if p is not None:
        ok = p.scope_tier in OWNED and p.state != 'retired' and p.cadence_tier in CADENCE_INTERVALS
    return a if ok else None


def _set(asset, key, data):
    asset.enrichment = {**(asset.enrichment or {}), key: data}
    asset.save(update_fields=['enrichment'])


def _iso(now):
    return (now or timezone.now()).isoformat()


# ---- ASN -> announced prefixes ----

def refresh_asn(asset, get=http.get_json, now=None):
    """Sync an ASN's announced public prefixes into cidr children. A provider failure changes nothing ({})."""
    now = now or timezone.now()
    asset = _still_ours(asset)
    if asset is None or asset.kind != 'asn' or not ASN_RE.fullmatch(asset.value):
        return {}
    status, body = get(ripestat.announced_prefixes_url(asset.value), provider='ripestat')
    if status != 200:  # children and status stay as they were; only the attempt is noted so due_ranges backs off
        _set(asset, 'asn', {**((asset.enrichment or {}).get('asn') or {}), 'attempted_at': _iso(now)})
        return {}
    # NOTE: v1 enumerates IPv4 only. Walking a v6 prefix per address is infeasible (a /48 holds 2^80 addresses), so
    # IPv6 needs a different approach (sampling, CT logs, DNS); until then v6 prefixes are reported, never stored or counted.
    parsed = [ipaddress.ip_network(p) for p in ripestat.parse_announced_prefixes(body)]
    v6 = [str(n) for n in parsed if n.version == 6]
    # more-specifics fold into their covering prefix, so a /22 announced with its /24s counts and enumerates once
    nets = list(ipaddress.collapse_addresses(n for n in parsed if n.version == 4 and not scope.is_reserved_network(n)))
    # prefixes the project already holds as owned ranges (user-added or another ASN's) are not ours to count or re-parent
    held = set(Asset.objects.filter(project=asset.project, kind='cidr', scope_tier__in=OWNED)
               .exclude(state='retired').exclude(parent=asset).values_list('value', flat=True))
    nets = [n for n in nets if str(n) not in held]
    skipped = {'skipped_v6': len(v6), 'skipped_v6_examples': v6[:3]}
    total = sum(n.num_addresses for n in nets)
    cap = settings.RANGE_ADDRESS_CAP
    free = cap - range_addresses(asset.project, exclude_parent=asset)
    if total > free:  # checked before any child is stored: an over-cap ASN stores nothing and counts toward no cap
        out = {'status': 'refused', 'checked_at': _iso(now), **skipped,
               'reason': f"{asset.value} announces {total} addresses, over this project's {cap}-address cap "
                         f"({max(free, 0)} still free): add the specific ranges you own instead"}
        _set(asset, 'asn', out)
        return out
    announced = {str(n) for n in nets}
    with transaction.atomic():  # a killed task never leaves half-stored children behind a stale status
        for value in sorted(announced):
            child, created = Asset.objects.get_or_create(project=asset.project, kind='cidr', value=value,
                                                         defaults={'scope_tier': 'owned_host', 'parent': asset})
            if child.scope_tier not in OWNED:
                continue  # a candidate/rejected row of the same range is the user's decision
            inventory._append_source(child, 'asn', asset.value)
            child.save(update_fields=['sources'])
            child.mark_missing_or_seen(True)
        for child in Asset.objects.filter(parent=asset, kind='cidr', scope_tier__in=OWNED).exclude(value__in=announced):
            child.mark_missing_or_seen(False)  # missing only after MISSING_THRESHOLD refreshes
        out = {'status': 'ok', 'prefixes': sorted(announced), 'refreshed_at': _iso(now), **skipped}
        _set(asset, 'asn', out)
    return out


# ---- per-IP enumeration ----

def _valid_name(name):
    n = normalize_host(name) if isinstance(name, str) else ''
    return n if n and len(n) <= 253 and validators.domain(n) is True else None


def resolve_ptr(ip, resolve=collect._resolve):
    """Valid PTR names for ip; [] when there is none (NXDOMAIN/NoAnswer); None on a DNS error (retry later)."""
    try:
        rev = dns.reversename.from_address(ip).to_text()
        found = resolve(rev, 'PTR')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.DNSException, ValueError):
        return None
    names = []
    for raw in found:
        name = _valid_name(raw)
        if name and name not in names:
            names.append(name)
    return names


def place_names(project, names, ip_value, evidence):
    """Names under an owned root become hostnames of it; everything else is only a candidate root, never owned
    (shared hosting and CDN ranges are the classic false positive). Returns the newly created owned hostnames."""
    roots = {a.value: a for a in Asset.objects.filter(project=project, kind='root_domain', scope_tier='owned_root')}
    new = []
    for raw in names:
        name = _valid_name(raw)
        if not name or name in roots:
            continue
        root = max((v for v in roots if name.endswith('.' + v)), key=len, default=None)
        if root:
            existed = Asset.objects.filter(project=project, kind='hostname', value=name).exists()
            host = inventory.upsert_hostname_asset(project, name, parent=roots[root], source='cidr', evidence=evidence)
            if host and not existed:
                new.append(host)
            continue
        reg = domains.registrable(name)
        if reg and reg not in roots:
            inventory.upsert_candidate(project, 'root_domain', reg, 'cidr', evidence)
    return new


def _refuse(asset, enum, reason):
    _set(asset, 'enum', {**enum, 'status': 'refused', 'reason': reason})
    return {'internetdb': 0, 'ptr': 0, 'new': 0}, True


def _child_ip(asset, ip):
    """The ip child to record a live address on, or None when the row is the user's decision (candidate/rejected)."""
    child, created = Asset.objects.get_or_create(project=asset.project, kind='ip', value=str(ip),
                                                 defaults={'scope_tier': 'owned_host', 'parent': asset})
    if created:
        return child, True
    if child.scope_tier == 'dependency':
        child.scope_tier = 'owned_host'
        child.save(update_fields=['scope_tier'])
    if child.scope_tier not in OWNED:
        return None, False
    if child.parent_id is None:
        child.parent = asset
        child.save(update_fields=['parent'])
    return child, False


def _step(asset, idb_budget, ptr_budget, get, resolve, now):
    """One budgeted slice of a range walk: ({'internetdb', 'ptr', 'new'}, finished_or_refused)."""
    now = now or timezone.now()
    zero = {'internetdb': 0, 'ptr': 0, 'new': 0}
    asset = _still_ours(asset)
    if asset is None or asset.kind != 'cidr':
        return zero, True
    enum = {'cursor': 0, 'pass': 0, **((asset.enrichment or {}).get('enum') or {})}
    if enum.get('status') == 'refused':
        return zero, True
    try:
        net = ipaddress.ip_network(asset.value, strict=False)
    except ValueError:
        return _refuse(asset, enum, 'not a valid network')
    if scope.is_reserved_network(net):
        return _refuse(asset, enum, 'this range touches reserved or private address space')
    from_asn = asset.parent_id is not None and asset.parent.kind == 'asn'  # ASN children are bounded by the project cap
    if net.num_addresses > MAX_ENTRY_ADDRESSES and not from_asn:
        return _refuse(asset, enum, f'{asset.value} holds {net.num_addresses} addresses, over the {MAX_ENTRY_ADDRESSES}-address '
                                    'limit per entry: add smaller ranges you own instead')
    if enum.get('status') == 'done':
        enum.update(status='running', cursor=0)
    enum['status'] = 'running'
    used = {'internetdb': 0, 'ptr': 0, 'new': 0}
    size = net.num_addresses
    cursor = min(int(enum['cursor']), size)
    while cursor < size and idb_budget > 0 and ptr_budget > 0:
        ip = net[cursor]
        if scope.is_reserved_ip(ip):
            cursor += 1  # no budget spent
            continue
        # fails closed: a False (budget spent, or cache down) ends this tick's work; the cursor stays put
        if not ratelimit.take_daily('internetdb', settings.INTERNETDB_DAILY_BUDGET):
            break
        status, body = get(internetdb.build_url(str(ip)), provider='internetdb')
        idb_budget, ptr_budget = idb_budget - 1, ptr_budget - 1
        used['internetdb'] += 1
        data = internetdb.parse(body) if status == 200 else None
        if status not in (200, 404):  # provider failure: nothing recorded; give up on this address after a few ticks
            enum['fails'] = enum.get('fails', 0) + 1
            if enum['fails'] < MAX_STEP_FAILURES:
                break
            enum['fails'] = 0
            cursor += 1
            continue
        enum['fails'] = 0
        # the PTR unit is taken only when the lookup is about to run; if it is refused the address is still
        # processed from InternetDB alone (names unknown, retried next pass) and the tick ends
        if ratelimit.take_daily('ptr', settings.PTR_DAILY_BUDGET):
            names = resolve_ptr(str(ip), resolve)
            used['ptr'] += 1
        else:
            names, ptr_budget = None, 0
        cursor += 1
        ptr_names = names or []
        live = bool(data and (data['ports'] or data['hostnames'])) or bool(ptr_names)
        if live:
            child, created = _child_ip(asset, ip)
            if child is not None:
                inventory._append_source(child, 'cidr', asset.value)
                child.save(update_fields=['sources'])
                child.mark_missing_or_seen(True)
                _store(child, 'internetdb', data or {'no_data': True}, now)
                if created:
                    used['new'] += 1
                    if enum['pass'] >= 1:  # a range's first sweep is silent
                        events.record_asset_new(asset.project, child, ports=(data or {}).get('ports', ()))
                place_names(asset.project, ptr_names, str(ip), f'ptr:{ip} in {asset.value}')
                place_names(asset.project, (data or {}).get('hostnames', []), str(ip), f'internetdb:{ip} in {asset.value}')
        elif names is not None:  # an unanswered PTR is no evidence of absence
            for child in Asset.objects.filter(parent=asset, kind='ip', value=str(ip), scope_tier__in=OWNED):
                child.mark_missing_or_seen(False)
    finished = cursor >= size
    if finished:
        enum.update(cursor=0, status='done', last_pass_at=_iso(now), **{'pass': enum['pass'] + 1})
    else:
        enum['cursor'] = cursor
    _set(asset, 'enum', enum)
    return used, finished


def enumerate_step(asset, idb_budget, ptr_budget, get=http.get_json, resolve=collect._resolve, now=None):
    """Walk the next addresses of one owned range, at most idb_budget InternetDB and ptr_budget PTR calls."""
    return _step(asset, idb_budget, ptr_budget, get, resolve, now)[0]


# ---- scheduling ----

def _stamp(value):
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def due_ranges(now):
    """Owned asn/cidr rows to work on, running ranges first, then oldest first."""
    due = []
    rows = Asset.objects.filter(kind__in=('asn', 'cidr'), scope_tier__in=OWNED).exclude(state='retired') \
        .exclude(cadence_tier='off').select_related('parent').order_by('id')
    for a in rows:
        if a.parent_id and not (a.parent.scope_tier in OWNED and a.parent.state != 'retired'
                                and a.parent.cadence_tier in CADENCE_INTERVALS):
            continue
        if a.cadence_tier not in CADENCE_INTERVALS:
            continue
        info = (a.enrichment or {}).get('asn' if a.kind == 'asn' else 'enum') or {}
        running = a.kind == 'cidr' and info.get('status', 'running') == 'running'
        if a.kind == 'cidr' and info.get('status') == 'refused':
            continue
        last = _stamp(info.get('refreshed_at') or info.get('checked_at') if a.kind == 'asn' else info.get('last_pass_at'))
        tried = _stamp(info.get('attempted_at')) if a.kind == 'asn' else None
        if tried is not None and tried > now - ASN_RETRY_AFTER:
            continue
        if not running and last is not None and last > now - CADENCE_INTERVALS[a.cadence_tier]:
            continue
        due.append((not running, last or datetime.min.replace(tzinfo=dt_timezone.utc), a.id, a))
    due.sort(key=lambda d: d[:3])
    return [d[3] for d in due]


@app.task(name='enumerate_ranges', bind=False)
def enumerate_ranges():
    """Beat tick: at most one ASN refresh (RIPEstat only), then budgeted range enumeration if opted in.

    Daily budget arithmetic: a tick spends at most per_tick(daily) = ceil(daily * 60 / 86400) calls, i.e. 4
    InternetDB and 7 PTR with the defaults (5000 / 10000 per day); take_daily is the hard daily stop.
    NOTE: a failed ASN lookup is not retried for ASN_RETRY_AFTER (6 h); a flat back-off, not exponential. Upgrade
    path: back off per consecutive failure."""
    if not settings.CONTINUOUS_SCANS:
        return {'reason': 'disabled'}
    with tick_lock('enumerate_ranges') as got:
        return _tick() if got else {'reason': 'locked'}


def _tick():
    now = timezone.now()
    deadline = time.monotonic() + TICK_BUDGET
    last_event = ChangeEvent.objects.order_by('-id').values_list('id', flat=True).first() or 0
    idb_left = ratelimit.per_tick(settings.INTERNETDB_DAILY_BUDGET)
    ptr_left = ratelimit.per_tick(settings.PTR_DAILY_BUDGET)
    out = {'refreshed': 0, 'internetdb': 0, 'ptr': 0, 'new': 0}
    due = due_ranges(now)
    asn = next((a for a in due if a.kind == 'asn'), None)  # RIPEstat only: runs whatever RANGE_ENUMERATION says
    if asn is not None:
        out['refreshed'] = 1
        refresh_asn(asn, get=http.get_json, now=now)
    for a in due if settings.RANGE_ENUMERATION else ():
        if a.kind != 'cidr':
            continue
        if time.monotonic() > deadline:
            break
        if idb_left <= 0 or ptr_left <= 0:
            break
        used, finished = _step(a, idb_left, ptr_left, http.get_json, collect._resolve, now)
        idb_left, ptr_left = idb_left - used['internetdb'], ptr_left - used['ptr']
        for k in used:
            out[k] += used[k]
        if not finished:
            break  # budget spent, a provider failed or take_daily said no: stop for this tick
    for pid in set(ChangeEvent.objects.filter(id__gt=last_event, kind='asset_new').values_list('project_id', flat=True)):
        deliver_immediate(Project.objects.get(pk=pid))  # safe to repeat: each event is claimed once (notified_at)
    return out
