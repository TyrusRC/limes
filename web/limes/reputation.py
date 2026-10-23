"""IP reputation of owned IPs, ranges and ASNs against the downloaded feeds (limes.feeds), plus an optional Spamhaus
ZEN lookup over DQS. The checks are provisional (limes.checks.catalogue.PROVISIONAL): issues and alerts, no points.
Lookups read the stored feeds only; the one network call is the opt-in per-IP DQS DNS query.

Feed text (SBL ids, AS names) is hostile data: it is cleaned before it is stored, and the UI escapes it again."""
import bisect
import ipaddress
import logging
import re
import time
from datetime import timedelta

import dns.exception
import dns.resolver
from django.conf import settings
from django.utils import timezone

from limes.checks import collect
from limes.checks.catalogue import CHECKS, Result
from limes.feeds import sources, store
from limes.intel import ratelimit
from startScan.models import Asset, FeedState, RiskCheck

log = logging.getLogger(__name__)

OWNED = ('owned_root', 'owned_host')
STALE = 'feed data older than 3 x its cadence'
DQS_EVERY = timedelta(hours=24)
# NOTE: DQS free tier is far below this; the daily cap and the 5-minute run cap are Limes's own ceilings. Upgrade
# path: per-tick shares via ratelimit.per_tick and a dedicated beat task.
DQS_DAILY_BUDGET = 5000
DQS_RUN_SECONDS = 300
ASN_RE = re.compile(r'AS(\d{1,10})')
KEY_RE = re.compile(r'[A-Za-z0-9_-]{1,63}')
_UNSAFE = re.compile(r'[<>&"\'`\x00-\x1f\x7f]')


def _clean(text, limit=200):
    return _UNSAFE.sub('', str(text))[:limit]


def redact(text, key):
    """text without the DQS key (it is part of every query name, so DNS errors echo it)."""
    return str(text).replace(key, '***') if key else str(text)


class _Nets:
    """Networks of one IP version sorted by first address. `reach[i]` is the largest last address among rows 0..i, so
    a lookup walks left from the bisect point only while something to the left can still reach the query."""

    def __init__(self, rows):
        self.rows = sorted(rows)
        self.firsts = [r[0] for r in self.rows]
        self.reach, top = [], -1
        for r in self.rows:
            top = max(top, r[1])
            self.reach.append(top)

    def hits(self, lo, hi):
        """Rows overlapping [lo, hi]: O(log n + k); overlapping/nested entries are handled by the reach walk."""
        out, j = [], bisect.bisect_right(self.firsts, hi) - 1
        while j >= 0 and self.reach[j] >= lo:
            if self.rows[j][1] >= lo:
                out.append(self.rows[j])
            j -= 1
        return out


class Index:
    """Everything the checks need, built once per run. `stale` is keyed by check id ('rep.listed_drop' for IPv4 and
    'rep.listed_drop6' for IPv6, since they are separate files)."""

    def __init__(self):
        self.drop = {4: _Nets([]), 6: _Nets([])}
        self.asn, self.c2, self.attacker = {}, {}, {}
        self.attacker_feeds = []
        self.stale, self.meta = {}, {}
        self.started = False  # any reputation feed ever attempted; before that there is nothing to report on


def _good(name, states, now, idx):
    """(data) of a fresh feed, else None; records meta and returns None for stale, missing or unreadable data."""
    feed, state = sources.FEEDS[name], states.get(name)
    if store.is_stale(feed, state, now):
        return None
    try:
        loaded = store.load(name)
    except Exception:  # noqa: BLE001 - a corrupt stored file is a missing feed, never a pass
        log.exception('feed %s unreadable', name)
        return None
    if loaded is None:
        return None
    idx.meta[name] = {'source_date': state.source_date, 'fetched_at': state.last_good_at, 'credit': feed.credit}
    return loaded[0]


def index(now):
    """NOTE: the whole index lives in memory per run (DROP ~2k networks, ASN-DROP ~500); IP and range lookups
    bisect. Upgrade path: PostgreSQL inet/cidr columns and GiST."""
    idx = Index()
    states = {s.name: s for s in FeedState.objects.filter(name__in=sources.REPUTATION)}
    idx.started = bool(states)
    for v, name in ((4, 'drop_v4'), (6, 'drop_v6')):
        data = _good(name, states, now, idx)
        idx.stale['rep.listed_drop' + ('6' if v == 6 else '')] = data is None
        rows = []
        for cidr, sbl in data or ():
            net = ipaddress.ip_network(cidr)
            rows.append((int(net.network_address), int(net.broadcast_address), cidr, sbl, name))
        idx.drop[v] = _Nets(rows)
    data = _good('asndrop', states, now, idx)
    idx.stale['rep.listed_asndrop'] = data is None
    idx.asn = dict(data or ())
    data = _good('feodo', states, now, idx)
    idx.stale['rep.listed_c2'] = data is None
    idx.c2 = {ip: 'feodo' for ip in data or ()}
    idx.attacker_feeds = [n for n in ('blocklist_de', 'cins') if sources.enabled(sources.FEEDS[n])]
    stale = False
    for name in idx.attacker_feeds:
        data = _good(name, states, now, idx)
        stale = stale or data is None
        for ip in data or ():
            idx.attacker.setdefault(ip, name)
    idx.stale['rep.listed_attacker'] = stale
    return idx


def _evidence(idx, feed, entry, now):
    m = idx.meta.get(feed) or {}
    when = m.get('source_date')
    fetched = m.get('fetched_at')
    return {'feed': feed, 'entry': _clean(entry), 'listed_at': when.isoformat() if when else None,
            'fetched_at': (fetched or now).isoformat(), 'credit': sources.FEEDS[feed].credit}


def _stale():
    return {'reason': STALE}


def _covering(asset, ip, ranges):
    """The owned range of the asset's project that holds ip, if any."""
    if ranges is None:
        ranges = []
        for v in Asset.objects.filter(project_id=asset.project_id, kind='cidr', scope_tier__in=OWNED) \
                .exclude(state='retired').values_list('value', flat=True):
            try:
                ranges.append(ipaddress.ip_network(v, strict=False))
            except ValueError:
                continue
    return next((n for n in ranges if n.version == ip.version and ip in n), None)


def _ip_results(asset, now, idx, dqs, ranges):
    try:
        ip = ipaddress.ip_address(asset.value)
    except ValueError:
        return []
    out, x = [], int(ip)
    if idx.stale['rep.listed_drop' + ('6' if ip.version == 6 else '')]:
        out.append(Result('rep.listed_drop', 'error', _stale()))
    else:
        hits = idx.drop[ip.version].hits(x, x)
        if not hits:
            out.append(Result('rep.listed_drop', 'pass', {}))
        else:
            cover = _covering(asset, ip, ranges)
            if cover is not None:  # the listing is raised once, on the owned range
                out.append(Result('rep.listed_drop', 'not_applicable', {'covered_by': str(cover)}))
            else:
                _, _, cidr, sbl, feed = hits[0]
                out.append(Result('rep.listed_drop', 'fail', _evidence(idx, feed, f'{cidr} {sbl}', now)))
    ipstr = str(ip)
    if idx.stale['rep.listed_c2']:
        out.append(Result('rep.listed_c2', 'error', _stale()))
    elif ipstr in idx.c2:
        out.append(Result('rep.listed_c2', 'fail', _evidence(idx, idx.c2[ipstr], ipstr, now)))
    else:
        out.append(Result('rep.listed_c2', 'pass', {}))
    if idx.attacker_feeds:
        if ipstr in idx.attacker:
            out.append(Result('rep.listed_attacker', 'fail', _evidence(idx, idx.attacker[ipstr], ipstr, now)))
        elif idx.stale['rep.listed_attacker']:
            out.append(Result('rep.listed_attacker', 'error', _stale()))
        else:
            out.append(Result('rep.listed_attacker', 'pass', {}))
    if dqs is not None:
        state, code = dqs
        if state == 'listed':
            out.append(Result('rep.dnsbl_listed', 'fail', {
                'feed': 'spamhaus_zen', 'entry': _clean(f'{ipstr} {code}'), 'listed_at': None,
                'fetched_at': now.isoformat(), 'credit': 'Spamhaus ZEN (DQS)'}))
        elif state == 'clean':
            out.append(Result('rep.dnsbl_listed', 'pass', {}))
        else:
            out.append(Result('rep.dnsbl_listed', 'error', {'reason': _clean(code or 'error', 80)}))
    return out


def evaluate_asset(asset, now, idx=None, dqs=None, ranges=None):
    """The reputation Results of one ip, cidr or asn asset. `dqs` is a dqs_lookup() tuple; `ranges` the project's
    owned ip_networks (loaded on demand). No network access."""
    idx = idx or index(now)
    if not idx.started:  # the feeds were never downloaded (new install or feeds off): no result, not a verdict
        return []
    if asset.kind == 'ip':
        return _ip_results(asset, now, idx, dqs, ranges)
    if asset.kind == 'cidr':
        try:
            net = ipaddress.ip_network(asset.value, strict=False)
        except ValueError:
            return []
        if idx.stale['rep.listed_drop' + ('6' if net.version == 6 else '')]:
            return [Result('rep.listed_drop', 'error', _stale())]
        hits = idx.drop[net.version].hits(int(net.network_address), int(net.broadcast_address))
        if not hits:
            return [Result('rep.listed_drop', 'pass', {})]
        _, _, cidr, sbl, feed = hits[0]
        return [Result('rep.listed_drop', 'fail', _evidence(idx, feed, f'{cidr} {sbl}', now))]
    if asset.kind == 'asn':
        m = ASN_RE.fullmatch(asset.value)
        if not m:
            return []
        if idx.stale['rep.listed_asndrop']:
            return [Result('rep.listed_asndrop', 'error', _stale())]
        n = int(m.group(1))
        if n in idx.asn:
            return [Result('rep.listed_asndrop', 'fail', _evidence(idx, 'asndrop', f'AS{n} {idx.asn[n]}', now))]
        return [Result('rep.listed_asndrop', 'pass', {})]
    return []


def dqs_lookup(ip, key, resolve=collect._resolve):
    """('listed', code) | ('clean', None) | ('error', reason) for ip in Spamhaus ZEN over DQS. The key is part of the
    query name, so it never reaches a log line or a returned reason unredacted."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return 'error', 'invalid ip'
    if addr.version != 4:
        # NOTE: ZEN over DQS for IPv6 uses nibble format. Upgrade path: build the nibble name here.
        return 'error', 'ipv6 not supported'
    if not KEY_RE.fullmatch(key or ''):
        return 'error', 'invalid DQS key'
    name = '.'.join(reversed(str(addr).split('.'))) + f'.{key}.zen.dq.spamhaus.net'
    try:
        answers = resolve(name, 'A')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return 'clean', None
    except dns.exception.DNSException as e:
        log.warning('DQS lookup failed: %s: %s', type(e).__name__, redact(e, key))
        return 'error', type(e).__name__
    for a in answers:
        if a.startswith('127.255.255.'):  # 254: open resolver refused, 255: bad query/key
            return 'error', a
    for a in answers:
        if re.fullmatch(r'127\.0\.0\.\d{1,3}', a):
            return 'listed', a
    return 'error', 'unexpected answer'


def _dqs_due(last, now):
    return last is None or last <= now - DQS_EVERY


def evaluate_reputation(now=None):
    """Check every owned, non-retired ip/cidr/asn of every project against one index, write the rows, then sync
    issues and deliver. Returns {'checked', 'projects'}."""
    from dashboard.stats import invalidate
    from limes.alerts.deliver import deliver_immediate
    from limes.alerts.issues import sync_issues
    from limes.checks.run import _write
    now = now or timezone.now()
    idx = index(now)
    key = settings.SPAMHAUS_DQS_KEY
    started, dqs_on = time.monotonic(), bool(key)
    by_project = {}
    for a in Asset.objects.filter(kind__in=('ip', 'cidr', 'asn'), scope_tier__in=OWNED).exclude(state='retired') \
            .select_related('project').order_by('project_id', 'id'):
        by_project.setdefault(a.project, []).append(a)
    checked = 0
    for project, assets in by_project.items():
        ranges = []
        for a in assets:
            if a.kind == 'cidr':
                try:
                    ranges.append(ipaddress.ip_network(a.value, strict=False))
                except ValueError:
                    pass
        last_dqs = dict(RiskCheck.objects.filter(asset__in=[a for a in assets if a.kind == 'ip'], check_id='rep.dnsbl_listed')
                        .values_list('asset_id', 'last_checked'))
        try:
            for a in assets:
                dqs = None
                if dqs_on and a.kind == 'ip' and _dqs_due(last_dqs.get(a.id), now):
                    if time.monotonic() - started > DQS_RUN_SECONDS or not _global(a.value):
                        pass
                    elif not ratelimit.take_daily('dqs', DQS_DAILY_BUDGET):
                        dqs_on = False  # budget spent (or cache down): no more lookups this run
                    else:
                        dqs = dqs_lookup(a.value, key)
                try:
                    _write(a, evaluate_asset(a, now, idx, dqs, ranges), now)
                    checked += 1
                except Exception:  # noqa: BLE001 - one bad asset must not stop the project
                    log.exception('reputation check failed for %s', a.value)
            for job in (sync_issues, deliver_immediate):
                job(project)
            invalidate(project.id)
        except Exception:  # noqa: BLE001 - other projects still run
            log.exception('reputation evaluation failed for project %s', project.id)
    return {'checked': checked, 'projects': len(by_project)}


def _global(value):
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False
