"""Certificate ingestion: one CT log record -> sightings, new hostnames, queued checks and coalesced events.
Records come from the public log, so every field is untrusted: the schema is checked, names are normalised and matched
by exact suffix lookup (limes.ct.match), and nothing from a record reaches a log line or an event unsanitised."""
import json
import logging
import re
from datetime import datetime, timedelta, timezone as dt_tz

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django_redis import get_redis_connection
from redis.exceptions import RedisError

from celery.exceptions import SoftTimeLimitExceeded
from dashboard.models import Project
from limes import event_queue
from limes.alerts import events
from limes.ct import lookalikes, match
from limes.intel import domains
from limes.tasks import intel, inventory
from startScan.models import Asset, ChangeEvent, CertSighting

logger = logging.getLogger(__name__)

SPOOL_MAX_BYTES = 512 * 1024
ISSUER_HISTORY = timedelta(days=365)
ISSUER_BASELINE = timedelta(days=30)
ISSUER_MAX = 50  # NOTE: the issuer history keeps ISSUER_MAX organisations per root. Upgrade path: a per-root issuer table if CA churn ever exceeds it.
# NOTE: one certificate creates at most STORED_NAMES new hostnames per project, so a SAN-stuffed certificate under a
# dangling subdomain cannot flood the inventory. Upgrade path: spill the rest to a candidate list.
LAT_MAX = 1000
_HEX64 = re.compile(r'[0-9a-f]{64}')
_CONTROL = re.compile(r'[\x00-\x1f\x7f-\x9f  ]')
_ORGS_KEY = 'ct_issuers'


_CHAT = str.maketrans({'<': '\u2039', '>': '\u203a', '@': '\uff20', '[': '(', ']': ')', '`': "'"})


def _chat_safe(v, limit):
    """Text bound for event titles, which reach chat: no mention, link or markup syntax survives."""
    return _text(v, limit).translate(_CHAT)


def _text(v, limit):
    return _CONTROL.sub(' ', v)[:limit] if isinstance(v, str) else ''


def _when(v):
    if not isinstance(v, str):
        return None
    try:
        t = parse_datetime(v)
        if t is not None and timezone.is_naive(t):
            t = t.replace(tzinfo=dt_tz.utc)
        return t.astimezone(dt_tz.utc) if t is not None else None
    except (ValueError, OverflowError):
        return None


def parse_record(raw):
    """The checked record dict, or None when the bytes are not a well-formed spool record."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > SPOOL_MAX_BYTES:
        return None
    try:
        r = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    if not isinstance(r, dict):
        return None
    tbs, names = r.get('tbs_sha256'), r.get('dns_names')
    if not isinstance(tbs, str) or not _HEX64.fullmatch(tbs):
        return None
    if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
        return None
    cert = r.get('cert_sha256')
    idx = r.get('entry_index')
    return {'tbs_sha256': tbs,
            'cert_sha256': cert if isinstance(cert, str) and _HEX64.fullmatch(cert) else None,
            'dns_names': names, 'names_total': len(names),
            'issuer_dn': _text(r.get('issuer_dn'), 500),
            'not_before': _when(r.get('not_before')), 'not_after': _when(r.get('not_after')),
            'log_uri': _text(r.get('log_uri'), 500),
            'entry_index': idx if isinstance(idx, int) and not isinstance(idx, bool) and 0 <= idx < 2 ** 63 else None}


def load_index():
    """The match index in three queries at most (assets, plus the optional lookalike watchlist)."""
    rows = (Asset.objects.filter(scope_tier__in=('owned_root', 'owned_host'), kind__in=('root_domain', 'hostname'))
            .exclude(cadence_tier='off').exclude(state='retired')
            .values_list('project_id', 'id', 'kind', 'scope_tier', 'value'))
    roots, hosts = {}, {}
    root_sets = {}
    rest = []
    for pid, aid, kind, tier, value in rows:
        if kind == 'root_domain' and tier == 'owned_root' and domains.registrable(value):  # not a public suffix itself
            roots.setdefault(value, []).append((pid, aid))
            root_sets.setdefault(pid, set()).add(value)
        elif tier == 'owned_host':
            rest.append((pid, aid, value))
    for pid, aid, value in rest:
        if not any(s in root_sets.get(pid, ()) for s in match._suffixes(value)):
            hosts.setdefault(value, []).append((pid, aid))
    look = {}
    for pid, dom in lookalikes.watched():
        if pid not in look.setdefault(dom, []):
            look[dom].append(pid)
    return match.Index(roots, hosts, look)


# --- issuer history ---------------------------------------------------------------------------------------------

def _iso(v):
    try:
        return datetime.fromisoformat(v)
    except (TypeError, ValueError):
        return None


def _write_issuers(root, now, change):
    """Apply `change(data) -> result` to root.enrichment['ct_issuers'] as stored now (locked)."""
    with transaction.atomic():
        row = Asset.objects.select_for_update().only('enrichment').get(pk=root.pk)
        enrichment = dict(row.enrichment or {})
        data = enrichment.get(_ORGS_KEY)
        data = data if isinstance(data, dict) else {}
        orgs = data.get('orgs') if isinstance(data.get('orgs'), dict) else {}
        data = {'orgs': dict(orgs), 'since': data.get('since') or now.isoformat(), 'seeded': bool(data.get('seeded'))}
        result = change(data)
        data['orgs'] = dict(sorted(data['orgs'].items(), key=lambda kv: kv[1])[-ISSUER_MAX:])
        enrichment[_ORGS_KEY] = data
        row.enrichment = enrichment
        row.save(update_fields=['enrichment'])
    root.enrichment = row.enrichment
    return result


def note_issuer(root, org_key, now):
    """Record that `org_key` issued for the root; True when that is a new issuer worth interrupting for."""
    def change(data):
        since = _iso(data['since'])
        baselined = data['seeded'] or (since is not None and since <= now - ISSUER_BASELINE)
        last = _iso(data['orgs'].get(org_key)) if org_key else None
        new = bool(org_key) and baselined and (last is None or last < now - ISSUER_HISTORY)
        if org_key:
            data['orgs'][org_key] = now.isoformat()
        return new
    return _write_issuers(root, now, change)


def seed_issuers(root, orgs, now, complete=True):
    """Learn the issuers crt.sh lists for still-valid certificates (about a year of history) and baseline the root.
    Nothing is learned from an empty answer: a failed fetch must not mark the root baselined. A partial answer
    (`complete` False: the response hit the row cap) extends the history silently and leaves the root unbaselined,
    so the next run can finish the job."""
    keys = {k for k in (o.casefold() for o in orgs if isinstance(o, str)) if k}
    if not keys:
        return

    def change(data):
        for k in keys:
            data['orgs'][k] = now.isoformat()
        data['seeded'] = data['seeded'] or bool(complete)
    _write_issuers(root, now, change)


# --- events -----------------------------------------------------------------------------------------------------

def record_cert_event(project, asset, names, immediate, issuer, now):
    """One cert_new row per asset and kind of urgency per CT_EVENT_WINDOW; later certificates count into it.
    A row already sent (notified or digested) is never folded into: later certificates start a new row, and an
    immediate row is per issuer, so a second rogue CA alerts on its own.
    NOTE: the lock covers an existing row only, so two first certificates racing can both insert one. Root-anchored
    events are serialised by note_issuer's root-row lock; only host-only projects can race. Upgrade path: lock the
    project row."""
    names = [n for n in names if isinstance(n, str)]
    issuer = _chat_safe(issuer, 200)
    with transaction.atomic():
        rows = (ChangeEvent.objects.select_for_update()
                .filter(kind='cert_new', project=project, asset=asset, immediate=immediate,
                        notified_at__isnull=True, digested_at__isnull=True,
                        created_at__gte=now - timedelta(seconds=settings.CT_EVENT_WINDOW)))
        if immediate:
            rows = rows.filter(detail__issuer=issuer)
        row = rows.order_by('-created_at').first()
        if row is not None:
            detail = dict(row.detail or {})
            detail['count'] = int(detail.get('count') or 1) + 1
            detail['names'] = sorted(set(detail.get('names') or []) | set(names))[:match.SAMPLE_NAMES]
            row.detail = detail
            row.save(update_fields=['detail'])
            return row
        title = f'New certificate for {asset.value}' + (f' from a new issuer ({issuer[:80]})' if immediate else '')
        return events.safe_record(project, 'cert_new', title, asset=asset, key=events.NEW_ISSUER_KEY if immediate else None,
                                  detail={'count': 1, 'names': sorted(set(names))[:match.SAMPLE_NAMES],
                                          'issuer': issuer})


# --- latency ----------------------------------------------------------------------------------------------------

def _push(prefix, seconds, now):
    if seconds < 0:
        seconds = 0
        event_queue.count('skew', now=now)
    try:
        r = get_redis_connection('default')
        key = f'{prefix}:{now.astimezone(dt_tz.utc):%Y%m%d}'
        pipe = r.pipeline()
        pipe.lpush(key, seconds)
        pipe.ltrim(key, 0, LAT_MAX - 1)
        pipe.expire(key, event_queue.DAY_TTL)
        pipe.execute()
    except RedisError as e:
        logger.warning('ct latency: redis error %s', type(e).__name__)


def _once(key, ttl):
    """True the first time `key` is seen within ttl; fails closed (False) when Redis is down."""
    try:
        return bool(get_redis_connection('default').set(key, 1, nx=True, ex=ttl))
    except RedisError:
        return False


# --- ingest -----------------------------------------------------------------------------------------------------

def _cand_allow(root_id, now):
    key = f'limes:ct:cand:{root_id}:{now.astimezone(dt_tz.utc):%Y%m%d%H}'

    def allow():
        try:
            r = get_redis_connection('default')
            pipe = r.pipeline()
            pipe.incr(key)
            pipe.expire(key, 3600)
            return pipe.execute()[0] <= intel.MAX_CANDIDATES_PER_ROOT
        except RedisError:
            return False  # fail closed: no new candidates while the allowance cannot be counted
    return allow


def _host_allow(project_id, now):
    """One new owned hostname from certificates, within the project's hourly allowance (fails closed)."""
    key = f'limes:ct:host:{project_id}:{now.astimezone(dt_tz.utc):%Y%m%d%H}'
    try:
        pipe = get_redis_connection('default').pipeline()
        pipe.incr(key)
        pipe.expire(key, 3600)
        return pipe.execute()[0] <= settings.CT_NEW_HOSTS_PER_HOUR
    except RedisError:
        return False


def _shown(name, wildcard):
    return f'*.{name}' if wildcard else name


def _project(project_id, pm, record, source, index, now, silent, api_ok=False):
    """One project's share of a certificate. True when a sighting was created."""
    project = Project.objects.filter(pk=project_id).first()
    if project is None:
        return False
    tbs = record['tbs_sha256']
    roots = {a.id: a for a in Asset.objects.filter(pk__in={rid for _, _, rid in pm.owned})}
    ours = [o for o in pm.owned if o[2] in roots]
    shown = [_shown(n, w) for n, w, _ in ours] + [n for n, _ in pm.hosts]
    if not shown:
        return False
    org = match.issuer_org(record['issuer_dn'])
    queue = []
    with transaction.atomic():
        sighting, created = CertSighting.objects.get_or_create(
            project=project, tbs_sha256=tbs,
            defaults={'cert_sha256': record['cert_sha256'], 'names': shown[:match.STORED_NAMES],
                      'other_names': max(0, record['names_total'] - len(shown[:match.STORED_NAMES])),
                      'wildcard': any(w for _, w, _ in ours), 'issuer': _text(record['issuer_dn'], 500),
                      'not_before': record['not_before'], 'not_after': record['not_after'],
                      'log_uri': _text(record['log_uri'], 500), 'entry_index': record['entry_index'], 'source': source,
                      'first_seen_at': now, 'watch_seen_at': now if source == 'certspotter' else None,
                      'api_while_watch_ok': bool(api_ok) and source == 'certspotter_api'})
        if not created:
            if source == 'certspotter' and sighting.watch_seen_at is None:
                CertSighting.objects.filter(pk=sighting.pk).update(watch_seen_at=now)
            return False
        label = 'ct' if source == 'certspotter' else source
        # sorted: watcher and poller lock rows in the same order, so they cannot deadlock on each other
        names = sorted({(n, rid) for n, w, rid in ours if not w and n != roots[rid].value})[:match.STORED_NAMES]
        have = {a.value: a for a in Asset.objects.filter(project=project, kind='hostname',
                                                          value__in=[n for n, _ in names])}
        first = None
        for name, rid in names:
            a = have.get(name)
            if a is None:
                if not _host_allow(project.id, now):  # over the hourly allowance: suggest it, never own it
                    inventory.upsert_candidate(project, 'hostname', name, label, f'cert:{tbs[:16]}')
                    continue
                a = inventory.upsert_hostname_asset(project, name, parent=roots[rid], source=label,
                                                    evidence=f'cert:{tbs[:16]}')
                reason = 'ct_new'
            else:
                reason = 'ct_cert'
            if a is not None:
                queue.append((a, reason))
                first = first or a
        host_assets = {a.id: a for a in Asset.objects.filter(pk__in=[aid for _, aid in pm.hosts])}
        for _, aid in pm.hosts:
            if aid in host_assets:
                queue.append((host_assets[aid], 'ct_cert'))
        by_root = {}
        for n, w, rid in ours:
            by_root.setdefault(rid, []).append(_shown(n, w))
        anchor = first or (roots[min(by_root)] if by_root else None) or (queue[0][0] if queue else None)
        if anchor is not None:
            sighting.asset = anchor
            sighting.save(update_fields=['asset'])
        for asset, reason in queue:
            transaction.on_commit(lambda a=asset, r=reason: event_queue.enqueue(a, r))
        for rid in sorted(by_root):  # every root the certificate covers, in a fixed order
            if pm.others:
                _cotenants(project, roots[rid], tbs, [o for o in ours if o[2] == rid], pm.others, index, now)
        if not silent and by_root:
            for rid in sorted(by_root):
                _announce(project, roots[rid], True, by_root[rid], org, now)
        elif not silent and anchor is not None:
            _announce(project, anchor, False, shown, org, now)
    return True


def _cotenants(project, root, tbs, ours, others, index, now):
    watched = {d for d, pids in index.lookalikes.items() if project.id in pids}
    exclude = watched | {r for r in (domains.registrable(d) for d in watched) if r}
    regs = {r for r in (domains.registrable(n) for n in others) if r}
    known = set(Asset.objects.filter(project=project, kind='root_domain', value__in=regs).values_list('value', flat=True))
    intel.cotenant_candidates(project, root, tbs[:16], [n for n, _, _ in ours] + others,
                              inventory.owned_root_values(project), known, _cand_allow(root.id, now), 'ct',
                              exclude=exclude)


def _announce(project, asset, has_root, names, org, now):
    try:
        with transaction.atomic():
            immediate = note_issuer(asset, org.casefold(), now) if has_root else False
            if immediate:
                record_cert_event(project, asset, names, True, org, now)
            record_cert_event(project, asset, names, False, org, now)
        logger.info('ct: certificate for project %s (issuer %r, immediate %s)', project.id, org, immediate)
    except SoftTimeLimitExceeded:
        raise
    except Exception:
        logger.exception('Could not record certificate event')


def ingest(record, source, index, now, seen_at=None, silent=False, api_ok=False):
    """Apply one checked record (parse_record) to every project it matches. Returns the ids of the projects where a
    sighting was created; a certificate already seen is a no-op (it only stamps `watch_seen_at`)."""
    matches, _dropped = match.classify(record['dns_names'], index)
    touched = set()
    for pid, pm in matches.items():
        if _project(pid, pm, record, source, index, now, silent, api_ok):
            touched.add(pid)
        for dom in pm.lookalikes:
            if _once(f'limes:ct:look:{pid}:{dom}:{record["tbs_sha256"]}', 86400):
                lookalikes.record_sighting(pid, dom, now)
    if touched:
        if seen_at is not None:
            _push('limes:ct:lat', now.timestamp() - seen_at, now)
        if record['not_before'] is not None:
            _push('limes:ct:age', (now - record['not_before']).total_seconds(), now)
    return touched
