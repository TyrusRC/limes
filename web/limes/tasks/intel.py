"""Passive providers against one owned root. Contacts only crt.sh, InternetDB and RIPEstat."""
import logging
from datetime import datetime, timedelta

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from limes.intel import crtsh, domains, http, internetdb, ripestat
from limes.tasks import inventory
from startScan.models import Asset, IpAddress

logger = logging.getLogger(__name__)

SHARED_CERT_LIMIT = 20      # certificates listing more registrable domains are not ownership evidence
MAX_NAMES_PER_ROOT = 10000  # NOTE: ceiling per root per run; upgrade path: paginate/stream crt.sh
# NOTE: ceiling of new co-tenant candidates per root per run. Co-tenant SANs are influenced by whoever
# controls a name under the root; a large legitimate set is surfaced over several runs.
MAX_CANDIDATES_PER_ROOT = 100
MAX_CONSECUTIVE_FAILURES = 3  # provider unreachable: stop calling it for the rest of the run
FRESH_FOR = timedelta(hours=24)


def _is_owned(domain, owned):
    return any(domain == r or domain.endswith('.' + r) for r in owned)


def _root_ips(project, root):
    addrs = (IpAddress.objects.filter(Q(assets=root) | Q(assets__parent=root, assets__kind='hostname'))
             .values_list('address', flat=True).distinct())
    return list(Asset.objects.filter(project=project, kind='ip', value__in=list(addrs)))


def _fresh(asset, key, now):
    ts = ((asset.enrichment or {}).get(key) or {}).get('fetched_at')
    try:
        return bool(ts) and now - datetime.fromisoformat(ts) < FRESH_FOR
    except (TypeError, ValueError):
        return False


def _store(asset, key, data, now):
    """Write one enrichment key, merged into the row as stored now (locked), so a concurrent write of another key
    (a cadence set by the user, the monitor's status) is never lost to this caller's stale copy."""
    with transaction.atomic():
        row = Asset.objects.select_for_update().only('enrichment').get(pk=asset.pk)
        row.enrichment = {**(row.enrichment or {}), key: {**data, 'fetched_at': now.isoformat()}}
        row.save(update_fields=['enrichment'])
    asset.enrichment = row.enrichment


def cotenant_candidates(project, root, cert_ref, names, owned, known, allow, source, exclude=frozenset(), done=None):
    """Registrable domains sharing one certificate with `root` become candidates (evidence only: never owned).
    `allow()` is asked once per brand-new candidate and refuses past the caller's allowance; `done` (the caller's
    run-wide set) keeps a domain to one upsert per run; `exclude` holds registrable domains never to suggest.
    Returns (new, capped).
    NOTE: evidence writes for known domains are bounded only by certificates x SHARED_CERT_LIMIT;
    upgrade path: skip the write when that (source, evidence) pair is already recorded."""
    done = set() if done is None else done
    regs = {r for r in (domains.registrable(n) for n in names) if r}
    if len(regs) > SHARED_CERT_LIMIT:
        return 0, 0
    in_root = next((n for n in names if n == root.value or n.endswith('.' + root.value)), None)
    if not in_root:
        return 0, 0
    inventory.record_fact(root, 'cert', cert_ref, source)
    new = capped = 0
    for reg in sorted(regs - done - set(exclude)):
        if _is_owned(reg, owned):
            continue
        done.add(reg)
        is_new = reg not in known
        if is_new and not allow():
            capped += 1
            continue
        cand = inventory.upsert_candidate(project, 'root_domain', reg, source,
                                          f'cert:{cert_ref} ({in_root}) shared with {root.value}')
        if cand:
            inventory.record_fact(cand, 'cert', cert_ref, source)
        new += is_new
    return new, capped


def run_crtsh(project, root, get=http.get_json):
    status, rows = get(crtsh.build_url(root.value), provider='crtsh')
    certs = crtsh.parse(rows) if status == 200 else []
    owned = inventory.owned_root_values(project)
    # distinct in-root names -> first certificate that listed them
    names = {}
    for cert in certs:
        for name in cert['names']:
            if name.endswith('.' + root.value) and name not in names and len(names) < MAX_NAMES_PER_ROOT:
                names[name] = cert['id']
    existing = set(Asset.objects.filter(project=project, kind='hostname', parent=root)
                   .values_list('value', flat=True))
    hostnames = 0
    for name, cert_id in names.items():
        inventory.upsert_hostname_asset(project, name, parent=root, source='crtsh', evidence=f'cert:{cert_id}')
        hostnames += name not in existing
    # Domains already in the inventory (candidate, rejected, ...) get evidence but never use up
    # the cap, so a large co-tenancy set surfaces over successive runs.
    known = set(Asset.objects.filter(project=project, kind='root_domain').values_list('value', flat=True))
    used, done = [0], set()

    def allow():
        used[0] += 1
        return used[0] <= MAX_CANDIDATES_PER_ROOT

    candidates = capped = 0
    for cert in certs:
        n, c = cotenant_candidates(project, root, str(cert['id']), cert['names'], owned, known, allow, 'crtsh',
                                   done=done)
        candidates, capped = candidates + n, capped + c
    from limes.ct import ingest  # lazy: ingest imports this module
    ingest.seed_issuers(root, crtsh.issuers(rows) if status == 200 else set(), timezone.now())
    return {'hostnames': hostnames, 'candidates': candidates, 'candidates_capped': capped}


def run_internetdb(project, root, get=http.get_json, now=None):
    now = now or timezone.now()
    owned = inventory.owned_root_values(project)
    enriched = candidates = down = 0
    aborted = {}
    for ip in _root_ips(project, root):
        if _fresh(ip, 'internetdb', now):
            continue
        status, body = get(internetdb.build_url(ip.value), provider='internetdb')
        down = down + 1 if status is None else 0
        if down >= MAX_CONSECUTIVE_FAILURES:
            aborted = {'internetdb_aborted': 1}
            break
        if status == 404:
            data = None
        elif status == 200:
            data = internetdb.parse(body)
        else:
            continue  # provider failure: not cached, retried next run
        _store(ip, 'internetdb', data or {'no_data': True}, now)
        enriched += 1
        if data and ip.scope_tier in ('owned_root', 'owned_host'):
            for host in data['hostnames']:
                reg = domains.registrable(host)
                if reg and not _is_owned(reg, owned):
                    cand = inventory.upsert_candidate(project, 'root_domain', reg, 'internetdb', f'ip:{ip.value}')
                    if cand:
                        inventory.record_fact(cand, 'ip', ip.value, 'internetdb')
                    candidates += 1
    return {'internetdb_enriched': enriched, 'candidates': candidates, **aborted}


def run_ripestat(project, root, get=http.get_json, now=None):
    now = now or timezone.now()
    holders, enriched, down = {}, 0, 0
    aborted = {}
    for ip in _root_ips(project, root):
        if _fresh(ip, 'ripestat', now):
            continue
        status, body = get(ripestat.network_info_url(ip.value), provider='ripestat')
        down = down + 1 if status is None else 0
        if down >= MAX_CONSECUTIVE_FAILURES:
            aborted = {'ripestat_aborted': 1}
            break
        if status != 200:
            continue
        info = ripestat.parse_network_info(body)
        if info['asn'] and info['asn'] not in holders:
            s, b = get(ripestat.as_overview_url(info['asn']), provider='ripestat')
            if s == 200:
                holders[info['asn']] = ripestat.parse_as_overview(b)['holder']  # a failed lookup is retried
        _store(ip, 'ripestat', {**info, 'holder': holders.get(info['asn'])}, now)
        enriched += 1
    return {'ripestat_enriched': enriched, **aborted}
