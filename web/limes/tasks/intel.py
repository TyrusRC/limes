"""Passive providers against one owned root. Contacts only crt.sh, InternetDB and RIPEstat."""
import logging
from datetime import datetime, timedelta

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
FRESH_FOR = timedelta(hours=24)


def _owned_registrables(project):
    return {domains.registrable(v) or v for v in inventory.owned_root_values(project)}


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
    asset.enrichment = {**(asset.enrichment or {}), key: {**data, 'fetched_at': now.isoformat()}}
    asset.save(update_fields=['enrichment'])


def run_crtsh(project, root, get=http.get_json):
    status, rows = get(crtsh.build_url(root.value), provider='crtsh')
    certs = crtsh.parse(rows) if status == 200 else []
    owned = _owned_registrables(project)
    hostnames = candidates = capped = seen = 0
    for cert in certs:
        for name in cert['names']:
            if seen >= MAX_NAMES_PER_ROOT:
                break
            if name.endswith('.' + root.value):
                inventory.upsert_hostname_asset(project, name, parent=root, source='crtsh',
                                                evidence=f'cert:{cert["id"]}')
                hostnames += 1
                seen += 1
        regs = {r for r in (domains.registrable(n) for n in cert['names']) if r}
        if len(regs) > SHARED_CERT_LIMIT:
            continue
        in_root = next((n for n in cert['names'] if n == root.value or n.endswith('.' + root.value)), None)
        if not in_root:
            continue
        for reg in sorted(regs - owned):
            if candidates >= MAX_CANDIDATES_PER_ROOT:
                capped += 1
                continue
            inventory.upsert_candidate(project, 'root_domain', reg, 'crtsh',
                                       f'cert:{cert["id"]} ({in_root}) shared with {root.value}')
            candidates += 1
    return {'hostnames': hostnames, 'candidates': candidates, 'candidates_capped': capped}


def run_internetdb(project, root, get=http.get_json, now=None):
    now = now or timezone.now()
    owned = _owned_registrables(project)
    enriched = candidates = 0
    for ip in _root_ips(project, root):
        if _fresh(ip, 'internetdb', now):
            continue
        status, body = get(internetdb.build_url(ip.value), provider='internetdb')
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
                if reg and reg not in owned:
                    inventory.upsert_candidate(project, 'root_domain', reg, 'internetdb', f'ip:{ip.value}')
                    candidates += 1
    return {'internetdb_enriched': enriched, 'candidates': candidates}


def run_ripestat(project, root, get=http.get_json, now=None):
    now = now or timezone.now()
    holders, enriched = {}, 0
    for ip in _root_ips(project, root):
        if _fresh(ip, 'ripestat', now):
            continue
        status, body = get(ripestat.network_info_url(ip.value), provider='ripestat')
        if status != 200:
            continue
        info = ripestat.parse_network_info(body)
        if info['asn'] and info['asn'] not in holders:
            s, b = get(ripestat.as_overview_url(info['asn']), provider='ripestat')
            holders[info['asn']] = ripestat.parse_as_overview(b)['holder'] if s == 200 else None
        _store(ip, 'ripestat', {**info, 'holder': holders.get(info['asn'])}, now)
        enriched += 1
    return {'ripestat_enriched': enriched}
