"""Ownership attribution (A3c): evidence collection, scoring and decisions for candidates.

DNS lookups go to resolvers only, never to a target.
"""
import logging
import os

from celery.exceptions import SoftTimeLimitExceeded

from limes import commands
from limes.pipeline import dnsx
from limes.tasks import inventory
from startScan.models import Asset, AssetFact

logger = logging.getLogger(__name__)

MAX_DNS_CANDIDATES = 2000  # NOTE: ceiling per run; oldest candidates first; upgrade path: rotate by last check
NS_MX_TIMEOUT = 10 * 60


def collect_dns(project, results_dir, run=commands.run):
    """NS/MX/A for candidate root domains. NS facts are kept only when the zone resolved (a working
    delegation); each answered host's NS/MX facts are replaced by the latest answer."""
    cands = dict(Asset.objects.filter(project=project, kind='root_domain', scope_tier='candidate')
                 .order_by('id').values_list('value', 'id')[:MAX_DNS_CANDIDATES])
    if not cands:
        return {'dns_checked': 0}
    hosts_file = os.path.join(results_dir, 'attribution_hosts.txt')
    out_file = os.path.join(results_dir, 'attribution_dnsx.jsonl')
    try:
        if os.path.exists(out_file):
            os.remove(out_file)
        with open(hosts_file, 'w') as f:
            f.write('\n'.join(cands) + '\n')
        res = run(dnsx.build_ns_mx_argv(hosts_file, out_file), timeout=NS_MX_TIMEOUT)
        if res is None or res.return_code != 0:
            logger.warning(f'dnsx (ns/mx) exited with {getattr(res, "return_code", None)}')
        if not os.path.isfile(out_file):
            return {'dns_checked': 0}
        with open(out_file) as f:
            records = dnsx.parse_ns_mx(f)
        checked = 0
        for name, rec in records.items():
            asset_id = cands.get(name)
            if asset_id is None:
                continue
            asset = Asset.objects.get(pk=asset_id)
            ns = rec['ns'] if rec['a'] else []  # lame delegation proves nothing
            AssetFact.objects.filter(asset=asset, kind='ns').exclude(value__in=ns).delete()
            AssetFact.objects.filter(asset=asset, kind='mx').exclude(value__in=rec['mx']).delete()
            for h in ns:
                inventory.record_fact(asset, 'ns', h, 'dns')
            for h in rec['mx']:
                inventory.record_fact(asset, 'mx', h, 'dns')
            for ip in rec['a']:
                inventory.record_fact(asset, 'ip', ip, 'dns')
            checked += 1
        return {'dns_checked': checked}
    except SoftTimeLimitExceeded:
        raise
    except Exception:
        logger.exception('Attribution DNS collection failed')
        return {'dns_checked': 0}
