"""RIPEstat network/AS lookups (passive, keyless)."""
import ipaddress
from urllib.parse import quote

BASE = 'https://stat.ripe.net/data'


def network_info_url(ip):
    return f'{BASE}/network-info/data.json?resource={quote(ip)}&sourceapp=limes'


def as_overview_url(asn):
    return f'{BASE}/as-overview/data.json?resource=AS{quote(str(asn))}&sourceapp=limes'


def _data(obj):
    data = obj.get('data') if isinstance(obj, dict) else None
    return data if isinstance(data, dict) else {}


def parse_network_info(obj):
    data = _data(obj)
    asns = data.get('asns') if isinstance(data.get('asns'), list) else []
    asn = str(asns[0]) if asns and isinstance(asns[0], (str, int)) and not isinstance(asns[0], bool) else None
    prefix = data.get('prefix') if isinstance(data.get('prefix'), str) else None
    return {'asn': asn, 'prefix': prefix}


def parse_as_overview(obj):
    holder = _data(obj).get('holder')
    return {'holder': holder if isinstance(holder, str) else None}


def announced_prefixes_url(asn):
    n = str(asn).strip().upper()
    n = n[2:] if n.startswith('AS') else n
    return f'{BASE}/announced-prefixes/data.json?resource=AS{quote(n)}&sourceapp=limes'


def parse_announced_prefixes(obj):
    """Canonical, deduplicated network strings in answer order; anything that is not a prefix is dropped."""
    rows = _data(obj).get('prefixes')
    out = []
    for row in rows if isinstance(rows, list) else []:
        raw = row.get('prefix') if isinstance(row, dict) else None
        try:
            net = str(ipaddress.ip_network(raw, strict=False)) if isinstance(raw, str) else None
        except ValueError:
            net = None
        if net and net not in out:
            out.append(net)
    return out
