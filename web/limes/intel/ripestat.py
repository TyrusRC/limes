"""RIPEstat network/AS lookups (passive, keyless)."""
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
