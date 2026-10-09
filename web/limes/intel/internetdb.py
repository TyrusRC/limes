"""Shodan InternetDB per-IP lookup (passive, keyless; non-commercial terms)."""
from urllib.parse import quote


def build_url(ip):
    return f'https://internetdb.shodan.io/{quote(ip)}'


def _strs(value):
    return [v for v in (value if isinstance(value, list) else []) if isinstance(v, str)]


def parse(obj):
    """None when InternetDB has no data (404 body) or the body is not an IP record."""
    if not isinstance(obj, dict) or 'ip' not in obj:
        return None
    ports = sorted({p for p in (obj.get('ports') if isinstance(obj.get('ports'), list) else [])
                    if isinstance(p, int) and not isinstance(p, bool)})
    hostnames = []
    for h in _strs(obj.get('hostnames')):
        h = h.strip().lower().rstrip('.')
        if h and h not in hostnames:
            hostnames.append(h)
    return {'ports': ports, 'cpes': _strs(obj.get('cpes')), 'vulns': _strs(obj.get('vulns')),
            'tags': _strs(obj.get('tags')), 'hostnames': hostnames}
