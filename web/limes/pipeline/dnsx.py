"""ProjectDiscovery dnsx integration: resolve A/AAAA/CNAME for a host list."""
import ipaddress
import json

from startScan.inventory_migrate import normalize_host


def build_argv(hosts_file, output_file):
    return ['dnsx', '-l', hosts_file, '-a', '-aaaa', '-cname', '-resp', '-json', '-silent', '-o', output_file]


def _canonical_ip(value, version):
    if not isinstance(value, str) or '%' in value:
        return None
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    return str(ip) if ip.version == version else None


def _as_list(value):
    return value if isinstance(value, list) else []


def parse(lines):
    out = {}
    for line in lines:
        try:
            rec = json.loads(line)
        except (TypeError, ValueError):
            continue
        if not isinstance(rec, dict):
            continue
        host = normalize_host(rec.get('host') if isinstance(rec.get('host'), str) else '')
        if not host:
            continue
        entry = out.setdefault(host, {'a': [], 'aaaa': [], 'cname': []})
        for key, version in (('a', 4), ('aaaa', 6)):
            for v in _as_list(rec.get(key)):
                ip = _canonical_ip(v, version)
                if ip and ip not in entry[key]:
                    entry[key].append(ip)
        for v in _as_list(rec.get('cname')):
            c = normalize_host(v) if isinstance(v, str) else ''
            if c and c not in entry['cname']:
                entry['cname'].append(c)
    return out


def build_ns_mx_argv(hosts_file, output_file):
    """A is requested too: an NS delegation only proves control when the zone actually resolves."""
    return ['dnsx', '-l', hosts_file, '-a', '-ns', '-mx', '-resp', '-json', '-silent', '-o', output_file]


def _hostnames(values):
    out = []
    for v in _as_list(values):
        if not isinstance(v, str):
            continue
        h = normalize_host(v.split()[-1]) if v.split() else ''  # MX may carry a priority prefix
        if h and h not in out:
            out.append(h)
    return out


def parse_ns_mx(lines):
    out = {}
    for line in lines:
        try:
            rec = json.loads(line)
        except (TypeError, ValueError):
            continue
        if not isinstance(rec, dict):
            continue
        host = normalize_host(rec.get('host') if isinstance(rec.get('host'), str) else '')
        if not host:
            continue
        entry = out.setdefault(host, {'a': [], 'ns': [], 'mx': []})
        for v in _as_list(rec.get('a')):
            ip = _canonical_ip(v, 4)
            if ip and ip not in entry['a']:
                entry['a'].append(ip)
        for key in ('ns', 'mx'):
            for h in _hostnames(rec.get(key)):
                if h not in entry[key]:
                    entry[key].append(h)
    return out
