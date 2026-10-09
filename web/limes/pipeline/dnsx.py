"""ProjectDiscovery dnsx integration: resolve A/AAAA/CNAME for a host list."""
import ipaddress
import json

from startScan.inventory_migrate import normalize_host


def build_argv(hosts_file, output_file):
    return ['dnsx', '-l', hosts_file, '-a', '-aaaa', '-cname', '-resp', '-json', '-silent', '-o', output_file]


def _valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


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
        for key in ('a', 'aaaa'):
            for v in rec.get(key) or []:
                if isinstance(v, str) and _valid_ip(v) and v not in entry[key]:
                    entry[key].append(v)
        for v in rec.get('cname') or []:
            c = normalize_host(v) if isinstance(v, str) else ''
            if c and c not in entry['cname']:
                entry['cname'].append(c)
    return out
