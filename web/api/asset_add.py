import ipaddress

import validators

from limes.scope import is_reserved_ip, is_reserved_network, parse_ip
from startScan.inventory_migrate import normalize_host


# Names that only resolve inside a network (mDNS, RFC 2606/6761/8375, common internal zones).
_INTERNAL_TLDS = ('local', 'internal', 'localhost', 'test', 'invalid', 'example', 'lan', 'corp')
_INTERNAL_SUFFIXES = ('home.arpa',)


def _err(msg):
    return {'kind': None, 'value': None, 'error': msg, 'warning': None}


def _ok(kind, value):
    return {'kind': kind, 'value': value, 'error': None, 'warning': None}


def classify_asset_entry(raw):
    """Normalize + classify a manual-add entry. Exactly one of kind/error is set."""
    s = (raw or '').strip()
    if not s:
        return _err('empty entry')
    if '*' in s:
        return _err(f'wildcards not allowed: {s}')
    if '/' in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            return _err(f'invalid CIDR: {s}')
        if is_reserved_network(net):
            return _err(f'private/reserved CIDR rejected: {s}')
        return _ok('cidr', str(net))
    ip = parse_ip(s)
    if ip is not None:
        if is_reserved_ip(ip):
            return _err(f'private/reserved IP rejected: {s}')
        return _ok('ip', str(ip))
    try:
        puny = s.encode('idna').decode('ascii')
    except (UnicodeError, ValueError):
        puny = s
    value = normalize_host(puny)
    if not value or not validators.domain(value):
        return _err(f'invalid domain/host: {s}')
    # NOTE: name checks can't stop public names that resolve to private IPs (e.g. 10.0.0.1.nip.io).
    # Upgrade path: reject private resolved IPs at each active stage (not implemented yet).
    if value.rsplit('.', 1)[-1] in _INTERNAL_TLDS or value.endswith(tuple('.' + x for x in _INTERNAL_SUFFIXES)):
        return _err(f'internal-only name rejected: {s}')
    # NOTE: label-count heuristic (<=2 labels = root_domain); a public-suffix-list
    # refinement (e.g. example.co.uk) is an A3 concern.
    kind = 'root_domain' if len(value.split('.')) <= 2 else 'hostname'
    return _ok(kind, value)
