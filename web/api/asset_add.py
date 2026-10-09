import ipaddress

import validators

from startScan.inventory_migrate import normalize_host


# Networks are rejected on OVERLAP with any of these (is_private only tests
# "subnet of", so supernets like 0.0.0.0/0 would slip through).
_RESERVED = [ipaddress.ip_network(c) for c in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15',
    '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4', '255.255.255.255/32',
    '::1/128', '::/128', 'fc00::/7', 'fe80::/10', 'ff00::/8', '2001:db8::/32', '::ffff:0:0/96',
    # transition/translation ranges that embed or route to IPv4 (incl. private), plus special-purpose
    '64:ff9b::/96', '64:ff9b:1::/48', '2002::/16', '2001::/23', '100::/64', '5f00::/16',
)]

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
        if (any(net.version == r.version and net.overlaps(r) for r in _RESERVED)
                or not net.network_address.is_global or not net.broadcast_address.is_global):
            return _err(f'private/reserved CIDR rejected: {s}')
        return _ok('cidr', str(net))
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if ip.is_multicast or not ip.is_global or any(ip.version == r.version and ip in r for r in _RESERVED):
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
