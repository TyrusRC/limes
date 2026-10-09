"""Scope guard for every stage that sends traffic. Fails closed.

NOTE: checks the IPs recorded by the latest resolution; a tool resolving later
can get a different answer (DNS rebinding). Upgrade path: pin tools to the
resolved IPs (naabu -host <ip>, httpx host-to-IP pinning).
Tools that follow redirects (httpx -fr, curl -L) can also reach hosts the guard
never saw. Upgrade path: disable cross-host redirects or re-check redirect targets.
"""
import ipaddress
from urllib.parse import urlsplit

# Overlap with any of these makes an address/network non-public. is_global alone
# misses NAT64/6to4/Teredo, and is_private on a network only tests "subnet of".
RESERVED_NETWORKS = [ipaddress.ip_network(c) for c in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15',
    '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4', '255.255.255.255/32',
    '::1/128', '::/128', 'fc00::/7', 'fe80::/10', 'ff00::/8', '2001:db8::/32', '::ffff:0:0/96',
    '64:ff9b::/96', '64:ff9b:1::/48', '2002::/16', '2001::/23', '100::/64', '5f00::/16',
)]


def parse_ip(value):
    """ip_address for value, IPv4-mapped IPv6 collapsed to IPv4; None if not an IP."""
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip


def is_reserved_ip(value):
    """True unless value is a public unicast address (unparseable counts as reserved)."""
    ip = value if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else parse_ip(value)
    if ip is None:
        return True
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (ip.is_multicast or not ip.is_global
            or any(ip.version == n.version and ip in n for n in RESERVED_NETWORKS))


def is_reserved_network(net):
    return (any(net.version == r.version and net.overlaps(r) for r in RESERVED_NETWORKS)
            or not net.network_address.is_global or not net.broadcast_address.is_global)


def target_host(target):
    """Host of a URL, host:port, [v6]:port or bare host; None when there is none."""
    t = (target or '').strip()
    if not t:
        return None
    # Parsers disagree on backslashes/whitespace/control chars (WHATWG vs urlsplit): refuse.
    if any(c == '\\' or c.isspace() or ord(c) < 32 or ord(c) == 127 for c in t):
        return None
    if parse_ip(t) is not None:  # bare IPv6 (no brackets) can't go through urlsplit
        return str(ipaddress.ip_address(t)).lower()
    if '://' not in t:
        t = '//' + t
    try:
        host = urlsplit(t).hostname
    except ValueError:
        return None
    host = (host or '').rstrip('.').lower()
    return host or None


def _assets_by_value(project, hosts):
    from startScan.models import Asset
    by_value = {}
    # NOTE: one IN query per call; fine for tens of thousands of targets.
    for a in Asset.objects.filter(project=project, value__in=hosts).prefetch_related('ip_addresses'):
        by_value.setdefault(a.value, []).append(a)
    return by_value


def _refusal(host, assets, attack, allow_co_brand):
    if not host:
        return 'no host'
    ip = parse_ip(host)
    if ip is not None:
        ips = {str(ip)}
    else:
        ips = {i.address for a in assets for i in a.ip_addresses.all() if i.address}
        if not ips:
            return 'not resolved'
    bad = sorted(i for i in ips if is_reserved_ip(i))
    if bad:
        return 'resolves to private/reserved ' + ', '.join(bad)
    if not attack:
        return None
    if not assets:
        return 'not in inventory'
    # Every same-value asset must be scannable; 'dependency' (observed, not decided) never vetoes.
    decided = [a for a in assets if a.scope_tier != 'dependency']
    if decided and all(a.is_active_scan_allowed and (allow_co_brand or a.scope_tier != 'co_brand')
                       for a in decided):
        return None
    return 'scope tier ' + '/'.join(sorted({a.scope_tier for a in assets})) + ' is not actively scannable'


def _check(project, targets, attack, allow_co_brand):
    targets = list(targets)
    if project is None:
        return [], [(t, 'no project') for t in targets]
    allowed, refused = [], []
    try:
        hosts = {t: target_host(t) for t in targets}
        keys = {}
        for h in {h for h in hosts.values() if h}:
            p = parse_ip(h)
            keys[h] = str(p) if p else h
        # Query the canonical key and the raw host: stored values may be non-canonical.
        assets = _assets_by_value(project, set(keys.values()) | set(keys))
        for t in targets:
            h = hosts[t]
            reason = _refusal(h, (assets.get(keys[h]) or assets.get(h) or []) if h else [], attack, allow_co_brand)
            if reason:
                refused.append((t, reason))
            else:
                allowed.append(t)
    except Exception as e:  # fail closed on any lookup error
        return [], [(t, f'scope check failed: {e}') for t in targets]
    return allowed, refused


def may_contact(project, targets):
    """Allowed to send any packet: every resolved IP is public."""
    return _check(project, targets, attack=False, allow_co_brand=True)


def may_attack(project, targets, allow_co_brand=True):
    """may_contact plus an actively scannable scope tier."""
    return _check(project, targets, attack=True, allow_co_brand=allow_co_brand)
