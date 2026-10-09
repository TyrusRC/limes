"""Scope guard for every stage that sends traffic. Fails closed.

NOTE: checks the IPs recorded by the latest resolution; a tool resolving later
can get a different answer (DNS rebinding). Upgrade path: pin tools to the
resolved IPs (naabu -host <ip>, httpx host-to-IP pinning).
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
    if '://' not in t:
        t = '//' + t
    try:
        host = urlsplit(t).hostname
    except ValueError:
        return None
    host = (host or '').rstrip('.').lower()
    return host or None
