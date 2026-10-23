import ipaddress
import re

import validators
from django.conf import settings

from limes import owned_ranges
from limes.intel import domains
from limes.scope import INTERNAL_SUFFIXES as _INTERNAL_SUFFIXES, INTERNAL_TLDS as _INTERNAL_TLDS
from limes.scope import is_reserved_ip, is_reserved_network, parse_ip
from startScan.inventory_migrate import normalize_host


def _err(msg):
    return {'kind': None, 'value': None, 'values': [], 'error': msg, 'warning': None}


def _ok(kind, value, values=None, warning=None):
    return {'kind': kind, 'value': value, 'values': values or [value], 'error': None, 'warning': warning}


_ASN_RE = re.compile(r'^AS\s?(\d{1,10})$', re.I | re.A)
_ENUM_OFF = 'range enumeration is off until the operator enables it (LIMES_RANGE_ENUMERATION); it is tracked but not expanded'


def _asn_reserved(n):
    return not 1 <= n <= 4294967294 or n == 23456 or 64496 <= n <= 131071 or n >= 4200000000


def _enum_warning(kind):
    return None if kind not in ('cidr', 'asn') or settings.RANGE_ENUMERATION else _ENUM_OFF


def _cidrs(nets, label):
    """Vet covering networks as one entry: size cap on the total, then no reserved space; all or nothing."""
    total = sum(n.num_addresses for n in nets)
    if total > owned_ranges.MAX_ENTRY_ADDRESSES:
        return _err(f'{label} is too large ({total} > {owned_ranges.MAX_ENTRY_ADDRESSES} addresses per entry): '
                    'add smaller ranges')
    if any(is_reserved_network(n) for n in nets):
        return _err(f'private/reserved CIDR rejected: {label}')
    values = [str(n) for n in nets]
    return _ok('cidr', values[0], values, _enum_warning('cidr'))


def classify_asset_entry(raw):
    """Normalize + classify a manual-add entry. Exactly one of kind/error is set."""
    s = (raw or '').strip()
    if not s:
        return _err('empty entry')
    if '*' in s:
        return _err(f'wildcards not allowed: {s}')
    if re.fullmatch(r'\d+', s, re.A):
        return _err(f'bare number {s}: write an ASN as AS{s}')
    m = _ASN_RE.match(s)
    if m:
        if _asn_reserved(int(m.group(1))):
            return _err(f'reserved or private ASN rejected: {s}')
        return _ok('asn', f'AS{int(m.group(1))}', warning=_enum_warning('asn'))
    if '/' in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            return _err(f'invalid CIDR: {s}')
        if is_reserved_network(net):
            return _err(f'private/reserved CIDR rejected: {s}')
        return _cidrs([net], s)
    if '-' in s:
        ends = [parse_ip(x) for x in s.split('-')]
        if len(ends) == 2 and None not in ends:
            lo, hi = ends
            if lo.version != hi.version:
                return _err(f'range mixes IPv4 and IPv6: {s}')
            if lo > hi:
                return _err(f'range start is after its end: {s}')
            span = int(hi) - int(lo) + 1
            if span > owned_ranges.MAX_ENTRY_ADDRESSES:  # refuse before summarising a huge span
                return _err(f'{s} is too large ({span} > {owned_ranges.MAX_ENTRY_ADDRESSES} addresses per entry): '
                            'add smaller ranges')
            return _cidrs(list(ipaddress.summarize_address_range(lo, hi)), s)
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
    # Name checks can't stop public names that resolve to private IPs (e.g. 10.0.0.1.nip.io): limes.safe_fetch
    # vets every resolved answer right before any contact and refuses the host if one is private or reserved.
    if value.rsplit('.', 1)[-1] in _INTERNAL_TLDS or value.endswith(tuple('.' + x for x in _INTERNAL_SUFFIXES)):
        return _err(f'internal-only name rejected: {s}')
    if domains.registrable(value) is None:
        return _err(f'public suffix cannot be a root domain: {s}')
    return _ok('root_domain' if domains.registrable(value) == value else 'hostname', value)
