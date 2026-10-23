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


def add_assets(project, raw, tier, reason, user, active_authorized=None):
    """Add owned assets by explicit entries (the REST view and the MCP tool both call this). `raw` is a list of
    entries, `tier` one of owned_root/owned_host/co_brand, `active_authorized` None when the caller did not give it.
    Returns {'added', 'existing', 'skipped', 'warnings'}."""
    from django.conf import settings
    from django.db import transaction
    from dashboard.stats import invalidate
    from limes.owned_ranges import addresses, range_addresses
    from limes.scan_target import ensure_scan_target
    from limes.tasks.inventory import _append_source
    from startScan.models import Asset
    set_authorized = tier == 'co_brand' and active_authorized is not None
    authorized = active_authorized
    added, existing, skipped, warnings = 0, 0, 0, []
    roots = []  # owned roots added, promoted or re-added, given a scan target once the transaction commits
    cap = settings.RANGE_ADDRESS_CAP
    # NOTE: `used` is read once without a lock, so two concurrent requests can both pass and exceed the cap.
    # Upgrade: select_for_update on the project row around this read and the writes.
    used = range_addresses(project)
    with transaction.atomic():
        for entry in raw:
            if not isinstance(entry, str):
                skipped += 1
                warnings.append('entry must be a string')
                continue
            c = classify_asset_entry(entry)
            if c['error']:
                skipped += 1
                warnings.append(c['error'])
                continue
            # The project cap is all-or-nothing per entry, against a running total across the request.
            # Only a missing row or a promoted candidate/dependency adds addresses: an owned row is already
            # in `used`, a rejected or co_brand one is skipped or left alone below.
            # NOTE: one query per CIDR (about 24 per range, 5000 entries per request at most). Upgrade:
            # read the project's cidr tiers once before the loop.
            new_cidrs = []
            if c['kind'] == 'cidr' and tier != 'co_brand':
                for v in c['values']:
                    row_tier = Asset.objects.filter(project=project, kind='cidr', value=v).values_list(
                        'scope_tier', flat=True).first()
                    if row_tier in (None, 'candidate', 'dependency'):
                        new_cidrs.append(v)
            need = sum(addresses(v) for v in new_cidrs)
            if need and used + need > cap:
                skipped += len(c['values'])
                warnings.extend(
                    f"{entry.strip()} would add {need} addresses, over this project's cap of {cap} "
                    f'({used} in use): add fewer ranges or ask the operator to raise LIMES_RANGE_ADDRESS_CAP'
                    for _ in c['values'])
                continue
            used += need
            if c['warning'] and c['warning'] not in warnings:
                warnings.append(c['warning'])
            for value in c['values']:
                asset, created = Asset.objects.get_or_create(
                    project=project, kind=c['kind'], value=value,
                    defaults={'scope_tier': tier, 'state': 'active'})
                # Re-adding never downgrades a tier, resurrects a rejection or wipes a recorded reason;
                # those are explicit decisions made through Confirm/Reject.
                if not created and asset.scope_tier == 'rejected':
                    skipped += 1
                    warnings.append(f'{asset.value} was rejected; confirm it instead of re-adding')
                    continue
                promote = created or asset.scope_tier in ('candidate', 'dependency')
                if not promote and not (set_authorized and asset.scope_tier == 'co_brand'):
                    existing += 1
                    roots.append(asset)  # idempotent: re-adding links a root whose earlier clash was cleared
                    continue
                if promote:
                    asset.scope_tier = tier
                    asset.state = 'active'
                if set_authorized:
                    asset.active_authorized = authorized
                asset.added_by = user
                if reason:
                    asset.decision_reason = reason
                _append_source(asset, 'manual', reason or f'added by {user.get_username()}')
                asset.save()
                added += 1
                roots.append(asset)
    for asset in roots:
        warning = ensure_scan_target(asset)[1]
        if warning:
            warnings.append(warning)
    invalidate(project.id)
    return {'added': added, 'existing': existing, 'skipped': skipped, 'warnings': warnings}
