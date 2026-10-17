"""Owned address ranges: the one place addresses are counted against the size caps."""
import ipaddress

MAX_ENTRY_ADDRESSES = 4096  # per entry, applied to the total after a start-end range is summarised


def addresses(value):
    """Number of addresses in an ip or CIDR string."""
    return ipaddress.ip_network(value, strict=False).num_addresses


def range_addresses(project, exclude_parent=None):
    """Addresses held by the project's owned, non-retired cidr rows; exclude_parent leaves out one ASN's children.

    NOTE: overlapping ranges are counted twice (conservative: errs toward refusing).
    Upgrade path: collapse with ipaddress.collapse_addresses before summing.
    """
    from startScan.models import Asset
    rows = Asset.objects.filter(project=project, kind='cidr', scope_tier__in=('owned_root', 'owned_host')
                                ).exclude(state='retired')
    if exclude_parent is not None:
        rows = rows.exclude(parent=exclude_parent)
    return sum(addresses(v) for v in rows.values_list('value', flat=True))
