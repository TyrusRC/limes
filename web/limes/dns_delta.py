"""DNS change detection for owned names: keep the last answer in enrichment['dns'] and record a dns_changed event
when the new one is significant. Quiet by design: a CDN rotating addresses inside a block is not a change."""
import ipaddress

from django.utils import timezone

from limes.alerts import events
from limes.tasks.intel import _store

LABELS = {'cname': 'CNAME target changed', 'unresolved': 'stopped resolving', 'resolved': 'started resolving',
          'moved': 'moved to new addresses'}
KEEP = 20
OWNED = ('owned_root', 'owned_host')


def _cnames(rec):
    return sorted({c.rstrip('.').lower() for c in rec.get('cname') or []})


def _nets(addrs, bits):
    out = set()
    for a in addrs:
        try:
            out.add(ipaddress.ip_network(f'{a}/{bits}', strict=False))
        except ValueError:
            continue
    return out


def significant(before, after):
    """'cname', 'unresolved', 'resolved', 'moved' or None for two {'a','aaaa','cname'} answers.
    # NOTE: /24 and /48 proximity keeps CDN rotation quiet; it misses a move within one provider's /24 and flags a CDN that rotates across blocks. Upgrade path: compare origin ASNs from RIPEstat enrichment."""
    if _cnames(before) != _cnames(after):
        return 'cname'
    b = list(before.get('a') or []) + list(before.get('aaaa') or [])
    a = list(after.get('a') or []) + list(after.get('aaaa') or [])
    if b and not a:
        return 'unresolved'
    if a and not b:
        return 'resolved'
    compared = new_seen = shares = False
    for key, bits in (('a', 24), ('aaaa', 48)):
        old, new = set(before.get(key) or []), set(after.get(key) or [])
        if not old or not new:
            continue  # a family empty on either side says nothing about a move
        compared = True
        fresh = new - old
        new_seen = new_seen or bool(fresh)
        if _nets(fresh, bits) & _nets(old, bits):
            shares = True
    return 'moved' if compared and new_seen and not shares else None


def _clean(rec):
    return {k: sorted(str(x).rstrip('.').lower() if k == 'cname' else str(x) for x in (rec.get(k) or []))[:KEEP]
            for k in ('a', 'aaaa', 'cname')}


def observe(asset, record, now=None, watched=False):
    """Store the answer for an owned hostname or root; record and return a dns_changed event when it is significant
    against the previous one. The first answer is a silent baseline."""
    if asset.scope_tier not in OWNED or asset.kind not in ('hostname', 'root_domain'):
        return None
    from django.db import transaction
    from startScan.models import Asset
    now = now or timezone.now()
    new = _clean(record)
    with transaction.atomic():
        row = Asset.objects.select_for_update().only('enrichment').get(pk=asset.pk)
        prev = (row.enrichment or {}).get('dns')
        reason = significant(prev, new) if prev else None
        data = {**new}
        if reason or (prev and prev.get('changed_at')):
            data['changed_at'] = now.isoformat() if reason else prev['changed_at']
        if watched:
            data['watched_at'] = now.isoformat()
        elif prev and prev.get('watched_at'):
            data['watched_at'] = prev['watched_at']
        _store(row, 'dns', data, now)
    asset.enrichment = row.enrichment
    if not reason:
        return None
    before = {k: prev.get(k) or [] for k in ('a', 'aaaa', 'cname')}
    return events.safe_record(asset.project, 'dns_changed', f'DNS changed for {asset.value}: {LABELS[reason]}',
                              asset=asset, detail={'reason': reason, 'before': before, 'after': new})
