"""DNS change detection for owned names: keep the last answer in enrichment['dns'] and record a dns_changed event
when the new one is significant. Quiet by design: a CDN rotating addresses inside a block is not a change."""
import ipaddress
from datetime import timedelta

from django.utils import timezone
from django.utils.dateparse import parse_datetime

from limes.alerts import events
from limes.tasks.intel import _store

LABELS = {'cname': 'CNAME target changed', 'unresolved': 'stopped resolving', 'resolved': 'started resolving',
          'moved': 'moved to new addresses'}
KEEP = 20
# NOTE: one dns_changed event per asset per COOLDOWN, so a flapping record cannot produce one per watch; the stored
# answer still tracks, so a real change inside the window is silent until the next one. Upgrade path: a digest row.
COOLDOWN = timedelta(hours=1)
OWNED = ('owned_root', 'owned_host')


def _cnames(rec):
    """The first CNAME hop only: a scan records the whole chain, the monitor one lookup, and a CDN's later hops move
    on their own."""
    return [c.rstrip('.').lower() for c in (rec.get('cname') or [])[:1]]


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
    if not a:
        return None  # unresolved before and after
    compared = shares = False
    for key, bits in (('a', 24), ('aaaa', 48)):
        old, new = set(before.get(key) or []), set(after.get(key) or [])
        if not old or not new:
            continue  # a family empty on either side says nothing about a move
        compared = True
        if _nets(new, bits) & _nets(old, bits):  # an unchanged address shares its own block
            shares = True
    return None if shares else 'moved'  # no comparable family (v4-only to v6-only) shares nothing either


def _clean(rec):
    out = {k: sorted(str(x) for x in (rec.get(k) or []))[:KEEP] for k in ('a', 'aaaa')}
    out['cname'] = _cnames(rec)
    return out


def touch(asset, now=None):
    """Stamp a watch attempt that got no usable answer, so the next tick does not retry it first."""
    from django.db import transaction
    from startScan.models import Asset
    now = now or timezone.now()
    with transaction.atomic():
        row = Asset.objects.select_for_update().only('enrichment').get(pk=asset.pk)
        prev = (row.enrichment or {}).get('dns') or {}
        _store(row, 'dns', {**{k: v for k, v in prev.items() if k != 'fetched_at'}, 'watched_at': now.isoformat()}, now)
    asset.enrichment = row.enrichment


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
        prev = prev if prev and 'a' in prev else None  # a bare watched_at stamp is no baseline
        if record.get('cname') is None:  # the CNAME lookup failed: no evidence, carry the last one forward
            new['cname'] = (prev or {}).get('cname', [])
        reason = significant(prev, new) if prev else None
        data = {**new}
        if reason and prev.get('changed_at') and now - parse_datetime(prev['changed_at']) < COOLDOWN:
            reason = None  # flapping: the answer is stored, the event is not repeated
            data['changed_at'] = prev['changed_at']
        elif reason:
            data['changed_at'] = now.isoformat()
        elif prev and prev.get('changed_at'):
            data['changed_at'] = prev['changed_at']
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
