"""Diff the current issues against TrackedIssue rows and record an event per change."""
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from limes import scoring
from limes.alerts import events
from limes.checks.catalogue import CHECKS
from startScan.models import Asset, IssueSyncState, IssueWaiver, TrackedIssue

WORDS = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
IP_BUCKET = '#ips'
issue_key = scoring.issue_key


def _bucket(asset, roots):
    """The first-sync unit an asset belongs to: its owned root, its range (IPs found by one), one shared bucket for other IPs, else itself."""
    if asset.kind == 'ip':
        if asset.parent_id and asset.parent.kind == 'cidr':  # a range sweeps in its own unit
            return f'cidr:{asset.parent.value}'
        return IP_BUCKET
    return scoring._root_of(asset.value, roots) or asset.value


def _event(project, kind, row, asset):
    sev = WORDS.get(row.severity, 'unrated')
    title = {'issue_new': f'New {sev} issue {row.key} on {asset.value}',
             'issue_regressed': f'Regressed {sev} issue {row.key} on {asset.value}',
             'issue_fixed': f'Fixed {sev} issue {row.key} on {asset.value}'}[kind]
    return events.record(project, kind, title, severity=row.severity, asset=asset, key=row.key,
                         detail={'key': row.key, 'source': row.source, 'reopened': row.reopened})


def sync_issues(project, now=None):
    """Bring TrackedIssue in line with the current issues; return the events recorded.
    The first sync for a project, or for a root (IPs share one bucket), creates rows silently. A finding is fixed only if its asset is still assessed;
    a check only when its own row is fresh and passing (error, not_applicable, stale or missing leave it open)."""
    now = now or timezone.now()
    with transaction.atomic():
        # locks the project's sync row so concurrent syncs serialize; created means first sync, which is silent
        state, first = IssueSyncState.objects.select_for_update().get_or_create(
            project=project, defaults={'first_synced_at': now})
        issues, assessed = scoring.current_issues(project, now=now)
        issues = {a: {issue_key(k): sev for k, sev in keys.items()} for a, keys in issues.items()}
        rows = {(r.asset_id, r.key): r for r in TrackedIssue.objects.filter(project=project)}
        assets = {a.id: a for a in Asset.objects.filter(project=project, id__in=set(issues) | assessed).select_related('parent')}
        roots = list(Asset.objects.filter(project=project, kind='root_domain', scope_tier='owned_root')
                     .values_list('value', flat=True))
        buckets = {a.id: _bucket(a, roots) for a in assets.values()}
        synced = set(state.roots)
        passed = set(scoring._fresh_checks(project, now).filter(status='pass').values_list('asset_id', 'check_id'))
        waived = set(IssueWaiver.objects.filter(IssueWaiver.active_q(now), issue__project=project)
                     .values_list('issue_id', flat=True))
        out = []
        for asset_id, keys in issues.items():
            asset = assets.get(asset_id)
            if asset is None:
                continue
            for key, sev in keys.items():
                row = rows.get((asset_id, key))
                if row is None:
                    row = TrackedIssue.objects.create(project=project, asset=asset, key=key, severity=sev, first_seen=now,
                                                      last_seen=now, source='check' if key in CHECKS else 'finding')
                    if not first and buckets[asset_id] in synced:  # a root's first sync is silent too
                        out.append(_event(project, 'issue_new', row, asset))
                    continue
                kind = None
                if row.status == 'fixed':
                    kind = 'issue_regressed'
                    row.status, row.fixed_at, row.reopened = 'open', None, row.reopened + 1
                elif sev > row.severity:
                    kind = 'issue_new'
                row.severity, row.last_seen = sev, now
                row.save()
                if kind and row.id not in waived:  # state still moves; only the announcement is silenced
                    out.append(_event(project, kind, row, asset))
        for (asset_id, key), row in rows.items():
            gone = (asset_id, key) in passed if row.source == 'check' else asset_id in assessed
            if row.status == 'open' and key not in issues.get(asset_id, {}) and gone and asset_id in assets:
                row.status, row.fixed_at = 'fixed', now
                row.save()
                out.append(_event(project, 'issue_fixed', row, assets[asset_id]))
        # a range's first sweep (enum.pass == 0) is silent: its bucket is not marked synced until the sweep ends
        # ... and only while the range is actually being walked: switched off, set to off or refused, it is released
        held = {buckets[a.id] for a in assets.values() if buckets[a.id].startswith('cidr:')
                and settings.RANGE_ENUMERATION and a.parent.cadence_tier != 'off'
                and ((a.parent.enrichment or {}).get('enum') or {}).get('status') == 'running'
                and ((a.parent.enrichment or {}).get('enum') or {}).get('pass', 0) == 0}
        known = set(buckets.values()) - held
        if not synced >= known:
            state.roots = sorted(synced | known)
            state.save(update_fields=['roots'])
        return out
