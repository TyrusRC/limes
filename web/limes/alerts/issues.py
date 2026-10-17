"""Diff the current issues against TrackedIssue rows and record an event per change."""
from django.db import transaction
from django.utils import timezone

from limes import scoring
from limes.alerts import events
from limes.checks.catalogue import CHECKS
from startScan.models import Asset, IssueSyncState, TrackedIssue

WORDS = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}


def _event(project, kind, row, asset):
    sev = WORDS.get(row.severity, 'unrated')
    title = {'issue_new': f'New {sev} issue {row.key} on {asset.value}',
             'issue_regressed': f'Regressed {sev} issue {row.key} on {asset.value}',
             'issue_fixed': f'Fixed {sev} issue {row.key} on {asset.value}'}[kind]
    return events.record(project, kind, title, severity=row.severity, asset=asset, key=row.key,
                         detail={'key': row.key, 'source': row.source, 'reopened': row.reopened})


def sync_issues(project, now=None):
    """Bring TrackedIssue in line with the current issues; return the events recorded.
    The first sync for a project creates rows silently. An issue is fixed only if its asset is still assessed."""
    now = now or timezone.now()
    with transaction.atomic():
        # locks the project's sync row so concurrent syncs serialize; created means first sync, which is silent
        first = IssueSyncState.objects.select_for_update().get_or_create(
            project=project, defaults={'first_synced_at': now})[1]
        issues, assessed = scoring.current_issues(project, now=now)
        rows = {(r.asset_id, r.key): r for r in TrackedIssue.objects.filter(project=project)}
        assets = {a.id: a for a in Asset.objects.filter(project=project, id__in=set(issues) | assessed)}
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
                    if not first:
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
                if kind:
                    out.append(_event(project, kind, row, asset))
        for (asset_id, key), row in rows.items():
            if row.status == 'open' and key not in issues.get(asset_id, {}) and asset_id in assessed and asset_id in assets:
                row.status, row.fixed_at = 'fixed', now
                row.save()
                out.append(_event(project, 'issue_fixed', row, assets[asset_id]))
        return out
