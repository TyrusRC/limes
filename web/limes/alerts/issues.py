"""Diff the current issues against TrackedIssue rows and record an event per change."""
import logging

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from limes import scope, scoring
from limes.alerts import events
from limes.checks.catalogue import CHECKS, PROVISIONAL
from startScan.models import Asset, IssueSyncState, IssueWaiver, TrackedIssue

logger = logging.getLogger(__name__)
WORDS = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
IP_BUCKET = '#ips'
EXPOSED_HOSTS = 20  # owned hostnames re-checked per newly exposed IP
issue_key = scoring.issue_key


def _bucket(asset, roots):
    """The first-sync unit an asset belongs to: its owned root, its range (IPs found by one), one shared bucket for other IPs, else itself."""
    if asset.kind == 'ip':
        if asset.parent_id and asset.parent.kind == 'cidr':  # a range sweeps in its own unit
            return f'cidr:{asset.parent.value}'
        return IP_BUCKET
    value = scope.target_host(asset.value) if asset.kind == 'api' else asset.value  # an API sits with its host's root
    return scoring._root_of(value or asset.value, roots) or asset.value


def _event(project, kind, row, asset):
    sev = WORDS.get(row.severity, 'unrated')
    title = {'issue_new': f'New {sev} issue {row.key} on {asset.value}',
             'issue_regressed': f'Regressed {sev} issue {row.key} on {asset.value}',
             'issue_fixed': f'Fixed {sev} issue {row.key} on {asset.value}'}[kind]
    return events.record(project, kind, title, severity=row.severity, asset=asset, key=row.key,
                         detail={'key': row.key, 'source': row.source, 'reopened': row.reopened})


def _queue_exposed(project, ip):
    """After commit: queue the owned hostnames that resolve to a newly exposed IP, so their risk checks refresh."""
    from limes import event_queue
    hosts = list(Asset.objects.filter(project=project, kind='hostname', scope_tier__in=('owned_root', 'owned_host'),
                                      ip_addresses__address=ip.value).exclude(state='retired').distinct().order_by('id')[:EXPOSED_HOSTS])

    def go():
        for h in hosts:
            event_queue.enqueue(h, 'exposed')
    transaction.on_commit(go)


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
        tracked = scoring.issue_assets(project)
        passed = set(scoring._fresh_checks(project, now, assets=tracked)
                     .filter(status='pass').values_list('asset_id', 'check_id'))
        # an IP whose listing is carried by an owned range is not its own issue: its old one is closed below
        covered = set(scoring._fresh_checks(project, now, assets=tracked)
                      .filter(status='not_applicable', check_id__in=PROVISIONAL, evidence__has_key='covered_by')
                      .values_list('asset_id', 'check_id'))
        assets = {a.id: a for a in Asset.objects.filter(project=project, id__in=set(issues) | assessed | {a for a, _ in passed}).select_related('parent')}
        roots = list(Asset.objects.filter(project=project, kind='root_domain', scope_tier='owned_root')
                     .values_list('value', flat=True))
        buckets = {a.id: _bucket(a, roots) for a in assets.values()}
        synced = set(state.roots)
        waived = set(IssueWaiver.objects.filter(IssueWaiver.active_q(now), issue__project=project)
                     .values_list('issue_id', flat=True))
        wide = set(IssueWaiver.objects.filter(IssueWaiver.active_q(now), issue__isnull=True, project=project)
                   .values_list('key', flat=True))
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
                    # a provisional check's first evaluation is a baseline too: silent until `check:<id>` is armed.
                    # NOTE: so an owned cidr/asn added later is silent on its first listing too (its own bucket is not
                    # in state.roots yet), and the IPs it covers raise no IP-level alert either.
                    baseline = key in PROVISIONAL and f'check:{key}' not in synced
                    if not first and not baseline and key not in wide and buckets[asset_id] in synced:  # a root's first sync is silent too
                        out.append(_event(project, 'issue_new', row, asset))
                    continue
                kind = None
                if row.status == 'fixed':
                    kind = 'issue_regressed'
                    row.status, row.fixed_at, row.reopened, row.reopened_at = 'open', None, row.reopened + 1, now
                elif sev > row.severity:
                    kind = 'issue_new'
                row.severity, row.last_seen = sev, now
                row.save()
                if kind and row.id not in waived and row.key not in wide:  # state still moves; only the announcement is silenced
                    out.append(_event(project, kind, row, asset))
        for (asset_id, key), row in rows.items():
            if row.status == 'open' and (asset_id, key) in covered and key not in issues.get(asset_id, {}):
                row.status, row.fixed_at = 'fixed', now  # moved to the range's issue: no event, one listing = one alert
                row.save()
                continue
            gone = (asset_id, key) in passed if row.source == 'check' else asset_id in assessed
            if row.status == 'open' and key not in issues.get(asset_id, {}) and gone and asset_id in assets:
                row.status, row.fixed_at = 'fixed', now
                row.save()
                out.append(_event(project, 'issue_fixed', row, assets[asset_id]))
        # a range's first sweep (enum.pass == 0) is silent: its bucket is not marked synced until the sweep ends
        # ... and only while the range is actually being walked: switched off, set to off or refused, it is released
        held = {buckets[a.id] for a in assets.values() if buckets[a.id].startswith('cidr:')
                and settings.RANGE_ENUMERATION and a.parent.cadence_tier != 'off'
                and ((a.parent.enrichment or {}).get('enum') or {}).get('status', 'running') == 'running'
                and ((a.parent.enrichment or {}).get('enum') or {}).get('pass', 0) == 0}
        known = set(buckets.values()) - held
        # a provisional check with a fresh pass/fail row has been evaluated: its later new hits alert
        known |= {f'check:{c}' for c in scoring._fresh_checks(project, now, assets=tracked)
                  .filter(status__in=('pass', 'fail'), check_id__in=PROVISIONAL).values_list('check_id', flat=True).distinct()}
        if not synced >= known:
            state.roots = sorted(synced | known)
            state.save(update_fields=['roots'])
        for ev in out:
            if ev.kind == 'issue_new' and ev.asset.kind == 'ip' and ev.detail['key'].startswith('net.exposed_'):
                _queue_exposed(project, ev.asset)
        try:  # the fixes above are saved; a remediation request that has nothing left open completes
            from remediation import service
            with transaction.atomic():  # a savepoint: a failure here must not poison the sync's transaction
                service.complete_finished(project, now)
        except Exception:
            logger.exception('Could not complete remediation requests for project %s', project.pk)
        return out
