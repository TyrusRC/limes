"""Overview activity cards (richer Overview, Task 4): remediation, top risks, what changed, discovery, coverage.
Each builder returns plain data with a fixed number of queries; names are data, escaped by the template."""
from datetime import timedelta

from django.db.models import Count, Exists, OuterRef, Q
from django.db.models.functions import Coalesce
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from dashboard.stats import OWNED
from limes import monitor, scoring
from limes.checks.catalogue import CHECKS

OLDEST_LIMIT = 5
TOP_RISKS = 10
SAMPLE_LIMIT = 5
WINDOWS = (30, 90)
GONE_STATES = ('missing', 'stale', 'retired')
DISCOVERY_NAMES = {'manual': 'Added by hand', 'CT': 'Certificate transparency', 'scan': 'Scan',
                   'InternetDB': 'Passive intel (InternetDB)', 'ASN': 'ASN', 'CIDR': 'IP range', 'attribution': 'Attribution',
                   'target': 'Scan target', 'other': 'Other'}
SOURCE_FILTERS = ('manual', 'scan', 'CT', 'InternetDB', 'CIDR', 'ASN', 'attribution')  # the Assets page's f_source options


def detected_at(issue):
    """When the issue was first detected, reset to when it came back."""
    return issue.reopened_at or issue.first_seen


def _detected():
    return Coalesce('reopened_at', 'first_seen')


def _age(now, when):
    return (now - when).days


def remediation(project, now):
    from startScan.models import IssueWaiver, TrackedIssue
    issues = TrackedIssue.objects.filter(project=project).annotate(detected=_detected())
    counts = {}
    for n in (7, 30):
        since = now - timedelta(days=n)
        counts[f'fixed_{n}'] = Count('id', filter=Q(status='fixed', fixed_at__gte=since))
        counts[f'opened_{n}'] = Count('id', filter=Q(detected__gte=since))
    out = issues.aggregate(**counts)
    waived = IssueWaiver.objects.filter(IssueWaiver.active_q(now), issue=OuterRef('pk'))
    oldest = (issues.filter(status='open', severity__gte=3).exclude(Exists(waived)).select_related('asset')
              .order_by('detected', 'asset__value', 'key')[:OLDEST_LIMIT])
    out['oldest'] = [{'id': i.id, 'asset': i.asset.value, 'title': CHECKS[i.key].title if i.key in CHECKS else i.key,
                      'category': scoring.category_of(i.key), 'severity': scoring.SEVERITY_NAMES.get(i.severity, 'unrated'),
                      'detected_at': i.detected, 'age_days': _age(now, i.detected), 'reopened': i.reopened_at is not None}
                     for i in oldest]
    return out


def top_risks(project, live, now):
    """The costliest live (waiver-excluded) issues, each joined to its open TrackedIssue for the detection date."""
    from startScan.models import TrackedIssue
    # NOTE: one IN list of every assessed asset id; fine for tens of thousands. Upgrade path: join on the score inputs in SQL.
    tracked = {(r['asset_id'], r['key']): r for r in
               TrackedIssue.objects.filter(project=project, status='open', asset_id__in=[a.id for a in live])
               .annotate(detected=_detected()).values('id', 'asset_id', 'key', 'detected')}
    rows = []
    for asset, issues in live.items():
        for key, sev in issues.items():
            t = tracked.get((asset.id, scoring.issue_key(key)))
            when = t['detected'] if t else None
            rows.append({'id': t['id'] if t else None, 'asset': asset.value, 'title': CHECKS[key].title if key in CHECKS else key,
                         'key': key, 'category': scoring.category_of(key), 'severity': scoring.SEVERITY_NAMES.get(sev, 'unrated'),
                         'points': scoring.PENALTY.get(sev, 0), 'detected_at': when,
                         'age_days': _age(now, when) if when else None})
    rows.sort(key=lambda r: (-r['points'], r['detected_at'] is None, r['detected_at'] or now, r['asset'], r['key']))
    return rows[:TOP_RISKS]


def _sample(qs):
    return list(qs.order_by('value').values_list('value', flat=True)[:SAMPLE_LIMIT])


def what_changed(project, now, score):
    from startScan.models import Asset, ScoreSnapshot, TrackedIssue
    owned = Asset.objects.filter(project=project, scope_tier__in=OWNED)
    issues = TrackedIssue.objects.filter(project=project).annotate(detected=_detected())
    out = []
    for n in WINDOWS:
        since = now - timedelta(days=n)
        new = owned.filter(first_seen__gte=since)
        # NOTE: the model keeps no timestamp for going missing or retired; last_seen (the last sighting) is the closest honest field.
        gone = owned.filter(state__in=GONE_STATES, last_seen__gte=since)
        snap = (ScoreSnapshot.objects.filter(project=project, date__lte=timezone.localtime(since).date(), score__isnull=False)
                .order_by('-date').values_list('score', 'date').first())
        snap, snap_date = snap or (None, None)
        out.append({'days': n, 'new_assets': new.count(), 'new_sample': _sample(new),
                    'removed_assets': gone.count(), 'removed_sample': _sample(gone),
                    'introduced': issues.filter(detected__gte=since).count(),
                    'resolved': issues.filter(status='fixed', fixed_at__gte=since).count(),
                    'score_from': snap, 'score_from_date': snap_date, 'score_to': score,
                    'score_delta': score - snap if snap is not None and score is not None else None})
    return out


def discovery(project):
    from startScan.models import Asset
    # NOTE: one row per owned asset in memory (monitor_state is Python-only); fine for tens of thousands. Upgrade path: store monitor status in a column.
    counts = {}
    total = 0
    for a in (Asset.objects.filter(project=project, scope_tier__in=OWNED).exclude(state='retired')
              .only('id', 'sources', 'added_by_id')):
        total += 1
        for label in monitor.found_by(a):
            counts[label] = counts.get(label, 0) + 1
    rows = [{'label': label, 'name': DISCOVERY_NAMES.get(label, label), 'count': n,
             'filter': label if label in SOURCE_FILTERS else None}
            for label, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]
    return {'rows': rows, 'total': total}


def coverage(project, now):
    from startScan.models import Asset
    from targetApp.models import Domain
    # NOTE: one row per owned asset in memory (monitor_state is Python-only); fine for tens of thousands. Upgrade path: store monitor status in a column.
    assets = (Asset.objects.filter(project=project, scope_tier__in=OWNED, kind__in=monitor.KINDS).exclude(state='retired')
              .select_related('parent', 'parent__parent')
              .annotate(has_target=Exists(Domain.objects.filter(project=OuterRef('project'), name=OuterRef('value')))))
    out = {'total': 0, 'on_time': 0, 'overdue': 0, 'never': 0, 'stopped': 0, 'range_swept': 0}
    never, overdue = [], []
    for a in assets:
        out['total'] += 1
        s = monitor.monitor_state(a)
        if s['status'] == 'range_sweep':
            out['range_swept'] += 1
        elif s['interval'] is None:
            out['stopped'] += 1
        elif s['last_checked'] is None:
            out['never'] += 1
            never.append((a.first_seen, a.value))
        elif parse_datetime(s['next_due']) < now:
            out['overdue'] += 1
            overdue.append((parse_datetime(s['last_checked']), a.value))
        else:
            out['on_time'] += 1
    out['oldest'] = None
    if never:
        out['oldest'] = {'value': min(never)[1], 'last_checked': None, 'why': 'never'}
    elif overdue:
        when, value = min(overdue)
        out['oldest'] = {'value': value, 'last_checked': when, 'why': 'overdue'}
    return out
