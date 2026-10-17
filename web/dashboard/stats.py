"""Project dashboard data (A-dash): inventory-first, read from the Asset inventory and the A4 score.
Cached per project for STATS_TTL; asset decisions and finished scans call invalidate()."""
from datetime import timedelta

from django.conf import settings
from django.core.cache import cache
from django.db.models import Count, Q
from django.utils import timezone

STATS_TTL = 60
WEEK = timedelta(days=7)
LIST_LIMIT = 10
RISKY_LIMIT = 6
OWNED = ('owned_root', 'owned_host')
SEVERITY_FIELDS = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low'}


def _key(project_id):
    return f'dashboard:stats:{project_id}'


def invalidate(project_id):
    cache.delete(_key(project_id))


def _risk(project):
    from limes import scoring
    from startScan.models import ScoreSnapshot
    risk = scoring.project_score(project)
    snaps = ScoreSnapshot.objects.filter(project=project).order_by('-date').values('date', 'score', 'version')[:30]
    risk['trend'] = [{'date': s['date'].isoformat(), 'score': s['score'], 'version': s['version']} for s in reversed(list(snaps))]
    risk['band'] = grade_band(risk['score'])
    risk['max_score'] = scoring.MAX_SCORE
    return risk


def grade_band(score):
    """The scoring model's band around score: {floor, top, next grade, points to it}; None when unscored."""
    from limes import scoring
    if score is None:
        return None
    floors = scoring.GRADES  # [(floor, grade)], best first
    i = next(i for i, (floor, _) in enumerate(floors) if score >= floor)
    top = floors[i - 1][0] - 1 if i else scoring.MAX_SCORE
    return {'floor': floors[i][0], 'top': top, 'next': floors[i - 1][1] if i else None,
            'to_next': floors[i - 1][0] - score if i else None}


def _risky_assets(project):
    """Assessed assets below the maximum, weakest first, scored the way the headline is (waivers left out).
    NOTE: recomputes the baselines project_score already built; cached for STATS_TTL. Upgrade: share them."""
    from limes import scoring
    from startScan.models import Asset
    penalties, assessed = scoring.current_issues(project)
    waived = scoring.waived_keys(project)
    rows = []
    for a in Asset.objects.filter(id__in=assessed).only('id', 'value', 'kind', 'last_seen'):
        live = scoring._live(a.id, penalties.get(a.id, {}), waived)
        score = scoring._score(live)
        if score < scoring.MAX_SCORE:
            sevs = list(live.values())
            rows.append({'value': a.value, 'kind': a.kind, 'score': score, 'grade': scoring.grade(score),
                         'last_seen': a.last_seen, 'counts': {n: sevs.count(v) for v, n in SEVERITY_FIELDS.items()}})
    rows.sort(key=lambda r: (r['score'], r['value']))
    return rows[:RISKY_LIMIT]


def _inventory(project):
    from startScan.models import Asset
    assets = Asset.objects.filter(project=project)
    counts = assets.aggregate(
        owned_root=Count('id', filter=Q(scope_tier='owned_root')),
        owned_host=Count('id', filter=Q(scope_tier='owned_host', kind__in=('hostname', 'root_domain'))),
        ip=Count('id', filter=Q(scope_tier__in=OWNED, kind='ip')),
        dependency=Count('id', filter=Q(scope_tier='dependency')))
    states = dict(assets.filter(scope_tier__in=OWNED).values_list('state').annotate(n=Count('id')))
    counts['states'] = {s: states.get(s, 0) for s in ('active', 'missing', 'stale', 'retired')}
    return counts


def _review(project):
    from limes.tasks.attribution import REVIEW
    from startScan.models import Asset
    cands = Asset.objects.filter(project=project, scope_tier='candidate')
    return {'candidates': cands.filter(Q(confidence__isnull=True) | Q(confidence__gte=REVIEW)).count(),
            'would_auto_confirm': cands.filter(confidence_detail__would_auto_confirm=True).count()}


def _changes(project, now):
    from startScan.models import Asset
    owned = Asset.objects.filter(project=project, scope_tier__in=OWNED)
    new = owned.filter(first_seen__gte=now - WEEK).order_by('-first_seen', 'id')[:LIST_LIMIT]
    missing = owned.filter(state='missing').order_by('-last_seen', 'id')[:LIST_LIMIT]
    auto = []
    for a in owned.filter(decision_reason__startswith='auto-confirmed', sources__contains=[{'source': 'attribution'}]):
        seen = max((s.get('seen_at') or '' for s in a.sources or [] if s.get('source') == 'attribution'), default='')
        if seen >= (now - WEEK).isoformat():
            auto.append({'value': a.value, 'kind': a.kind, 'seen_at': seen})
    auto.sort(key=lambda r: r['seen_at'], reverse=True)
    return {'new_owned': _rows(new, 'first_seen'), 'missing': _rows(missing, 'last_seen'),
            'auto_confirmed': auto[:LIST_LIMIT]}


def _rows(assets, field):
    return [{'value': a.value, 'kind': a.kind, field: getattr(a, field)} for a in assets]


def _findings(project):
    from limes import scoring
    from startScan.models import Vulnerability
    base = scoring.baselines(project)
    assets = scoring.assessed_assets(project, base)
    counts = (Vulnerability.objects.filter(scan_history__in=[s.id for s in base.values()], open_status=True,
                                           asset_id__in=list(assets), severity__gte=1)
              .values_list('severity').annotate(n=Count('id')))
    by_sev = dict(counts)
    return {name: by_sev.get(sev, 0) for sev, name in SEVERITY_FIELDS.items()}


def _monitoring(project, now):
    from limes import continuous
    from startScan.models import ScanHistory
    scans = ScanHistory.objects.filter(domain__project=project)
    # NOTE: due_roots spans every project; fine for hundreds of roots, cached for STATS_TTL
    due = [a for a in continuous.due_roots(now) if a.project_id == project.id][:5]
    last_auto = scans.filter(initiated_by__isnull=True).order_by('-start_scan_date').values_list('start_scan_date', flat=True).first()
    last_scan = scans.order_by('-start_scan_date').values_list('start_scan_date', flat=True).first()
    return {'enabled': settings.CONTINUOUS_SCANS,
            'running': scans.filter(scan_status__in=continuous.IN_PROGRESS).count(),
            'next_due': [{'value': a.value, 'cadence_tier': a.cadence_tier} for a in due],
            'last_auto': last_auto, 'last_scan': last_scan}


def _recent_changes(project):
    from startScan.models import ChangeEvent
    evs = ChangeEvent.objects.filter(project=project).select_related('asset').order_by('-created_at', '-id')[:LIST_LIMIT]
    return [{'kind': e.kind, 'title': e.title, 'severity': e.severity, 'created_at': e.created_at,
             'asset': e.asset.value if e.asset else None} for e in evs]


def asm_stats(project):
    from startScan.models import ScanActivity
    now = timezone.now()
    return {
        'risk': _risk(project),
        'inventory': _inventory(project),
        'review': _review(project),
        'changes': _changes(project, now),
        'recent_changes': _recent_changes(project),
        'findings': _findings(project),
        'risky_assets': _risky_assets(project),
        'monitoring': _monitoring(project, now),
        'activity': list(ScanActivity.objects.filter(scan_of__domain__project=project).order_by('-time')[:15]),
    }


def project_stats(project):
    stats = cache.get(_key(project.id))
    if stats is None:
        stats = asm_stats(project)
        cache.set(_key(project.id), stats, STATS_TTL)
    return stats
