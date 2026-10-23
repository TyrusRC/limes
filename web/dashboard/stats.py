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
CHANGE_LABELS = {'issue_new': 'New issue', 'issue_fixed': 'Fixed', 'issue_regressed': 'Came back',
                 'score_dropped': 'Score dropped', 'score_changed': 'Score changed', 'waiver_expired': 'Waiver expired',
                 'asset_missing': 'Asset missing', 'asset_auto_confirmed': 'Auto-confirmed',
                 'asset_new': 'New asset', 'cert_new': 'New certificate', 'dns_changed': 'DNS changed',
                 'monitoring_degraded': 'Monitoring degraded', 'monitoring_restored': 'Monitoring restored'}


def _key(project_id):
    return f'dashboard:stats:{project_id}'


def invalidate(project_id):
    cache.delete(_key(project_id))


def _risk(project):
    from limes import scoring
    from startScan.models import ScoreSnapshot
    risk = scoring.project_score(project)
    snaps = ScoreSnapshot.objects.filter(project=project).order_by('-date').values('date', 'score', 'version')[:30]
    trend = [{'date': s['date'].isoformat(), 'score': s['score'], 'version': s['version']} for s in reversed(list(snaps))]
    if risk['score'] is not None:  # today's point is the live score, so the series ends at the headline
        today = {'date': timezone.localdate().isoformat(), 'score': risk['score'], 'version': risk['version']}
        trend = (trend[:-1] if trend and trend[-1]['date'] == today['date'] else trend[-29:]) + [today]
    risk['trend'] = trend
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


def _live_issues(project):
    """{asset: {category: severity}} for assessed assets, without actively waived issues: the inputs the
    headline score uses. NOTE: rebuilds the baselines project_score already built; cached for STATS_TTL."""
    from limes import scoring
    from startScan.models import Asset
    penalties, assessed = scoring.current_issues(project)
    waived = scoring.waived_keys(project)
    return {a: scoring._live(a.id, penalties.get(a.id, {}), waived)
            for a in Asset.objects.filter(id__in=assessed).only('id', 'value', 'kind', 'last_seen')}


def _sev_counts(categories):
    sevs = list(categories)
    return {name: sevs.count(sev) for sev, name in SEVERITY_FIELDS.items()}


def _risky_assets(live):
    """Assessed assets below the maximum, weakest first, scored the way the headline is."""
    from limes import scoring
    rows = []
    for a, cats in live.items():
        score = scoring._score(cats)
        if score < scoring.MAX_SCORE:
            rows.append({'value': a.value, 'kind': a.kind, 'score': score, 'grade': scoring.grade(score),
                         'last_seen': a.last_seen, 'counts': _sev_counts(cats.values())})
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
    return {'new_owned': Asset.objects.filter(project=project, scope_tier__in=OWNED, first_seen__gte=now - WEEK).count()}


def _findings(live):
    """Open issues (findings and failed checks) on assessed assets, actively waived ones left out."""
    return _sev_counts(sev for cats in live.values() for sev in cats.values())


def _monitoring(project, now):
    from limes import continuous
    from startScan.models import ScanHistory
    scans = ScanHistory.objects.filter(domain__project=project)
    due = continuous.due_roots(now, project=project)[:5]
    last_auto = scans.filter(initiated_by__isnull=True).order_by('-start_scan_date').values_list('start_scan_date', flat=True).first()
    last_scan = scans.order_by('-start_scan_date').values_list('start_scan_date', flat=True).first()
    return {'enabled': settings.CONTINUOUS_SCANS,
            'running': scans.filter(scan_status__in=continuous.IN_PROGRESS).count(),
            'next_due': [{'value': a.value, 'cadence_tier': a.cadence_tier} for a in due],
            'last_auto': last_auto, 'last_scan': last_scan}


def _recent_changes(project):
    from startScan.models import ChangeEvent
    evs = ChangeEvent.objects.filter(project=project).select_related('asset').order_by('-created_at', '-id')[:LIST_LIMIT]
    return [{'id': e.id, 'kind': e.kind, 'label': CHANGE_LABELS.get(e.kind, e.kind), 'title': e.title, 'severity': e.severity, 'created_at': e.created_at,
             'asset': e.asset.value if e.asset else None} for e in evs]


def asm_stats(project):
    now = timezone.now()
    from dashboard import activity, posture
    live = _live_issues(project)
    risk = _risk(project)
    return {
        'risk': risk,
        'inventory': _inventory(project),
        'review': _review(project),
        'changes': _changes(project, now),
        'recent_changes': _recent_changes(project),
        'findings': _findings(live),
        'risky_assets': _risky_assets(live),
        'monitoring': _monitoring(project, now),
        'categories': posture.category_cards(project, now),
        'exposure': posture.exposure(project, now),
        'certificates': posture.certificates(project, now),
        'technologies': posture.technologies(project),
        'remediation': activity.remediation(project, now),
        'top_risks': activity.top_risks(project, live, now),
        'what_changed': activity.what_changed(project, now, risk['score']),
        'discovery': activity.discovery(project),
        'coverage': activity.coverage(project, now),
    }


def project_stats(project):
    stats = cache.get(_key(project.id))
    if stats is None:
        stats = asm_stats(project)
        cache.set(_key(project.id), stats, STATS_TTL)
    return stats
