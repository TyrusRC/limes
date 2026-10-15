"""Published, explainable risk score (A4, model limes-score-v1).

Asset score: 950 minus one penalty per distinct issue (template, else name) at its worst severity,
floored at 0, then capped by the worst severity present. Project score: nearest-rank P10 of owned
asset scores (weakest-link). Findings count only from each root's latest scan whose vulnerability
stage succeeded, so a fix confirmed by a rescan recovers at once and old scans never double-count.
"""
import math
from datetime import timedelta

from django.db.models import Exists, OuterRef
from django.utils import timezone

from limes.celery import app
from limes.definitions import SUCCESS_TASK
from startScan.models import Asset, ScanActivity, ScanHistory, ScoreSnapshot, Vulnerability
from targetApp.models import Domain

VERSION = 'limes-score-v1'
MAX_SCORE = 950
PENALTY = {4: 200, 3: 80, 2: 25, 1: 5}  # critical, high, medium, low; info (0) and unknown (-1) cost nothing
CEILING = {4: 599, 3: 799}  # any critical caps at grade C, any high at grade B
GRADES = [(800, 'A'), (600, 'B'), (400, 'C'), (200, 'D'), (0, 'F')]
COVERAGE_WINDOW = timedelta(days=30)
TOP_PENALTIES = 5
SEVERITY_NAMES = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low'}


def grade(score):
    if score is None:
        return 'N/A'
    return next(g for floor, g in GRADES if score >= floor)


def scored_assets(project):
    return Asset.objects.filter(project=project, scope_tier__in=('owned_root', 'owned_host'),
                                kind__in=('root_domain', 'hostname')).exclude(state='retired')


def _owned_domains(project):
    roots = Asset.objects.filter(project=project, kind='root_domain', scope_tier='owned_root').values('value')
    return Domain.objects.filter(project=project, name__in=roots)


def baselines(project):
    """{domain_id: ScanHistory} - each owned root's latest scan whose vulnerability stage succeeded."""
    vuln_ok = ScanActivity.objects.filter(scan_of=OuterRef('pk'), name='vulnerability_scan', status=SUCCESS_TASK)
    out = {}
    for d in _owned_domains(project):
        scan = (ScanHistory.objects.filter(domain=d).filter(Exists(vuln_ok))
                .order_by('-start_scan_date', '-id').first())
        if scan:
            out[d.id] = scan
    return out


def _penalties(project, asset_ids=None):
    """{asset_id: {category: severity}} from the baseline scans, worst severity per category."""
    scans = [s.id for s in baselines(project).values()]
    vulns = Vulnerability.objects.filter(scan_history_id__in=scans, open_status=True, severity__gte=1,
                                         asset__in=scored_assets(project))
    if asset_ids is not None:
        vulns = vulns.filter(asset_id__in=asset_ids)
    out = {}
    for asset_id, template_id, name, severity in vulns.values_list('asset_id', 'template_id', 'name', 'severity'):
        category = template_id or name
        per_asset = out.setdefault(asset_id, {})
        per_asset[category] = max(severity, per_asset.get(category, severity))
    return out


def _score(categories):
    score = max(0, MAX_SCORE - sum(PENALTY.get(s, 0) for s in categories.values()))
    worst = max(categories.values(), default=0)
    return min(score, CEILING.get(worst, MAX_SCORE))


def _rows(value, categories):
    return [{'asset': value, 'issue': c, 'severity': SEVERITY_NAMES[s], 'points': PENALTY[s]}
            for c, s in sorted(categories.items(), key=lambda kv: (-kv[1], kv[0]))]


def asset_breakdown(asset):
    categories = _penalties(asset.project, [asset.id]).get(asset.id, {})
    score = _score(categories)
    return {'score': score, 'grade': grade(score), 'penalties': _rows(asset.value, categories)}


def p10(scores):
    """Nearest-rank 10th percentile: the weakest assets drive it, duplicating the estate does not."""
    if not scores:
        return None
    ordered = sorted(scores)
    return ordered[max(0, math.ceil(0.10 * len(ordered)) - 1)]


def coverage(project, now=None):
    now = now or timezone.now()
    domains = list(_owned_domains(project).values_list('id', flat=True))
    if not domains:
        return None
    fresh = sum(1 for s in baselines(project).values() if s.start_scan_date >= now - COVERAGE_WINDOW)
    return fresh / len(domains)


def project_score(project):
    assets = dict(scored_assets(project).values_list('id', 'value'))
    penalties = _penalties(project)
    scores = [_score(penalties.get(a, {})) for a in assets]
    rows = [r for a, cats in penalties.items() if a in assets for r in _rows(assets[a], cats)]
    rows.sort(key=lambda r: (-r['points'], r['asset'], r['issue']))
    score = p10(scores)
    return {'version': VERSION, 'score': score, 'grade': grade(score), 'coverage': coverage(project),
            'asset_count': len(assets), 'top_penalties': rows[:TOP_PENALTIES]}


@app.task(name='snapshot_scores', bind=False)
def snapshot_scores():
    from dashboard.models import Project
    today = timezone.localdate()
    for project in Project.objects.all():
        s = project_score(project)
        ScoreSnapshot.objects.update_or_create(project=project, date=today, defaults={
            'version': s['version'], 'score': s['score'], 'grade': s['grade'], 'coverage': s['coverage'],
            'asset_count': s['asset_count'], 'top_penalties': s['top_penalties']})
    return {'projects': Project.objects.count()}
