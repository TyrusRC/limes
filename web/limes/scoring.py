"""Published, explainable risk score (A4, model limes-score-v3).

Asset score: 950 minus one penalty per distinct issue (template, else name) at its worst severity,
floored at 0, then capped by the worst severity present. Project score: nearest-rank P10 of owned
asset scores (weakest-link). Findings count only from each root's latest scan whose vulnerability
stage succeeded, so a fix confirmed by a rescan recovers at once and old scans never double-count.
The headline score leaves out issues under an active waiver; raw_score counts them. Failed risk checks (RiskCheck) last checked within CHECK_FRESH add one penalty each, at their own asset only.
"""
import hashlib
import logging
import math
from datetime import timedelta

from celery.exceptions import SoftTimeLimitExceeded
from django.db import transaction
from django.db.models import Exists, OuterRef
from django.utils import timezone

from limes.celery import app
from limes.checks.catalogue import CHECKS
from limes.definitions import NOTHING_ASSESSED, SUCCESS_TASK
from startScan.models import (Asset, IssueWaiver, RiskCheck, ScanActivity, ScanHistory, ScoreSnapshot, SubScan,
                              TrackedIssue, Vulnerability)
from targetApp.models import Domain

VERSION = 'limes-score-v3'
MAX_SCORE = 950
PENALTY = {4: 200, 3: 80, 2: 25, 1: 5}  # critical, high, medium, low; info (0) and unknown (-1) cost nothing
CEILING = {4: 599, 3: 799}  # any critical caps at grade C, any high at grade B
GRADES = [(800, 'A'), (600, 'B'), (400, 'C'), (200, 'D'), (0, 'F')]
COVERAGE_WINDOW = timedelta(days=30)
CHECK_FRESH = timedelta(days=30)
TOP_PENALTIES = 5
KEY_MAX = 255  # TrackedIssue.key max_length
SEVERITY_NAMES = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low'}


def issue_key(key):
    """The stored TrackedIssue key: unchanged when it fits, else a readable prefix plus a hash of the whole key
    (an untemplated finding's name can run to 2500 characters)."""
    if len(key) <= KEY_MAX:
        return key
    return key[:190] + '#' + hashlib.sha256(key.encode()).hexdigest()[:64]


def waived_keys(project, now=None):
    """{(asset_id, normalized key)} of issues with an active waiver; expires_at is honoured at read time."""
    now = now or timezone.now()
    active = IssueWaiver.objects.filter(IssueWaiver.active_q(now), issue=OuterRef('pk'))
    return set(TrackedIssue.objects.filter(project=project).filter(Exists(active)).values_list('asset_id', 'key'))


def grade(score):
    if score is None:
        return 'N/A'
    return next(g for floor, g in GRADES if score >= floor)


def scored_assets(project):
    return Asset.objects.filter(project=project, scope_tier__in=('owned_root', 'owned_host'),
                                kind__in=('root_domain', 'hostname', 'ip')).exclude(state='retired')


def _owned_domains(project):
    roots = Asset.objects.filter(project=project, kind='root_domain', scope_tier='owned_root').values('value')
    return Domain.objects.filter(project=project, name__in=roots)


def _assessed(activities):
    return (activities.filter(name='vulnerability_scan', status=SUCCESS_TASK)
            .exclude(error_message__startswith=NOTHING_ASSESSED))


def _scan_stage_assessed(scan):
    """The scan's own vulnerability stage scanned something. A subscan's activity attaches to the parent
    scan but covers one host, so it never counts."""
    subscan_ids = {c for ids in SubScan.objects.filter(scan_history=scan).values_list('celery_ids', flat=True)
                   for c in ids or []}
    return any(c not in subscan_ids
               for c in _assessed(ScanActivity.objects.filter(scan_of=scan)).values_list('celery_id', flat=True))


def baselines(project):
    """{root value: ScanHistory} - each owned root's latest scan whose own vulnerability stage assessed
    something. NOTE: a few queries per owned root; fine for tens of roots. Upgrade: one annotated query."""
    vuln_ok = _assessed(ScanActivity.objects.filter(scan_of=OuterRef('pk')))
    out = {}
    for d in _owned_domains(project):
        for scan in ScanHistory.objects.filter(domain=d).filter(Exists(vuln_ok)).order_by('-start_scan_date', '-id'):
            if _scan_stage_assessed(scan):
                out[d.name] = scan
                break
    return out


def _root_of(value, roots):
    return next((r for r in sorted(roots, key=len, reverse=True) if value == r or value.endswith('.' + r)), None)


def _fresh_checks(project, now=None):
    """RiskCheck rows on scored assets whose last_checked is within CHECK_FRESH."""
    now = now or timezone.now()
    return RiskCheck.objects.filter(asset__in=scored_assets(project), last_checked__gte=now - CHECK_FRESH)


def assessed_assets(project, base=None, now=None):
    """{asset_id: value} of scored assets that are assessed: their owned root has a baseline, or a risk
    check passed/failed on them recently. An asset with neither is unassessed, not clean."""
    base = baselines(project) if base is None else base
    checked = set(_fresh_checks(project, now).filter(status__in=('pass', 'fail')).values_list('asset_id', flat=True))
    return {a: v for a, v in scored_assets(project).values_list('id', 'value') if a in checked or _root_of(v, base)}


def _check_penalties(project, now=None, asset_ids=None):
    """{asset_id: {check_id: severity}} from fresh failed checks. Only 'fail' ever scores."""
    rows = _fresh_checks(project, now).filter(status='fail')
    if asset_ids is not None:
        rows = rows.filter(asset_id__in=asset_ids)
    out = {}
    for asset_id, check_id, severity in rows.values_list('asset_id', 'check_id', 'severity'):
        out.setdefault(asset_id, {})[check_id] = severity
    return out


def _penalties(project, asset_ids=None, base=None, now=None):
    """{asset_id: {category: severity}} from the baseline scans (worst severity per category) plus fresh
    failed checks (category = check_id, whose 'group.' prefix never collides with a finding template)."""
    base = baselines(project) if base is None else base
    scans = [s.id for s in base.values()]
    vulns = Vulnerability.objects.filter(scan_history_id__in=scans, open_status=True, severity__gte=1,
                                         asset__in=scored_assets(project))
    if asset_ids is not None:
        vulns = vulns.filter(asset_id__in=asset_ids)
    out = {}
    for asset_id, template_id, name, severity in vulns.values_list('asset_id', 'template_id', 'name', 'severity'):
        category = template_id or name
        per_asset = out.setdefault(asset_id, {})
        per_asset[category] = max(severity, per_asset.get(category, severity))
    for asset_id, checks in _check_penalties(project, now, asset_ids).items():
        out.setdefault(asset_id, {}).update(checks)
    return out


def current_issues(project, now=None):
    """(asset_id -> {key: severity}, assessed asset ids) from the same inputs the score uses."""
    base = baselines(project)
    assessed = assessed_assets(project, base=base, now=now)
    return _penalties(project, base=base, now=now), set(assessed)


def _score(categories):
    score = max(0, MAX_SCORE - sum(PENALTY.get(s, 0) for s in categories.values()))
    worst = max(categories.values(), default=0)
    return min(score, CEILING.get(worst, MAX_SCORE))


def _live(asset_id, categories, excluded):
    """categories without the (asset, normalized key) pairs in excluded."""
    return {c: s for c, s in categories.items() if (asset_id, issue_key(c)) not in excluded}


def _rows(value, categories, asset_id=None, waived=()):
    return [{'asset': value, 'issue': c, 'severity': SEVERITY_NAMES[s], 'points': PENALTY[s],
             'kind': 'check' if c in CHECKS else 'finding', 'waived': (asset_id, issue_key(c)) in waived}
            for c, s in sorted(categories.items(), key=lambda kv: (-kv[1], kv[0]))]


def asset_breakdown(asset):
    base = baselines(asset.project)
    if asset.id not in assessed_assets(asset.project, base):
        return {'score': None, 'grade': grade(None), 'penalties': [], 'assessed': False}
    categories = _penalties(asset.project, [asset.id], base).get(asset.id, {})
    waived = waived_keys(asset.project)
    score = _score(_live(asset.id, categories, waived))
    return {'score': score, 'grade': grade(score), 'penalties': _rows(asset.value, categories, asset.id, waived),
            'assessed': True}


def p10(scores):
    """Nearest-rank 10th percentile: the weakest assets drive it, duplicating the estate does not."""
    if not scores:
        return None
    ordered = sorted(scores)
    return ordered[max(0, math.ceil(0.10 * len(ordered)) - 1)]


def coverage(project, now=None, base=None):
    now = now or timezone.now()
    domains = _owned_domains(project).count()
    if not domains:
        return None
    base = baselines(project) if base is None else base
    fresh = sum(1 for s in base.values() if s.start_scan_date >= now - COVERAGE_WINDOW)
    return fresh / domains


def project_score(project, now=None, exclude=frozenset()):
    """Adjusted score/grade leave out active waivers (and, for forecast, the extra exclude pairs);
    raw_score/raw_grade ignore waivers. exclude holds (asset_id, normalized key) pairs."""
    base = baselines(project)
    assets = assessed_assets(project, base, now)
    penalties = {a: c for a, c in _penalties(project, base=base, now=now).items() if a in assets}
    waived = waived_keys(project, now)
    drop = waived | set(exclude)
    live = {a: _live(a, penalties.get(a, {}), drop) for a in assets}
    score = p10([_score(live[a]) for a in assets])
    raw = p10([_score(penalties.get(a, {})) for a in assets])
    rows = [r for a, cats in live.items() for r in _rows(assets[a], cats, a)]
    rows.sort(key=lambda r: (-r['points'], r['asset'], r['issue']))
    waived_count = sum(1 for a, cats in penalties.items() for c in cats if (a, issue_key(c)) in waived)
    scored = scored_assets(project).count()
    fresh = _fresh_checks(project, now).filter(status__in=('pass', 'fail')).values('asset_id').distinct().count()
    return {'version': VERSION, 'score': score, 'grade': grade(score), 'raw_score': raw, 'raw_grade': grade(raw),
            'waived_count': waived_count, 'coverage': coverage(project, now, base=base),
            'check_coverage': fresh / scored if scored else None,
            'asset_count': len(assets), 'unassessed': scored - len(assets),
            'top_penalties': rows[:TOP_PENALTIES]}


def forecast(project, issue_ids, now=None):
    """Adjusted score if the given TrackedIssues (of this project) were fixed. Ids from elsewhere are ignored."""
    now = now or timezone.now()
    fixed = set(TrackedIssue.objects.filter(project=project, id__in=issue_ids).values_list('asset_id', 'key'))
    cur = project_score(project, now)['score']
    new = project_score(project, now, exclude=fixed)['score']
    return {'score': new, 'grade': grade(new), 'delta': None if new is None or cur is None else new - cur}


logger = logging.getLogger(__name__)
GRADE_ORDER = 'ABCDF'
SCORE_DROP_POINTS = 50


def score_event(prev, today):
    """(kind, title) for a day-over-day score change, or None. A fall is a worse grade or >= 50 points."""
    if prev is None or prev.score is None or today.score is None or prev.score == today.score:
        return None
    worse = GRADE_ORDER.find(today.grade) > GRADE_ORDER.find(prev.grade) >= 0
    dropped = worse or prev.score - today.score >= SCORE_DROP_POINTS
    verb = 'fell' if today.score < prev.score else 'rose'
    return ('score_dropped' if dropped else 'score_changed',
            f'Score {verb} from {prev.score} ({prev.grade}) to {today.score} ({today.grade})')


@app.task(name='snapshot_scores', bind=False)
def snapshot_scores():
    from dashboard.models import Project
    from limes.alerts import events
    from limes.alerts.deliver import deliver_immediate
    today = timezone.localdate()
    for project in Project.objects.all():
        try:
            s = project_score(project)
            # snapshot and event commit together: a failed event leaves no row, so the next run retries it
            with transaction.atomic():
                snap, created = ScoreSnapshot.objects.update_or_create(project=project, date=today, defaults={
                    'version': s['version'], 'score': s['score'], 'grade': s['grade'], 'raw_score': s['raw_score'],
                    'coverage': s['coverage'],
                    'asset_count': s['asset_count'], 'top_penalties': s['top_penalties']})
                if created:  # a same-day rerun updates the row and must not alert twice
                    prev = ScoreSnapshot.objects.filter(project=project, date__lt=today).order_by('-date').first()
                    change = score_event(prev, snap)
                    if change:
                        events.record(project, change[0], change[1],
                                      detail={'from': prev.score, 'to': snap.score, 'grade': snap.grade})
            deliver_immediate(project)
        except SoftTimeLimitExceeded:
            raise
        except Exception:
            logger.exception('Score snapshot failed for project %s', project.pk)
    return {'projects': Project.objects.count()}
