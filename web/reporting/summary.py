"""Executive summary data: the Overview's builders (dashboard.stats, activity, posture, scoring) reshaped for one
printable page, with a fixed number of queries whatever the size of the estate. Everything returned is data;
the templates escape it."""
from datetime import timedelta

from django.db.models import Count, Q
from django.db.models.functions import Coalesce
from django.utils import timezone

from dashboard import activity, stats
from limes import scoring, tags as tag_rules
from limes.checks.catalogue import PROVISIONAL
from startScan.models import Asset, ScoreSnapshot, Tag, TrackedIssue

DAYS = (30, 90, 365)
DEFAULT_DAYS = 90
TOP_RISKS = 100  # NOTE: rows of the risks table; the page says how many more exist. Upgrade path: link to the CSV export.
SPARK_W, SPARK_H = 300, 60


def members(project, tag):
    """(clean tag name or None, asset ids) for a tag filter. A name that is not a tag of this project gives (name, empty)."""
    if not tag:
        return None, None
    name = tag_rules.lookup(tag) or ''
    ids = set(Asset.tags.through.objects.filter(tag__project=project, tag__name=name).values_list('asset_id', flat=True))
    return name, ids


def _trend(project, now, days, live_score):
    since = timezone.localtime(now).date() - timedelta(days=days)
    rows = list(ScoreSnapshot.objects.filter(project=project, date__gte=since, score__isnull=False)
                .order_by('date').values_list('date', 'score')[:days + 1])
    today = timezone.localtime(now).date()
    if live_score is not None:
        rows = [r for r in rows if r[0] != today] + [(today, live_score)]
    return rows


def _spark(points):
    """An SVG polyline 'x,y x,y ...' for [(date, score)], or '' with fewer than two points (all numbers: nothing to escape)."""
    if len(points) < 2:
        return ''
    lo, hi = min(s for _, s in points), max(s for _, s in points)
    span_days = max((points[-1][0] - points[0][0]).days, 1)
    pad = 6
    out = []
    for d, s in points:
        x = (d - points[0][0]).days / span_days * SPARK_W
        y = SPARK_H / 2 if hi == lo else pad + (hi - s) / (hi - lo) * (SPARK_H - 2 * pad)
        out.append(f'{x:.1f},{y:.1f}')
    return ' '.join(out)


def _progress(project, now, windows, ids):
    issues = TrackedIssue.objects.filter(project=project).annotate(detected=Coalesce('reopened_at', 'first_seen'))
    if ids is not None:
        issues = issues.filter(asset_id__in=list(ids))
    agg = {}
    for n in windows:
        since = now - timedelta(days=n)
        agg[f'f{n}'] = Count('id', filter=Q(status='fixed', fixed_at__gte=since))
        agg[f'o{n}'] = Count('id', filter=Q(detected__gte=since))
    got = issues.aggregate(**agg)
    return [{'days': n, 'fixed': got[f'f{n}'], 'opened': got[f'o{n}'], 'net': got[f'f{n}'] - got[f'o{n}']} for n in windows]


def headline(d):
    """Plain sentences from the data (no model): where the score stands, what is open, the weak spot, the last 30 days."""
    scope = f"Tag {d['tag']}" if d['tag'] else d['project'].name
    sc = d['score']
    if sc['score'] is None:
        return f'{scope} has not been assessed yet, so there is no score. Run a scan to produce one.'
    first = f"{scope} scores {sc['score']} out of {sc['max']} (grade {sc['grade']})"
    if sc['delta'] is not None:
        verb = 'up' if sc['delta'] > 0 else 'down'
        first += (f", {verb} {abs(sc['delta'])} point{'s' if abs(sc['delta']) != 1 else ''} over the last {d['days']} days"
                  if sc['delta'] else f", unchanged over the last {d['days']} days")
    out = [first + '.']
    sev = [f'{n} {name}' for name, n in d['severity'].items() if n]
    out.append(f"Open issues: {', '.join(sev)}." if sev else 'No critical, high, medium or low issues are open.')
    scored = [c for c in d['categories'] if c['score'] is not None and not c['provisional']]
    if scored and not d['tag']:
        weakest = min(scored, key=lambda c: (c['score'], c['label']))
        out.append(f"The weakest category is {weakest['label']} (grade {weakest['grade']}).")
    p30 = next((p for p in d['progress'] if p['days'] == 30), None)
    if p30:
        out.append(f"In the last 30 days {p30['fixed']} issue{'s were' if p30['fixed'] != 1 else ' was'} fixed and {p30['opened']} opened.")
    return ' '.join(out)


def build(project, days=DEFAULT_DAYS, tag=None, now=None):
    now = now or timezone.now()
    days = days if days in DAYS else DEFAULT_DAYS
    s = stats.project_stats(project)  # cached for STATS_TTL, shared with the Overview
    tag_name, ids = members(project, tag)
    live = stats._live_issues(project)
    if ids is not None:
        live = {a: c for a, c in live.items() if a.id in ids}
    rows = activity.top_risks(project, live, now, limit=None)  # NOTE: builds every row, then caps; fine for tens of thousands
    risk = s['risk']
    tag_rows = scoring.tag_scores(project, now, name=tag_name) if tag_name else s['tag_cards']
    head = tag_rows[0] if tag_name and tag_rows else None
    score, grade = ((head['score'], head['grade']) if head else (None, 'N/A')) if tag_name else (risk['score'], risk['grade'])
    trend = [] if tag_name else _trend(project, now, days, risk["score"])
    base = trend[0][1] if len(trend) > 1 else None
    windows = sorted({30, 90, days})
    d = {
        'project': project, 'generated_at': now, 'days': days, 'tag': tag_name, 'tag_missing': bool(tag_name) and not tag_rows,
        'score': {'score': score, 'grade': grade, 'max': scoring.MAX_SCORE, 'version': risk['version'],
                  'raw_score': head['raw_score'] if head else risk['raw_score'], 'waived': risk['waived_count'],
                  'coverage': risk['coverage'], 'delta': score - base if score is not None and base is not None else None,
                  'delta_from': base, 'spark': _spark(trend), 'points': len(trend)},
        'severity': stats._findings(live),
        'categories': s['categories'],
        'risks': {'rows': rows[:TOP_RISKS], 'total': len(rows), 'truncated': len(rows) > TOP_RISKS, 'cap': TOP_RISKS},
        'progress': _progress(project, now, windows, ids),
        'changes': activity.what_changed(project, now, risk['score']),
        'recent_changes': s['recent_changes'],
        'tags': tag_rows,
        'inventory': s['inventory'], 'exposure': s['exposure'], 'certificates': s['certificates'],
        'technologies': s['technologies'], 'discovery': s['discovery'], 'coverage': s['coverage'], 'brand': s['brand'],
    }
    d['headline'] = headline(d)
    return d
