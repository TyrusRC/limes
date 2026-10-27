"""CSV exports of issues and assets (stdlib csv; openpyxl is not a dependency, so there is no XLSX).
Every text cell goes through cell(): a value a spreadsheet would run as a formula is stored as text."""
import csv
from datetime import datetime

from django.db.models import Count, Exists, OuterRef, Q
from django.http import HttpResponse
from django.utils import timezone

from limes import scoring
from limes.checks.catalogue import CHECKS
from startScan.models import Asset, IssueWaiver, TrackedIssue

EXPORT_CAP = 50000  # NOTE: rows per file; the response says when it was cut. Upgrade path: stream with a server-side cursor.
FORMULA_LEADS = ('=', '+', '-', '@', '\t', '\r', '\n')


def cell(value):
    if value is None:
        return ''
    if isinstance(value, datetime):
        return value.isoformat(timespec='seconds')
    if isinstance(value, str) and value.startswith(FORMULA_LEADS):
        return "'" + value
    return value


def _tags(asset_ids):
    out = {}
    for asset_id, name in Asset.tags.through.objects.filter(asset_id__in=asset_ids).values_list('asset_id', 'tag__name'):
        out.setdefault(asset_id, []).append(name)
    return {a: '; '.join(sorted(n)) for a, n in out.items()}


def _respond(filename, header, rows, total_hint=None):
    cap = EXPORT_CAP
    rows = list(rows)
    truncated = len(rows) > cap
    resp = HttpResponse(content_type='text/csv; charset=utf-8')
    resp['Content-Disposition'] = f'attachment; filename="{filename}"'
    resp['Cache-Control'] = 'no-store'
    resp['X-Limes-Truncated'] = '1' if truncated else '0'
    w = csv.writer(resp)
    w.writerow(header)
    for r in rows[:cap]:
        w.writerow([cell(v) for v in r])
    if truncated:
        w.writerow([f'# truncated: only the first {cap} rows are exported'])
    return resp


def issues_csv(project, members=None):
    """members: asset ids to keep (a tag filter), or None."""
    active = IssueWaiver.objects.filter(IssueWaiver.active_q(timezone.now()), issue=OuterRef('pk'))
    qs = TrackedIssue.objects.filter(project=project).select_related('asset').annotate(waived=Exists(active))
    if members is not None:
        qs = qs.filter(asset_id__in=members)
    qs = list(qs.order_by('-status', '-severity', 'asset__value', 'key')[:EXPORT_CAP + 1])
    tags = _tags({i.asset_id for i in qs})
    rows = [[i.asset.value, scoring.category_of(i.key), CHECKS[i.key].title if i.key in CHECKS else i.key,
             scoring.SEVERITY_NAMES.get(i.severity, 'unrated'), i.status, i.first_seen, i.reopened_at, i.fixed_at,
             'yes' if i.waived else 'no', tags.get(i.asset_id, '')] for i in qs]
    return _respond('limes-issues.csv', ['asset', 'category', 'issue', 'severity', 'status', 'first_detected', 'reopened_at',
                                         'fixed_at', 'waived', 'tags'], rows)


def assets_csv(project, members=None):
    qs = Asset.objects.filter(project=project).annotate(open_issues=Count('tracked_issues', filter=Q(tracked_issues__status='open')))
    if members is not None:
        qs = qs.filter(id__in=members)
    qs = list(qs.order_by('value', 'id')[:EXPORT_CAP + 1])
    tags = _tags({a.id for a in qs})
    rows = [[a.value, a.kind, a.scope_tier, a.state, a.first_seen, a.last_seen, a.open_issues, tags.get(a.id, '')] for a in qs]
    return _respond('limes-assets.csv', ['asset', 'kind', 'scope', 'state', 'first_seen', 'last_seen', 'open_issues', 'tags'], rows)
