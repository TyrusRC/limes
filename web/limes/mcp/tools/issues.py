"""Read tools: issues, waivers and notes, the score forecast and the score history."""
from datetime import timedelta
from typing import Annotated, Literal
from django.db.models import Count, Prefetch
from django.utils import timezone
from pydantic import Field
from limes import scoring
from limes.mcp import access
from limes.mcp.access import McpError
from limes.mcp.registry import tool
from limes.mcp.results import Cursor, Limit, RowId, Slug, iso, page, untrusted
from limes.mcp.tools.inventory import issue_title, waived_exists
from startScan.asset_models import IssueNote, IssueWaiver, ScoreSnapshot, TrackedIssue

DETAIL_CAP = 20  # 20 waivers + 20 notes at 1000 characters each stay far inside the result budget
TEXT_CAP = 1000
FORECAST_MAX = 500


def _issue_item(i):
    w = i.live_waivers[0] if i.live_waivers else None
    return {'id': i.id, 'asset_id': i.asset_id, 'asset': untrusted(i.asset.value), 'key': untrusted(i.key),
            'title': issue_title(i.source, i.key), 'source': i.source, 'severity': i.severity, 'status': i.status,
            'first_seen': iso(i.first_seen), 'last_seen': iso(i.last_seen), 'fixed_at': iso(i.fixed_at),
            'reopened': i.reopened, 'note_count': i.note_count,
            'waiver': {'kind': w.kind, 'expires_at': iso(w.expires_at),
                       'created_by': w.created_by.username if w.created_by else None} if w else None}


def _with_extras(qs, now):
    live = IssueWaiver.objects.filter(IssueWaiver.active_q(now)).select_related('created_by').order_by('-created_at', '-id')
    return (qs.select_related('asset').annotate(note_count=Count('notes', distinct=True))
            .prefetch_related(Prefetch('waivers', queryset=live, to_attr='live_waivers')))


@tool(title='List issues')
def list_issues(caller, project: Slug, status: Literal['open', 'fixed'] = 'open',
                severity: Literal[1, 2, 3, 4] | None = None, source: Literal['check', 'finding'] | None = None,
                waived: bool | None = None, category: Literal[scoring.CATEGORIES] | None = None,
                cursor: Cursor = None, limit: Limit = 50):
    """List the project's issues, worst first, with the active waiver and note count. severity 4 is critical, 1 low."""
    p = access.project_for(caller, project)
    now = timezone.now()
    qs = TrackedIssue.objects.filter(project=p, status=status)
    if severity:
        qs = qs.filter(severity=severity)
    if source:
        qs = qs.filter(source=source)
    if category:
        qs = qs.filter(scoring.category_q(category))
    if waived is not None:
        qs = qs.filter(waived_exists(now)) if waived else qs.exclude(waived_exists(now))
    return page(_with_extras(qs, now).order_by('-severity', 'first_seen', 'id'), cursor, limit, _issue_item)


@tool(title='Issue detail')
def get_issue(caller, project: Slug, issue_id: RowId):
    """One issue with its waivers (newest first) and notes (oldest first)."""
    p = access.project_for(caller, project)
    now = timezone.now()
    issue = _with_extras(TrackedIssue.objects.filter(project=p, pk=issue_id), now).first()
    if issue is None:
        raise McpError('not_found', 'issue not found')
    waivers = (IssueWaiver.objects.filter(issue=issue).select_related('created_by', 'revoked_by')
               .order_by('-created_at', '-id')[:DETAIL_CAP])
    notes = IssueNote.objects.filter(issue=issue).select_related('author').order_by('created_at', 'id')[:DETAIL_CAP]
    active = {w.id for w in issue.live_waivers}
    return {**_issue_item(issue),
            'waivers': [{'kind': w.kind, 'reason': untrusted(w.reason, TEXT_CAP),
                         'created_by': w.created_by.username if w.created_by else None,
                         'created_at': iso(w.created_at), 'expires_at': iso(w.expires_at),
                         'revoked_at': iso(w.revoked_at), 'revoked_by': w.revoked_by.username if w.revoked_by else None,
                         'active': w.id in active} for w in waivers],
            'notes': [{'author': n.author.username if n.author else None, 'text': untrusted(n.text, TEXT_CAP),
                       'created_at': iso(n.created_at)} for n in notes]}


@tool(title='Forecast the score')
def forecast_score(caller, project: Slug, issue_ids: Annotated[list[RowId], Field(min_length=1, max_length=FORECAST_MAX)]):
    """The project score if these issues were fixed. Ids from other projects are ignored."""
    p = access.project_for(caller, project)
    now = timezone.now()
    # NOTE: forecast runs project_score twice, uncached, per call (about 2 x the Overview's cold cost). Upgrade
    # path: a per-project cache of the score inputs shared with stats.
    out = scoring.forecast(p, issue_ids, now)
    out['current_score'] = out['score'] - out['delta'] if out['delta'] is not None else scoring.project_score(p, now)['score']
    return out


@tool(title='Score history')
def get_score_history(caller, project: Slug, days: Annotated[int, Field(ge=1, le=365)] = 30):
    """Daily score snapshots of the last N days, oldest first, with the per-category scores."""
    p = access.project_for(caller, project)
    rows = ScoreSnapshot.objects.filter(project=p, date__gte=timezone.localdate() - timedelta(days=days)).order_by('date')
    return {'items': [{'date': r.date.isoformat(), 'score': r.score, 'grade': r.grade, 'raw_score': r.raw_score,
                       'version': r.version, 'categories': r.categories} for r in rows]}
