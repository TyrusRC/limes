"""Read tools: remediation requests. Titles, messages and notes are user text, so they come back wrapped as untrusted."""
from typing import Literal

from limes.mcp import access
from limes.mcp.access import McpError
from limes.mcp.registry import tool
from limes.mcp.results import Cursor, Limit, RowId, Slug, iso, page, untrusted
from limes.mcp.tools.inventory import issue_title
from remediation import service
from remediation.models import RemediationRequest

THREAD_CAP = 20  # 20 messages + 20 events at 1000 characters stay far inside the result budget
ITEM_CAP = service.MAX_ISSUES
TEXT_CAP = 1000


def _summary(row):
    r = row['req']
    return {'id': r.id, 'title': untrusted(r.title, 300), 'status': r.status, 'due_date': r.due_date.isoformat() if r.due_date else None,
            'overdue': row['overdue'], 'open_issues': row['open'], 'total_issues': row['total'], 'impacted_assets': row['assets'],
            'categories': row['categories'], 'created_by': r.created_by.username if r.created_by else None,
            'assignee': r.assignee.username if r.assignee else None, 'external_recipients': len(r.external_emails),
            'created_at': iso(r.created_at), 'updated_at': iso(r.updated_at)}


@tool(title='List remediation requests')
def list_remediation_requests(caller, project: Slug, status: Literal['active', 'completed', 'archived'] = 'active',
                              cursor: Cursor = None, limit: Limit = 50):
    """The project's remediation requests of one status, most recently updated first, with open issue and impacted asset counts."""
    p = access.project_for(caller, project)
    qs = (RemediationRequest.objects.filter(project=p, status=status).select_related('created_by', 'assignee')
          .order_by('-updated_at', '-id'))
    chunk = page(qs, cursor, limit, lambda r: r)  # paginate the rows, then summarise the page in a fixed number of queries
    rows = service.summaries(chunk['items'])
    return {**chunk, 'items': [_summary(r) for r in rows]}


@tool(title='Remediation request detail')
def get_remediation_request(caller, project: Slug, request_id: RowId):
    """One remediation request with its issues, the potential score impact of fixing what is still open, the newest messages and the timeline."""
    p = access.project_for(caller, project)
    req = RemediationRequest.objects.filter(pk=request_id, project=p).select_related('created_by', 'assignee', 'project').first()
    if req is None:
        raise McpError('not_found', 'remediation request not found')
    items = req.items.select_related('issue__asset').order_by('issue__asset__value', 'issue__key', 'id')[:ITEM_CAP]
    messages = list(req.messages.select_related('author').order_by('-created_at', '-id')[:THREAD_CAP])[::-1]
    events = list(req.events.select_related('actor').order_by('-created_at', '-id')[:THREAD_CAP])[::-1]
    return {**_summary(service.summaries([req])[0]), 'message': untrusted(req.message, TEXT_CAP),
            'email_status': req.email_status, 'impact': service.impact(req),
            'issues': [{'issue_id': i.issue_id, 'asset': untrusted(i.issue.asset.value), 'key': untrusted(i.issue.key),
                        'title': issue_title(i.issue.source, i.issue.key), 'status': i.issue.status, 'severity': i.issue.severity}
                       for i in items],
            'messages': [{'author': m.author.username if m.author else None, 'text': untrusted(m.text, TEXT_CAP),
                          'created_at': iso(m.created_at)} for m in messages],
            'timeline': [{'kind': e.kind, 'text': untrusted(e.text, 300), 'actor': e.actor.username if e.actor else None,
                          'created_at': iso(e.created_at)} for e in events]}
