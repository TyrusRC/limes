"""Read tools: vulnerabilities, search and system status. Scan-derived text goes out only through untrusted()."""
import importlib.metadata
import logging
from typing import Annotated, Literal
from django.conf import settings
from django.db.models import Q
from django.utils import timezone
from django_celery_beat.models import PeriodicTask
from pydantic import Field
from limes import celery_routing
from limes.celery import app
from limes.checks.catalogue import CHECKS
from limes.continuous import IN_PROGRESS
from limes.definitions import PERM_MODIFY_SYSTEM_CONFIGURATIONS
from limes.mcp import access
from limes.mcp.access import McpError
from limes.mcp.redact import redact_log
from limes.mcp.registry import tool
from limes.mcp.results import LOG_CAP, Cursor, Limit, RowId, Slug, iso, page, untrusted
from limes.mcp.tools.inventory import asset_item
from limes.mcp.tools.issues import _issue_item, _with_extras
from limes.tasks.attribution import REVIEW
from startScan.models import Asset, ScanHistory, TrackedIssue, Vulnerability

logger = logging.getLogger(__name__)

EXTRACTED_CAP = 20
NAME_LIST_CAP = 50
WINDOW = LOG_CAP * 4


def _vulns(p):
    return Vulnerability.objects.filter(scan_history__domain__project=p)


@tool(title='List vulnerabilities')
def list_vulnerabilities(caller, project: Slug, severity: Literal[-1, 0, 1, 2, 3, 4] | None = None, open_only: bool = True,
                         asset_id: RowId | None = None, scan_id: RowId | None = None, cursor: Cursor = None,
                         limit: Limit = 50):
    """Scanner findings, worst first. severity 4 is critical, 0 info, -1 unknown. open_only (default) hides fixed ones."""
    p = access.project_for(caller, project)
    qs = _vulns(p)
    if severity is not None:
        qs = qs.filter(severity=severity)
    if open_only:
        qs = qs.filter(open_status=True)
    if asset_id is not None:
        qs = qs.filter(asset_id=asset_id)
    if scan_id is not None:
        qs = qs.filter(scan_history_id=scan_id)
    return page(qs.order_by('-severity', '-discovered_date', 'id'), cursor, limit, lambda v: {
        'id': v.id, 'name': untrusted(v.name), 'severity': v.severity, 'source': v.source and untrusted(v.source),
        'template_id': untrusted(v.template_id), 'http_url': untrusted(v.http_url), 'asset_id': v.asset_id,
        'scan_id': v.scan_history_id, 'discovered_date': iso(v.discovered_date), 'open_status': v.open_status,
        'cvss_score': v.cvss_score})


def _redacted(text, cap=LOG_CAP):
    return untrusted(text and redact_log(text[:WINDOW]), cap)


@tool(title='Vulnerability detail')
def get_vulnerability(caller, project: Slug, vulnerability_id: RowId):
    """One finding with description, impact, remediation, the redacted request and response, the first 20 extracted results, CVE and CWE ids, tags and references."""
    p = access.project_for(caller, project)
    v = _vulns(p).filter(pk=vulnerability_id).first()
    if v is None:
        raise McpError('not_found', 'vulnerability not found')
    names = lambda qs, f='name': [untrusted(getattr(x, f)) for x in qs.all().order_by('id')[:NAME_LIST_CAP]]
    return {
        'id': v.id, 'name': untrusted(v.name), 'severity': v.severity, 'source': v.source and untrusted(v.source),
        'template_id': untrusted(v.template_id), 'http_url': untrusted(v.http_url), 'asset_id': v.asset_id,
        'scan_id': v.scan_history_id, 'discovered_date': iso(v.discovered_date), 'open_status': v.open_status,
        'cvss_score': v.cvss_score,
        'description': untrusted(v.description), 'impact': untrusted(v.impact), 'remediation': untrusted(v.remediation),
        'matcher_name': untrusted(v.matcher_name), 'cvss_metrics': untrusted(v.cvss_metrics),
        'curl_command': _redacted(v.curl_command, 2000), 'request': _redacted(v.request), 'response': _redacted(v.response),
        'extracted_results': [untrusted(r) for r in (v.extracted_results or [])[:EXTRACTED_CAP]],
        'cve_ids': names(v.cve_ids), 'cwe_ids': names(v.cwe_ids), 'tags': names(v.tags),
        'references': names(v.references, 'url')}


@tool(title='Search')
def search(caller, project: Slug, query: Annotated[str, Field(min_length=2, max_length=200)],
           limit: Annotated[int, Field(ge=1, le=50)] = 20):
    """Case-insensitive substring search over the project's asset values and page titles, and issue keys and titles. The query is literal text, not a pattern."""
    # NOTE: icontains is a sequential scan inside the project (bounded by the project's size and limit+1 matches).
    # Upgrade path: a trigram index on asset value.
    p = access.project_for(caller, project)
    now = timezone.now()
    assets = list(Asset.objects.filter(project=p).exclude(scope_tier='candidate', confidence__lt=REVIEW)
                  .filter(Q(value__icontains=query) | Q(page_title__icontains=query)).order_by('value', 'id')[:limit + 1])
    needle = query.lower()
    titled = [k for k, c in CHECKS.items() if needle in c.title.lower()]
    issues = list(_with_extras(TrackedIssue.objects.filter(project=p).filter(
        Q(key__icontains=query) | Q(source='check', key__in=titled)), now).order_by('-severity', 'id')[:limit + 1])
    return {'assets': [asset_item(a) for a in assets[:limit]], 'issues': [_issue_item(i) for i in issues[:limit]],
            'truncated': len(assets) > limit or len(issues) > limit}


def _safely(what, fn, default):
    try:
        return fn()
    except Exception as e:  # the broker URL can sit in the message: log only the type
        logger.warning('MCP system status: %s unavailable (%s)', what, type(e).__name__)
        return default


def _queues():
    conn = app.connection_for_read()
    try:
        client = conn.default_channel.client
        return {q: client.llen(q) for q in (celery_routing.SCAN, celery_routing.IO, celery_routing.ORCHESTRATE)}
    finally:
        conn.release()


def _mcp_version():
    try:
        return importlib.metadata.version('mcp')
    except importlib.metadata.PackageNotFoundError:
        return None


@tool(title='System status', perm=PERM_MODIFY_SYSTEM_CONFIGURATIONS)
def get_system_status(caller):
    """Live workers, queue depths, scheduler heartbeat, scans in progress and software versions. System administrators only."""
    # NOTE: inspect ping blocks a worker thread up to 1 s.
    beat = {t.name: iso(t.last_run_at) for t in PeriodicTask.objects.filter(name__in=list(settings.CELERY_BEAT_SCHEDULE))}
    return {
        'workers': _safely('workers', lambda: sorted(app.control.inspect(timeout=1.0).ping() or {}), []),
        'queues': _safely('queues', _queues, None),
        'beat': beat, 'last_dispatch_tick': beat.get('dispatch-due-scans'),
        'scans_in_progress': ScanHistory.objects.filter(scan_status__in=IN_PROGRESS).count(),
        'versions': {'limes': settings.LIMES_CURRENT_VERSION, 'django': django_version(), 'mcp': _mcp_version()}}


def django_version():
    import django
    return django.get_version()
