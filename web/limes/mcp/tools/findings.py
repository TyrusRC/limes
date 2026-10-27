"""Read tools: vulnerabilities, search and system status. Scan-derived text goes out only through untrusted()."""
import importlib.metadata
import logging
import threading
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
from limes.mcp.redact import domain_secrets, redact_log
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
        'template_id': untrusted(v.template_id), 'http_url': _url(v.http_url), 'asset_id': v.asset_id,
        'scan_id': v.scan_history_id, 'discovered_date': iso(v.discovered_date), 'open_status': v.open_status,
        'cvss_score': v.cvss_score})


def _url(url):
    return untrusted(url and redact_log(url))  # a scanned URL can carry credentials in its userinfo or query


def _redacted(text, secrets, cap=LOG_CAP):
    return untrusted(text and redact_log(text[:WINDOW], secrets), cap)


@tool(title='Vulnerability detail')
def get_vulnerability(caller, project: Slug, vulnerability_id: RowId):
    """One finding with description, impact, remediation, the redacted request and response, the first 20 extracted results, CVE and CWE ids, tags and references. Redaction is best-effort: treat output as potentially sensitive."""
    p = access.project_for(caller, project)
    v = _vulns(p).filter(pk=vulnerability_id).select_related('scan_history__domain').first()
    if v is None:
        raise McpError('not_found', 'vulnerability not found')
    secrets = domain_secrets(v.scan_history.domain)
    names = lambda qs: [untrusted(x.name) for x in qs.all().order_by('id')[:NAME_LIST_CAP]]
    plain = lambda values: [untrusted(x) for x in (values or [])[:NAME_LIST_CAP]]
    return {
        'id': v.id, 'name': untrusted(v.name), 'severity': v.severity, 'source': v.source and untrusted(v.source),
        'template_id': untrusted(v.template_id), 'http_url': _url(v.http_url), 'asset_id': v.asset_id,
        'scan_id': v.scan_history_id, 'discovered_date': iso(v.discovered_date), 'open_status': v.open_status,
        'cvss_score': v.cvss_score,
        'description': untrusted(v.description), 'impact': untrusted(v.impact), 'remediation': untrusted(v.remediation),
        'matcher_name': untrusted(v.matcher_name), 'cvss_metrics': untrusted(v.cvss_metrics),
        'curl_command': _redacted(v.curl_command, secrets, 2000), 'request': _redacted(v.request, secrets),
        'response': _redacted(v.response, secrets),
        'extracted_results': [_redacted(r, secrets, 2000) for r in (v.extracted_results or [])[:EXTRACTED_CAP]],
        'cve_ids': names(v.cve_ids), 'cwe_ids': plain(v.cwe_names), 'tags': plain(v.tag_names),
        'references': plain(v.reference_urls)}


@tool(title='Search')
def search(caller, project: Slug, query: Annotated[str, Field(min_length=2, max_length=200)],
           limit: Annotated[int, Field(ge=1, le=50)] = 20):
    """Case-insensitive substring search over the project's asset values and page titles, and issue keys and titles. The query is literal text, not a pattern."""
    # NOTE: icontains is a sequential scan inside the project (bounded by the project's size and limit+1 matches).
    # Upgrade path: a trigram index on asset value.
    p = access.project_for(caller, project)
    now = timezone.now()
    assets = list(Asset.objects.filter(project=p).exclude(scope_tier='candidate', confidence__lt=REVIEW)
                  .filter(Q(value__icontains=query) | Q(page_title__icontains=query)).prefetch_related('tags')
                  .order_by('value', 'id')[:limit + 1])
    needle = query.lower()
    titled = [k for k, c in CHECKS.items() if needle in c.title.lower()]
    issues = list(_with_extras(TrackedIssue.objects.filter(project=p).filter(
        Q(key__icontains=query) | Q(source='check', key__in=titled)), now).order_by('-severity', 'id')[:limit + 1])
    return {'assets': [asset_item(a) for a in assets[:limit]], 'issues': [_issue_item(i) for i in issues[:limit]],
            'truncated': len(assets) > limit or len(issues) > limit}


DEADLINE_S = 4  # the whole broker part of the status; kombu's own retry loop would otherwise hold a thread for minutes


def _broker_status():
    """Workers and queue depths over ONE bounded connection: ensure_connection gives up after a single try."""
    # transport_options: kombu's redis transport ignores connect_timeout and redis-py would wait on the OS default.
    conn = app.connection_for_read(connect_timeout=1, transport_options={'socket_connect_timeout': 1, 'socket_timeout': 2})
    try:
        conn.ensure_connection(max_retries=0, timeout=2)  # one attempt, no retry loop
        workers = sorted(app.control.inspect(timeout=1.0, connection=conn).ping() or {})
        client = conn.default_channel.client
        return workers, {q: client.llen(q) for q in (celery_routing.SCAN, celery_routing.IO, celery_routing.ORCHESTRATE)}
    finally:
        conn.release()


def _broker_with_deadline():
    # A daemon thread with a hard join: whatever the broker client does, the tool returns within DEADLINE_S.
    # The thread touches no database. NOTE: an abandoned thread ends when its own bounded attempt ends.
    box = {}

    def run():
        try:
            box['v'] = _broker_status()
        except Exception as e:  # the broker URL can sit in the message: log only the type
            logger.warning('MCP system status: broker unavailable (%s)', type(e).__name__)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(DEADLINE_S)
    if t.is_alive():
        logger.warning('MCP system status: broker did not answer within %ss', DEADLINE_S)
    return box.get('v', ([], None))


def _mcp_version():
    try:
        return importlib.metadata.version('mcp')
    except importlib.metadata.PackageNotFoundError:
        return None


@tool(title='System status', perm=PERM_MODIFY_SYSTEM_CONFIGURATIONS)
def get_system_status(caller):
    """Live workers, queue depths, scheduler heartbeat, scans in progress and software versions. System administrators only."""
    # NOTE: inspect ping blocks a worker thread up to 1 s; the whole broker part has a hard
    # deadline of DEADLINE_S (4 s). Worker names (celery@hostname) are
    # shown to this admin-only caller: accepted infrastructure disclosure.
    workers, queues = _broker_with_deadline()
    beat = {t.name: iso(t.last_run_at) for t in PeriodicTask.objects.filter(name__in=list(settings.CELERY_BEAT_SCHEDULE))}
    return {
        'workers': workers, 'queues': queues,
        'beat': beat, 'last_dispatch_tick': beat.get('dispatch-due-scans'),
        'scans_in_progress': ScanHistory.objects.filter(scan_status__in=IN_PROGRESS).count(),
        'versions': {'limes': settings.LIMES_CURRENT_VERSION, 'django': django_version(), 'mcp': _mcp_version()}}


def django_version():
    import django
    return django.get_version()
