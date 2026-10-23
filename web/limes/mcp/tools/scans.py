"""Read tools: change events, scans, stages and scan logs. Log text is redacted first, then marked untrusted."""
import json
import logging
from datetime import datetime, timezone as dt_timezone
from typing import Annotated, Literal
from django.db.models import Count, Q
from django.db.models.functions import Right, Substr
from pydantic import Field
from limes import identity
from limes.alerts import events
from limes.definitions import ABORTED_TASK, FAILED_TASK, INITIATED_TASK, RUNNING_TASK, SUCCESS_TASK
from limes.mcp import access
from limes.mcp.access import McpError
from limes.mcp.redact import redact_log
from limes.mcp.registry import tool
from limes.mcp.results import LOG_CAP, Cursor, Limit, RowId, Slug, iso, page, untrusted
from startScan.models import ChangeEvent, Command, ScanActivity, ScanHistory, SubScan

logger = logging.getLogger(__name__)

STATUS = {INITIATED_TASK: 'initiated', FAILED_TASK: 'failed', RUNNING_TASK: 'running', SUCCESS_TASK: 'success',
          ABORTED_TASK: 'aborted'}
STATUS_CODE = {v: k for k, v in STATUS.items()}
STAGE_CAP = 200
TRACEBACK_TAIL = 2000
# Redaction sees a window larger than the cap so a secret near the cut is still matched whole.
# NOTE: a secret that straddles the start of that window is cut; upgrade path: redact at write time.
WINDOW = LOG_CAP * 4


@tool(title='List changes')
def list_changes(caller, project: Slug, kinds: list[Literal[events.KINDS]] | None = None, since: datetime | None = None,
                 cursor: Cursor = None, limit: Limit = 50):
    """The project's change events (new or fixed issues, score changes, missing assets...), newest first. since is an ISO time; without a zone it is UTC."""
    p = access.project_for(caller, project)
    qs = ChangeEvent.objects.filter(project=p).select_related('asset')
    if kinds:
        qs = qs.filter(kind__in=kinds)
    if since:
        qs = qs.filter(created_at__gte=since if since.tzinfo else since.replace(tzinfo=dt_timezone.utc))
    return page(qs.order_by('-created_at', '-id'), cursor, limit, lambda e: {
        'id': e.id, 'kind': e.kind, 'severity': e.severity, 'asset_id': e.asset_id,
        'asset': untrusted(e.asset.value) if e.asset else None, 'title': untrusted(e.title),
        'detail': untrusted(json.dumps(e.detail, default=str)), 'created_at': iso(e.created_at)})


def _scan_item(s):
    return {'id': s.id, 'target': untrusted(s.domain.name), 'engine': s.scan_type.engine_name,
            'status': STATUS.get(s.scan_status, str(s.scan_status)), 'started': iso(s.start_scan_date),
            'stopped': iso(s.stop_scan_date),
            'duration_s': int((s.stop_scan_date - s.start_scan_date).total_seconds()) if s.stop_scan_date else None,
            'error': untrusted(s.error_message and redact_log(s.error_message)),
            'initiated_by': s.initiated_by.username if s.initiated_by else None, 'automatic': s.initiated_by_id is None}


def _scans(p):
    return ScanHistory.objects.filter(domain__project=p).select_related('domain', 'scan_type', 'initiated_by')


def _scan(p, scan_id):
    s = _scans(p).filter(pk=scan_id).first()
    if s is None:
        raise McpError('not_found', 'scan not found')
    return s


def _secrets(domain):
    """The scan target's secret header values. A value that cannot be decrypted yields no secrets, never an error."""
    try:
        return identity.redaction_secrets(identity.ScanIdentity.for_domain(domain))
    except Exception as e:
        logger.warning('MCP log redaction: could not read the scan identity (%s)', type(e).__name__)
        return []


@tool(title='List scans')
def list_scans(caller, project: Slug, status: Literal['initiated', 'failed', 'running', 'success', 'aborted'] | None = None,
               cursor: Cursor = None, limit: Limit = 50):
    """The project's scans, newest first. automatic is true for scans the scheduler started."""
    p = access.project_for(caller, project)
    qs = _scans(p)
    if status:
        qs = qs.filter(scan_status=STATUS_CODE[status])
    return page(qs.order_by('-start_scan_date', '-id'), cursor, limit, _scan_item)


@tool(title='Scan detail')
def get_scan(caller, project: Slug, scan_id: RowId):
    """One scan with its stages in time order (at most 200, with errors and the redacted traceback tail) and its subscan counts by status."""
    p = access.project_for(caller, project)
    s = _scan(p, scan_id)
    secrets = _secrets(s.domain)
    s.error_message = s.error_message and redact_log(s.error_message, secrets)
    stages = ScanActivity.objects.filter(scan_of=s).order_by('time', 'id')
    counts = SubScan.objects.filter(scan_history=s).values('status').annotate(n=Count('id'))
    return {**_scan_item(s),
            'stages': [{'id': a.id, 'name': a.name, 'title': untrusted(a.title), 'status': STATUS.get(a.status, str(a.status)),
                        'time': iso(a.time), 'error': untrusted(a.error_message and redact_log(a.error_message, secrets)),
                        'traceback_tail': untrusted(a.traceback and redact_log(a.traceback[-WINDOW:], secrets)[-TRACEBACK_TAIL:])}
                       for a in stages[:STAGE_CAP]],
            'subscans': {STATUS.get(r['status'], str(r['status'])): r['n'] for r in counts}}


@tool(title='Scan logs')
def get_scan_logs(caller, project: Slug, scan_id: RowId, activity_id: RowId | None = None, cursor: Cursor = None,
                  limit: Annotated[int, Field(ge=1, le=50)] = 20):
    """Commands the scan ran, newest first, with the last 20,000 characters of each output. Tokens, keys, credentials and secret header values are replaced by ***."""
    p = access.project_for(caller, project)
    s = _scan(p, scan_id)
    qs = Command.objects.filter(scan_history=s)
    if activity_id is not None:
        if not ScanActivity.objects.filter(scan_of=s, pk=activity_id).exists():
            raise McpError('not_found', 'activity not found')
        qs = qs.filter(activity_id=activity_id)
    secrets = _secrets(s.domain)
    qs = (qs.annotate(cmd_head=Substr('command', 1, WINDOW), out_tail=Right('output', WINDOW))
          .only('id', 'activity_id', 'time', 'return_code').order_by('-time', '-id'))
    return page(qs, cursor, limit, lambda c: {
        'id': c.id, 'activity_id': c.activity_id, 'time': iso(c.time), 'return_code': c.return_code,
        'command': untrusted(c.cmd_head and redact_log(c.cmd_head, secrets)),
        'output_tail': untrusted(c.out_tail and redact_log(c.out_tail, secrets)[-LOG_CAP:], LOG_CAP)})
