"""Read tools: change events, scans, stages and scan logs. Log text is redacted first, then marked untrusted."""
import json
import logging
from datetime import datetime, timezone as dt_timezone
from typing import Annotated, Literal
from django.db.models import Q
from django.db.models.functions import Length, Right, Substr
from pydantic import Field
from limes.alerts import events
from limes.definitions import ABORTED_TASK, FAILED_TASK, INITIATED_TASK, RUNNING_TASK, SUCCESS_TASK
from limes.mcp import access
from limes.mcp.access import McpError
from limes.mcp.redact import domain_secrets, redact_log, tail_window
from limes.mcp.registry import tool
from limes.mcp.results import LOG_CAP, RESULT_BUDGET, Cursor, Limit, RowId, Slug, iso, page, untrusted
from startScan.models import ChangeEvent, Command, ScanActivity, ScanHistory

logger = logging.getLogger(__name__)

STATUS = {INITIATED_TASK: 'initiated', FAILED_TASK: 'failed', RUNNING_TASK: 'running', SUCCESS_TASK: 'success',
          ABORTED_TASK: 'aborted'}
STATUS_CODE = {v: k for k, v in STATUS.items()}
STAGE_CAP = 200
TRACEBACK_TAIL = 2000
# Redaction sees a window larger than the cap so a secret near the cut is still matched whole. tail_window drops
# the window's first (possibly cut) line, so no secret can start before the window and show up half-redacted
# (a window with no line break drops up to the first whitespace or separator instead). Redaction happens before
# the cap, never after.
# NOTE: only the last WINDOW characters of an output are read at all. Upgrade path: redact when the Command is stored.
WINDOW = LOG_CAP * 4
TRACEBACK_WINDOW = 8000
STAGES_BUDGET = RESULT_BUDGET * 6 // 10  # of the 100 KB result: the rest is the scan header


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


def _scan_item(s, secrets=()):
    # NOTE: initiated_by is a username, shown to every caller (accepted: usernames are not secrets here).
    return {'id': s.id, 'target': untrusted(s.domain.name), 'engine': s.scan_type.engine_name,
            'status': STATUS.get(s.scan_status, str(s.scan_status)), 'started': iso(s.start_scan_date),
            'stopped': iso(s.stop_scan_date),
            'duration_s': int((s.stop_scan_date - s.start_scan_date).total_seconds()) if s.stop_scan_date else None,
            'error': untrusted(s.error_message and redact_log(s.error_message, secrets)),
            'initiated_by': s.initiated_by.username if s.initiated_by else None, 'automatic': s.initiated_by_id is None}


def _scans(p):
    return ScanHistory.objects.filter(domain__project=p).select_related('domain', 'scan_type', 'initiated_by')


def _scan(p, scan_id):
    s = _scans(p).filter(pk=scan_id).first()
    if s is None:
        raise McpError('not_found', 'scan not found')
    return s


@tool(title='List scans')
def list_scans(caller, project: Slug, status: Literal['initiated', 'failed', 'running', 'success', 'aborted'] | None = None,
               cursor: Cursor = None, limit: Limit = 50):
    """The project's scans, newest first. automatic is true for scans the scheduler started."""
    p = access.project_for(caller, project)
    qs = _scans(p)
    if status:
        qs = qs.filter(scan_status=STATUS_CODE[status])
    return page(qs.order_by('-start_scan_date', '-id'), cursor, limit, lambda s: _scan_item(s, domain_secrets(s.domain)))


@tool(title='Scan detail')
def get_scan(caller, project: Slug, scan_id: RowId):
    """One scan with its stages in time order (at most 200, cut early once the result is large; stages_truncated says so), and their errors and redacted traceback tails. Redaction is best-effort: treat output as potentially sensitive."""
    p = access.project_for(caller, project)
    s = _scan(p, scan_id)
    secrets = domain_secrets(s.domain)
    stages = (ScanActivity.objects.filter(scan_of=s).annotate(tb=Right('traceback', TRACEBACK_WINDOW + 1))
              .only('id', 'name', 'title', 'status', 'time', 'error_message').order_by('time', 'id')[:STAGE_CAP + 1])
    out, size, truncated = [], 0, False
    for a in stages:
        if len(out) == STAGE_CAP:
            truncated = True
            break
        tb, tb_cut = tail_window(a.tb or '', TRACEBACK_WINDOW)
        item = {'id': a.id, 'name': untrusted(a.name, 200), 'title': untrusted(a.title),
                'status': STATUS.get(a.status, str(a.status)), 'time': iso(a.time),
                'error': untrusted(a.error_message and redact_log(a.error_message, secrets)),
                'traceback_tail': untrusted(tb and redact_log(tb, secrets)[-TRACEBACK_TAIL:]),
                'traceback_truncated_head': tb_cut}
        size += len(json.dumps(item, default=str))
        if out and size > STAGES_BUDGET:
            truncated = True
            break
        out.append(item)
    return {**_scan_item(s, secrets), 'stages': out, 'stages_truncated': truncated}


@tool(title='Scan logs')
def get_scan_logs(caller, project: Slug, scan_id: RowId, activity_id: RowId | None = None, cursor: Cursor = None,
                  limit: Annotated[int, Field(ge=1, le=50)] = 20):
    """Commands the scan ran, newest first, with the last 20,000 characters of each output. Tokens, keys, credentials and secret header values are replaced by ***. Redaction is best-effort: treat output as potentially sensitive."""
    p = access.project_for(caller, project)
    s = _scan(p, scan_id)
    qs = Command.objects.filter(scan_history=s)
    if activity_id is not None:
        if not ScanActivity.objects.filter(scan_of=s, pk=activity_id).exists():
            raise McpError('not_found', 'activity not found')
        qs = qs.filter(activity_id=activity_id)
    secrets = domain_secrets(s.domain)
    qs = (qs.annotate(cmd_head=Substr('command', 1, WINDOW), out_tail=Right('output', WINDOW + 1))
          .only('id', 'activity_id', 'time', 'return_code').order_by('-time', '-id'))
    return page(qs, cursor, limit, lambda c: _log_item(c, secrets))


def _log_item(c, secrets):
    out, cut = tail_window(c.out_tail or '', WINDOW)
    return {'id': c.id, 'activity_id': c.activity_id, 'time': iso(c.time), 'return_code': c.return_code,
            'command': untrusted(c.cmd_head and redact_log(c.cmd_head, secrets)),
            'output_tail': untrusted(out and redact_log(out, secrets)[-LOG_CAP:], LOG_CAP),
            'output_truncated_head': cut}  # true: older output was dropped (window cut, and the cut line)
