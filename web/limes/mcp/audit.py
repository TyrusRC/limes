"""MCP call log: truncated, secret-scrubbed argument summaries, and the 90-day retention purge."""
import json
import logging
import re
from datetime import timedelta
from django.utils import timezone
from dashboard.models import McpCallLog
from limes.celery import app
from limes.continuous import tick_lock

logger = logging.getLogger(__name__)

SECRET_KEY_RE = re.compile(r'(?i)(secret|token|password|passwd|api_?key|authorization|cookie)')
ARGS_CAP = 1024
RETENTION = timedelta(days=90)


def _scrub(v):
    if isinstance(v, dict):
        return {k: '***' if SECRET_KEY_RE.search(str(k)) else _scrub(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_scrub(x) for x in v]
    return v


def scrub_args(args):
    return json.dumps(_scrub(args), sort_keys=True, default=str)[:ARGS_CAP]


def log_call(*, token_pk, token_public_id, user_id, tool, project, args, outcome, write, duration_ms):
    # NOTE: a failed audit insert does not fail the call; upgrade path: write the row in the same transaction as the write tool's change.
    try:
        McpCallLog.objects.create(token_id=token_pk, token_public_id=token_public_id, user_id=user_id, tool=tool,
                                  project=project, arguments=scrub_args(args), outcome=outcome, write=write,
                                  duration_ms=duration_ms)
    except Exception:
        logger.exception('mcp audit insert failed (tool=%s token=%s)', tool, token_public_id)


@app.task(name='purge_mcp_logs', bind=False)
def purge_mcp_logs():
    with tick_lock('purge_mcp_logs') as got:
        if not got:
            return {'deleted': 0, 'reason': 'locked'}
        deleted, _ = McpCallLog.objects.filter(created_at__lt=timezone.now() - RETENTION).delete()
        return {'deleted': deleted}
