"""Write tools. Opt-in three ways (server setting, read_write token, the user's own permission), all enforced by
registry.call_tool before these run. They call the services the UI calls and never copy their logic."""
from datetime import datetime, timezone as dt_timezone
from django.conf import settings
from typing import Annotated, Literal
from pydantic import Field
from api import asset_add
from limes.definitions import PERM_INITATE_SCANS_SUBSCANS, PERM_MODIFY_TARGETS
from limes import continuous, waivers
from limes.definitions import INITIATED_TASK, RUNNING_TASK
from limes.mcp import access
from limes.mcp.access import McpError
from limes.mcp.registry import tool
from limes.mcp.results import RowId, Slug, untrusted
from startScan.models import Asset, ScanHistory, TrackedIssue

# Appended to every agent-written reason or note so a reader of the UI can tell where the text came from.
VIA = ' (via MCP)'
def _text(value):
    value = value.strip()
    if not value:
        raise McpError('invalid', 'text must not be blank')
    return value + VIA


Text = Annotated[str, Field(min_length=1, max_length=4980)]  # 5000 less the suffix


def _asset(caller, project, asset_id):
    p = access.project_for(caller, project)
    asset = Asset.objects.filter(project=p, pk=asset_id).first()
    if asset is None:
        raise McpError('not_found', 'asset not found')
    return asset


def _issue(caller, project, issue_id):
    p = access.project_for(caller, project)
    issue = TrackedIssue.objects.filter(project=p, pk=issue_id).first()
    if issue is None:
        raise McpError('not_found', 'issue not found')
    return issue


def add_tier():
    t = settings.MCP_ADD_TIER
    return t if t in ('candidate', 'owned_host', 'owned_root') else 'candidate'  # never co_brand or a typo'd tier


@tool(title='Add assets', write=True, perm=PERM_MODIFY_TARGETS, destructive=True, open_world=True)
def add_assets(caller, project: Slug,
               entries: Annotated[list[Annotated[str, Field(min_length=1, max_length=300)]],
                                  Field(min_length=1, max_length=50)],
               reason: Text):
    """Add up to 50 explicit domains, hostnames, IPs, CIDR ranges or ASNs. They arrive as candidates for a human to
    confirm unless the operator set LIMES_MCP_ADD_TIER. Rows that already exist are never changed."""
    p = access.project_for(caller, project)
    # The tier is the operator's, not the agent's; existing rows are left alone (create_only).
    d = asset_add.add_assets(p, entries, add_tier(), _text(reason), caller.user, create_only=True)
    return {**d, 'warnings': [untrusted(w) for w in d['warnings']]}


@tool(title='Start ASM scan', write=True, perm=PERM_INITATE_SCANS_SUBSCANS, open_world=True)
def start_asm_scan(caller, project: Slug, asset_id: RowId):
    """Start an ASM scan of one owned root domain. This scans the real target on the internet."""
    asset = _asset(caller, project, asset_id)
    if ScanHistory.objects.filter(domain__project_id=asset.project_id, scan_status__in=(INITIATED_TASK, RUNNING_TASK)).exists():
        raise McpError('invalid', 'a scan is already in progress for this project; wait for it to finish')
    ok, message = continuous.start_asm_scan(asset, initiated_by_id=caller.user.id)
    if not ok:
        raise McpError('invalid', message)
    return {'message': message}


@tool(title='Set asset cadence', write=True, perm=PERM_INITATE_SCANS_SUBSCANS, destructive=True)
def set_asset_cadence(caller, project: Slug, asset_id: RowId,
                      cadence_tier: Literal['crown_jewel', 'standard', 'inactive', 'off']):
    """Set how often an owned asset is rediscovered or monitored. Replaces the current setting; 'off' stops monitoring."""
    asset = _asset(caller, project, asset_id)
    ok, message = continuous.set_cadence(asset, cadence_tier)
    if not ok:
        raise McpError('invalid', message)
    return {'message': message}


@tool(title='Waive issue', write=True, perm=PERM_MODIFY_TARGETS, destructive=True)
def waive_issue(caller, project: Slug, issue_id: RowId, kind: Literal['accepted_risk', 'false_positive'],
                reason: Text, expires_at: datetime | None = None):
    """Waive an issue as an accepted risk (default expiry 90 days) or a false positive. Replaces any active waiver."""
    issue = _issue(caller, project, issue_id)
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=dt_timezone.utc)
    try:
        w = waivers.create_waiver(issue, kind, _text(reason), caller.user, expires_at)
    except waivers.WaiverError as e:
        raise McpError('invalid', str(e)) from None
    return {'waiver_id': w.id, 'kind': w.kind, 'expires_at': w.expires_at.isoformat() if w.expires_at else None}


@tool(title='Revoke waiver', write=True, perm=PERM_MODIFY_TARGETS, destructive=True)
def revoke_waiver(caller, project: Slug, issue_id: RowId):
    """Revoke the issue's active waiver, so the issue counts against the score again."""
    issue = _issue(caller, project, issue_id)
    if not waivers.revoke_waiver(issue, caller.user):
        raise McpError('invalid', 'no active waiver')
    return {'revoked': True}


@tool(title='Add issue note', write=True, perm=PERM_MODIFY_TARGETS)
def add_issue_note(caller, project: Slug, issue_id: RowId, text: Text):
    """Add a note to an issue."""
    issue = _issue(caller, project, issue_id)
    try:
        n = waivers.add_note(issue, caller.user, _text(text))
    except waivers.WaiverError as e:
        raise McpError('invalid', str(e)) from None
    return {'note_id': n.id}
