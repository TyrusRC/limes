"""Which URL needs which project role. Names are resolver view names (namespace included).

Default: reading needs any role, anything that is not GET/HEAD/OPTIONS needs `standard`. The sets below are the
exceptions; tests/core/test_access_matrix.py fails if a name here no longer exists, so a rename cannot silently
drop a rule."""
SAFE_METHODS = frozenset({'GET', 'HEAD', 'OPTIONS'})

# Need an admin of the project: members, integrations and secrets (notification webhooks, proxy, tool configs and the
# API keys in them), user administration, SSO, deleting the project.
ADMIN_ONLY = frozenset({
    'project_members', 'project_member_add', 'project_member_role', 'project_member_remove',
    'project_members_api', 'project_member_api',
    'notification_settings', 'proxy_settings', 'tool_settings',
    'admin_interface', 'admin_interface_update',
    'delete_project',
    'api:getFileContents',
})
# POST endpoints that only read (the body carries the question, nothing is stored).
READ_ONLY_POST_OK = frozenset({'api:score_forecast'})
# A user's own password and personal tokens: allowed to every role. A token is bounded by its owner's project role
# in the MCP server, so a read-only user's token cannot write.
SELF_SERVICE = frozenset({'profile', 'api_tokens'})
# GET endpoints that change state (kept for compatibility): treated like a POST.
MUTATING_GET = frozenset({'api:create_project'})

# Views whose project is not in the URL slug or a `project` parameter. The resolver gets the request and returns the
# project slugs it touches; every one must be visible to the user.
def _scan_projects(request):
    from startScan.models import ScanHistory
    import json
    try:
        ids = [int(i) for i in (json.loads(request.body or b'{}').get('scan_ids') or [])]
    except (ValueError, TypeError, AttributeError):
        return None
    return set(ScanHistory.objects.filter(id__in=ids).values_list('domain__project__slug', flat=True))


def _project_by_id(request, view_kwargs):
    from dashboard.models import Project
    return set(Project.objects.filter(id=view_kwargs.get('id')).values_list('slug', flat=True))


EXTRA_RESOLVERS = {'api:stop_scan': lambda request, kw: _scan_projects(request),
                   'delete_project': _project_by_id}
# Not tied to a project: the user needs to be an admin of at least one (or global).
ANY_ADMIN = frozenset({'api:getFileContents'})
