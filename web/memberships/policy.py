"""Which URL needs which project role. Names are resolver view names (namespace included).

Default: reading needs any role, anything that is not GET/HEAD/OPTIONS needs `standard`. The sets below are the
exceptions; tests/core/test_access_matrix.py fails if a name here no longer exists, so a rename cannot silently
drop a rule."""
SAFE_METHODS = frozenset({'GET', 'HEAD', 'OPTIONS'})

# Need an admin of the project: members and deleting the project.
ADMIN_ONLY = frozenset({
    'project_members', 'project_member_add', 'project_member_role', 'project_member_remove',
    'project_members_api', 'project_member_api',
    'delete_project',
})
# Instance-wide, not per project: scan engines (every project's scans run on them), notification webhooks, proxy, tool
# configuration (and the keys in it), user
# administration, and creating projects. Only a global admin (superuser or sys_admin); being admin of a project, even
# one you just created, never unlocks them.
GLOBAL_ONLY = frozenset({
    'notification_settings', 'proxy_settings', 'tool_settings', 'admin_interface', 'admin_interface_update',
    'api:getFileContents', 'api:create_project',
    'add_engine', 'update_engine', 'delete_engine_url',
})
# POST endpoints that only read (the body carries the question, nothing is stored), or only set the caller's own view
# (the portfolio picked in their session).
READ_ONLY_POST_OK = frozenset({'api:score_forecast', 'api:select_portfolio'})
# A user's own password and personal tokens: allowed to every role. A token is bounded by its owner's project role
# in the MCP server, so a read-only user's token cannot write.
SELF_SERVICE = frozenset({'profile', 'api_tokens', 'api:notification-mark-read', 'api:notification-mark-all-read',
                          'api:notification-clear-all'})
# GET endpoints that change state (kept for compatibility): treated like a POST.
MUTATING_GET = frozenset()

# Writes that name no project are refused unless the route is here: sign-in and out, the first-project onboarding
# (its view refuses once a project exists), creating a project (GLOBAL_ONLY), and a user's own notification read state.
# Everything else that writes must say which project it is about. Namespaces listed are exempt (Django's own admin
# checks its own permissions).
NO_PROJECT_WRITES = frozenset({'login', 'logout', 'sso_login', 'sso_callback', 'onboarding', 'api:create_project',
                               'api:notification-mark-read', 'api:notification-mark-all-read',
                               'api:notification-clear-all'})
NO_PROJECT_WRITE_NAMESPACES = frozenset({'admin'})


# Views whose project is not in the URL slug or a `project` parameter. The resolver gets the parsed body (a dict or
# QueryDict, or None) and the URL kwargs and returns the project slugs the request touches, or None when it cannot
# tell (refused).
def _scan_projects(data, view_kwargs):
    from startScan.models import ScanHistory
    try:
        raw = data.getlist('scan_ids') if hasattr(data, 'getlist') else (data or {}).get('scan_ids') or []
        if isinstance(raw, (str, bytes, dict)) or not isinstance(raw, (list, tuple)):
            return None
        ids = [int(i) for i in raw]
    except (ValueError, TypeError, AttributeError, OverflowError):
        return None
    return set(ScanHistory.objects.filter(id__in=ids).values_list('domain__project__slug', flat=True))


def _project_by_id(data, view_kwargs):
    from dashboard.models import Project
    return set(Project.objects.filter(id=view_kwargs.get('id')).values_list('slug', flat=True))


EXTRA_RESOLVERS = {'api:stop_scan': _scan_projects, 'delete_project': _project_by_id}
