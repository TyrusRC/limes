"""Second layer: runs inside DRF, after DRF has parsed the request, and decides again from request.data / the query
string / the URL kwargs with the same policy as the middleware. Whatever the middleware thought the body said, this
sees what the view will act on."""
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.permissions import BasePermission

from memberships import access


class ProjectRolePermission(BasePermission):
    def has_permission(self, request, view):
        match = request._request.resolver_match
        name = match.view_name if match else ''
        namespaces = match.namespaces if match else []
        try:
            data = request.data if request.method not in ('GET', 'HEAD', 'OPTIONS') else None
            if data is not None and not len(data):
                data = None
            slugs = access.slugs_of(getattr(view, 'kwargs', {}) or {}, request.query_params, data, name, True)
        except access.Unreadable:
            raise NotFound('project not found')
        decided = getattr(request._request, 'limes_decided', None)
        if decided == (name, request.method, frozenset(slugs)):
            return True  # the middleware already decided this exact question: no second lookup
        verdict, _ = access.decide(request.user, name, namespaces, request.method, slugs)
        if verdict == access.NOT_FOUND:
            raise NotFound('project not found')
        if verdict == access.FORBIDDEN:
            raise PermissionDenied('your role in this project does not allow this')
        return True
