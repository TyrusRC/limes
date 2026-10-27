"""The one choke point for project access.

Every request is resolved to the project slugs it touches: the `slug` URL argument, the `project` / `project_slug`
parameters of the REST API (query string, form body or JSON body) and the few views that name a project indirectly
(memberships.policy.EXTRA_RESOLVERS). Each of them must exist and be visible to the user, otherwise the answer is a
404 that is identical for "no such project" and "not yours". Then the user's role in each project must allow the
method and the URL (memberships.policy). Views carry no checks of their own for this.

Runs after AuthenticationMiddleware and the login-required middleware."""
import json
from json import JSONDecodeError

from django.core.exceptions import PermissionDenied, RequestDataTooBig, SuspiciousOperation
from django.http import Http404, JsonResponse

from memberships import policy, rules
from memberships.models import ADMIN, READ_ONLY, STANDARD

PARAMS = ('project', 'project_slug')


class Unreadable(Exception):
    """A request whose project cannot be read: refused as not found rather than guessed at."""


def _values(source, out):
    for key in PARAMS:
        if hasattr(source, 'getlist'):
            out.extend(source.getlist(key))
        elif key in source:
            out.append(source[key])


def candidate_slugs(request, view_kwargs, view_name):
    """The set of slugs the request names, or raises Unreadable."""
    found = []
    if 'slug' in view_kwargs:
        found.append(view_kwargs['slug'])
    _values(request.GET, found)
    if request.path_info.startswith('/api/'):
        ctype = (request.content_type or '').lower()
        if request.method not in policy.SAFE_METHODS:
            if ctype in ('application/x-www-form-urlencoded', 'multipart/form-data'):
                _values(request.POST, found)
            else:  # DRF parses anything that is not a form as JSON, so read the body the same way
                try:
                    body = request.body
                except (RequestDataTooBig, SuspiciousOperation):
                    raise Unreadable
                if body:
                    try:
                        data = json.loads(body)
                    except (JSONDecodeError, UnicodeDecodeError, RecursionError):
                        data = None  # the view answers 400; it has no project to read from it either
                    if isinstance(data, dict):
                        _values(data, found)
    extra = policy.EXTRA_RESOLVERS.get(view_name)
    if extra:
        got = extra(request, view_kwargs)
        if got is None:
            raise Unreadable
        found.extend(got)
    if not all(isinstance(s, str) for s in found):
        raise Unreadable
    return {s for s in found if s}


def needed_role(view_name, method):
    if view_name in policy.ADMIN_ONLY:
        return ADMIN
    if view_name in policy.SELF_SERVICE:
        return READ_ONLY
    if view_name in policy.READ_ONLY_POST_OK:
        return READ_ONLY
    if method in policy.SAFE_METHODS and view_name not in policy.MUTATING_GET:
        return READ_ONLY
    return STANDARD


class ProjectAccessMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    @staticmethod
    def _not_found(request):
        if request.path_info.startswith('/api/'):
            return JsonResponse({'status': False, 'message': 'project not found'}, status=404)
        raise Http404('project not found')

    @staticmethod
    def _forbidden(request):
        if request.path_info.startswith('/api/'):
            return JsonResponse({'status': False, 'message': 'your role in this project does not allow this'}, status=403)
        raise PermissionDenied

    def process_view(self, request, view_func, view_args, view_kwargs):
        match = request.resolver_match
        name = match.view_name if match else ''
        try:
            slugs = candidate_slugs(request, view_kwargs, name)
        except Unreadable:
            request.limes_access = 'not_found'
            return self._not_found(request)
        user = request.user
        roles = {}
        if slugs:
            roles = rules.roles_by_slug(user, slugs)
            if set(roles) != slugs:
                request.limes_access = 'not_found'
                return self._not_found(request)
            need = needed_role(name, request.method)
            if not all(rules.at_least(r, need) for r in roles.values()):
                request.limes_access = 'forbidden'
                return self._forbidden(request)
        if name in policy.ANY_ADMIN and not rules.is_any_admin(user):
            request.limes_access = 'forbidden'
            return self._forbidden(request)
        request.limes_roles = roles if slugs else {}  # the page chrome reads it: no second lookup
        request.limes_access = 'allowed' if slugs else 'unscoped'  # read by the tests: which layer answered
        return None
