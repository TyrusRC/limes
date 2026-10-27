"""The first of two layers of project access (the second is memberships.drf, which re-decides from DRF's own parse).

Every request is resolved to the project slugs it touches: the `slug` URL argument, the `project` / `project_slug`
parameters (query string and, for API writes, the body) and the few views that name a project indirectly. Each must
exist and be visible to the user, otherwise the answer is a 404 identical for "no such project" and "not yours". Then
the user's role must allow the method and the URL (memberships.policy), and a write that names no project is refused
unless its route is on the allowlist.

API write bodies are read here with the strictest reading: the media type and charset are normalised to lower case
(and the request rewritten to match, so Django and DRF see the same thing), only JSON, urlencoded forms and multipart
are accepted, the charset must be absent or utf-8, JSON must be strict utf-8 and an object. Anything else is refused
before a view sees it.

Runs after AuthenticationMiddleware and the login-required middleware."""
import json

from django.core.exceptions import PermissionDenied, RequestDataTooBig, SuspiciousOperation
from django.http import Http404, JsonResponse

from memberships import access

JSON = 'application/json'
FORMS = ('application/x-www-form-urlencoded', 'multipart/form-data')


class Unsupported(Exception):
    pass


class BadBody(Exception):
    pass


def _bad_constant(name):
    raise ValueError(name)  # DRF's JSON parser refuses NaN and Infinity; so does this


def normalise_content_type(request):
    """Lower-case the media type and the parameter names (and the charset value), keep other values (a multipart
    boundary is case-sensitive), and make Django re-read it. Returns (media type, charset or '')."""
    raw = request.META.get('CONTENT_TYPE', '') or ''
    head, *params = [p.strip() for p in raw.split(';')]
    media, charset, out = head.lower(), '', []
    for p in params:
        name, _, value = p.partition('=')
        name = name.strip().lower()
        value = value.strip()
        if name == 'charset':
            charset = value.strip('"').lower()
            value = charset
        out.append(f'{name}={value}')
    request.META['CONTENT_TYPE'] = '; '.join([media] + out) if media else ''
    request._set_content_type_params(request.META)
    return media, charset


def read_body(request):
    """The parsed body of an API write: a dict / QueryDict, or None when there is no body. Raises Unsupported or
    access.Unreadable."""
    media, charset = normalise_content_type(request)
    try:
        body = request.body
    except (RequestDataTooBig, SuspiciousOperation):
        raise access.Unreadable
    if not body:
        return None
    if charset not in ('', 'utf-8'):
        raise Unsupported
    if media == JSON:
        try:
            data = json.loads(body.decode('utf-8'), parse_constant=_bad_constant)
        except (ValueError, RecursionError):  # includes UnicodeDecodeError and JSONDecodeError
            raise BadBody
        if not isinstance(data, dict):
            raise BadBody
        return data
    if media in FORMS:
        return request.POST
    raise Unsupported


class ProjectAccessMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    @staticmethod
    def _deny(request, is_api, verdict, status=None):
        request.limes_access = verdict
        if verdict == access.NOT_FOUND:
            if is_api:
                return JsonResponse({'status': False, 'message': 'project not found'}, status=404)
            raise Http404('project not found')
        if is_api:
            return JsonResponse({'status': False, 'message': 'your role in this project does not allow this'}, status=403)
        raise PermissionDenied

    def process_view(self, request, view_func, view_args, view_kwargs):
        match = request.resolver_match
        name = match.view_name if match else ''
        namespaces = match.namespaces if match else []
        is_api = 'api' in namespaces
        data = None
        try:
            if is_api and request.method not in ('GET', 'HEAD', 'OPTIONS'):
                data = read_body(request)
            slugs = access.slugs_of(view_kwargs, request.GET, data, name, is_api)
        except access.Unreadable:
            return self._deny(request, is_api, access.NOT_FOUND)
        except BadBody:
            request.limes_access = 'bad_body'
            return JsonResponse({'status': False, 'message': 'the request body is not a valid JSON object'}, status=400)
        except Unsupported:
            request.limes_access = 'unsupported'
            return JsonResponse({'status': False, 'message': 'unsupported content type'}, status=415)
        verdict, roles = access.decide(request.user, name, namespaces, request.method, slugs)
        if verdict != access.OK:
            return self._deny(request, is_api, verdict)
        request.limes_roles = roles
        request.limes_decided = (name, request.method, frozenset(slugs))  # the DRF layer reuses this for the same inputs
        request.limes_access = 'allowed' if slugs else 'unscoped'  # read by the tests: which layer answered
        return None
