"""The access decision, in one function used by both layers: the middleware (from its own reading of the request) and
the DRF permission (from DRF's parse of the same request). If the two ever read a request differently, the DRF layer
still sees what the view will act on."""
from collections.abc import Mapping

from memberships import policy, rules
from memberships.models import ADMIN, READ_ONLY, STANDARD

OK, NOT_FOUND, FORBIDDEN = 'allowed', 'not_found', 'forbidden'
PARAMS = ('project', 'project_slug')


class Unreadable(Exception):
    """A request whose project cannot be read: refused as not found rather than guessed at."""


def needed_role(view_name, method):
    if view_name in policy.ADMIN_ONLY:
        return ADMIN
    if view_name in policy.SELF_SERVICE or view_name in policy.READ_ONLY_POST_OK:
        return READ_ONLY
    if method in policy.SAFE_METHODS and view_name not in policy.MUTATING_GET:
        return READ_ONLY
    return STANDARD


def _take(source, found):
    for key in PARAMS:
        if hasattr(source, 'getlist'):
            found.extend(source.getlist(key))
        elif key in source:
            found.append(source[key])


def slugs_of(view_kwargs, query, data, view_name, is_api):
    """The set of project slugs a request names. `query` is the query string mapping, `data` the parsed body (dict,
    QueryDict, or None for no body). Anything that is not plain text raises Unreadable."""
    found = []
    if 'slug' in view_kwargs:
        found.append(view_kwargs['slug'])
    _take(query, found)
    if data is not None:
        if not isinstance(data, Mapping):
            raise Unreadable
        _take(data, found)
    extra = policy.EXTRA_RESOLVERS.get(view_name)
    if extra:
        got = extra(data, view_kwargs)
        if got is None:
            raise Unreadable
        found.extend(got)
    if not all(isinstance(s, str) for s in found):
        raise Unreadable
    return {s for s in found if s}


def decide(user, view_name, namespaces, method, slugs):
    """allowed / not_found / forbidden."""
    if slugs:
        roles = rules.roles_by_slug(user, slugs)
        if set(roles) != slugs:
            return NOT_FOUND, {}
    else:
        roles = {}
        if (method not in policy.SAFE_METHODS and view_name not in policy.NO_PROJECT_WRITES
                and not (set(namespaces) & policy.NO_PROJECT_WRITE_NAMESPACES)):
            return FORBIDDEN, roles  # a write that names no project
    if view_name in policy.GLOBAL_ONLY and not rules.is_global_admin(user):
        return FORBIDDEN, roles
    need = needed_role(view_name, method)
    if not all(rules.at_least(r, need) for r in roles.values()):
        return FORBIDDEN, roles
    return OK, roles
