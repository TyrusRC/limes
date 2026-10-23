"""Per-call authority. Nothing here is cached across calls: token, user and role are re-read every time."""
import logging
import time
from dataclasses import dataclass
from django.conf import settings
from django.utils import timezone
from django_redis import get_redis_connection
from redis.exceptions import RedisError
from rolepermissions.checkers import has_permission
from dashboard.models import ApiToken, Project
from limes.mcp import ratelimit, results

logger = logging.getLogger(__name__)
_last_warn = 0.0


class McpError(Exception):
    def __init__(self, code, message, retry_after_seconds=None):
        super().__init__(message)
        self.code, self.message, self.retry_after_seconds = code, message, retry_after_seconds

    def envelope(self):
        return results.error(self.code, self.message, self.retry_after_seconds)


@dataclass(frozen=True)
class Caller:
    token: ApiToken
    user: object


def resolve_caller(token_pk, now=None):
    tok = ApiToken.objects.select_related('user').filter(pk=token_pk).first() if token_pk is not None else None
    if tok is None or not tok.usable(now or timezone.now()) or not tok.user.is_active:
        raise McpError('unauthorized', 'token is not valid')
    return Caller(tok, tok.user)


def project_for(caller, slug):
    """The only slug -> Project lookup tools may use. Today: the project exists and the caller is an active user
    (Limes has no per-user project ACL). A future ACL lands here, with the same message for unknown and forbidden."""
    project = Project.objects.filter(slug=slug).first()
    if project is None or not caller.user.is_active:
        raise McpError('not_found', 'project not found')
    return project


def visible_projects(caller):
    """The projects project_for would accept, for listings. A future ACL changes this and project_for together."""
    return Project.objects.filter(pk__in=[]) if not caller.user.is_active else Project.objects.all()


def require(caller, perm):
    if not has_permission(caller.user, perm):
        raise McpError('forbidden', 'your role does not allow this')


def require_write(caller, perm):
    if not settings.MCP_WRITES_ENABLED:
        raise McpError('writes_disabled', 'writes are disabled on this server')
    if caller.token.scope != 'read_write':
        raise McpError('forbidden', 'this token is read-only')
    require(caller, perm)


def check_rate(caller, write):
    # NOTE: buckets are per token, so a user with N tokens gets N times the limit. Upgrade path: key the bucket by user id.
    global _last_warn
    tid = caller.token.token_id
    buckets = [('call', settings.MCP_RATE_PER_MIN)] + ([('write', settings.MCP_WRITE_RATE_PER_MIN)] if write else [])
    try:
        conn = get_redis_connection('default')
        for name, cap in buckets:
            wait = ratelimit.take(f'limes:mcp:rate:{tid}:{name}', cap, 60, conn=conn)
            if wait:
                raise McpError('rate_limited', 'too many calls', retry_after_seconds=wait)
    except RedisError as e:  # fail closed: no limiter, no calls
        if time.monotonic() - _last_warn > 60 or _last_warn == 0.0:  # NOTE: throttled per process, once a minute
            _last_warn = time.monotonic()
            logger.warning('MCP rate limiter unavailable (%s); refusing calls', type(e).__name__)
        raise McpError('unavailable', 'rate limiter unavailable; try again shortly') from None
