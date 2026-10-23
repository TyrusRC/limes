"""ASGI entrypoint for the HTTP transport: transport security, then bearer auth, then the FastMCP app."""
import json
import logging
from urllib.parse import parse_qs
import anyio
import anyio.to_thread
from redis.exceptions import RedisError
from django.conf import settings
from django.db import close_old_connections
from mcp.server.transport_security import TransportSecurityMiddleware
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Route
import limes  # noqa: F401  (limes/celery.py runs django.setup())
from limes.mcp import ratelimit, tokens
from limes.mcp.server import LIMITER, build_server, transport_security

# NOTE: _open is per process (uvicorn --workers N gives N times MAX_OPEN); upgrade path: a Redis counter.
# NOTE: static personal tokens instead of OAuth 2.1 (spec SHOULD for HTTP); upgrade path: RFC 9728 protected-resource
# metadata, an authorization server, tokens with audience /mcp.
logger = logging.getLogger(__name__)
QUERY_TOKEN_KEYS = ('token', 'access_token', 'api_key')
NOT_ENABLED = 'MCP is not enabled on this instance'


MAX_OPEN = 4  # concurrent in-flight requests (streams included) per token, per process
REQ_BURST = 3  # raw requests allowed per tool-call budget: initialize + tools/list + the call
_open = {}


async def _threaded(fn, *args):
    return await anyio.to_thread.run_sync(fn, *args, limiter=LIMITER)  # unauthenticated floods share the tool pool


def _verify(raw):
    close_old_connections()
    try:
        return tokens.verify(raw)
    finally:
        close_old_connections()


def _burn(raw):
    """A token that arrived in a URL sits in proxy and client logs: revoke it if it was a live one."""
    tok = _verify(raw)
    if tok is not None:
        close_old_connections()
        try:
            tokens.revoke(tok)
        finally:
            close_old_connections()
        logger.warning('MCP token sent in a URL was revoked (token id %s)', tok.token_id)


def _take_request(tok):
    close_old_connections()
    try:
        wait = ratelimit.take(f'limes:mcp:rate:{tok.token_id}:req', settings.MCP_RATE_PER_MIN * REQ_BURST, 60)
    except RedisError:
        return 60  # fail closed, like the tool-call limiter
    return wait


def _reply(status, body, headers=None, media_type='application/json'):
    return Response(body, status_code=status, media_type=media_type, headers=headers)


class BearerAuth:
    def __init__(self, app, security: TransportSecurityMiddleware):
        self.app, self.security = app, security

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'lifespan':
            return await self.app(scope, receive, send)
        if scope['type'] != 'http':  # fail closed: websockets and anything new are refused
            if scope['type'] == 'websocket':
                await send({'type': 'websocket.close', 'code': 1008})
            return
        refusal = await self.security.validate_request(Request(scope), is_post=False)
        if refusal is not None:
            return await refusal(scope, receive, send)
        query = parse_qs(scope.get('query_string', b'').decode('latin-1'))
        in_url = [v for k in QUERY_TOKEN_KEYS for v in query.get(k, [])]
        auth = Request(scope).headers.get('authorization', '')
        scheme, _, raw = auth.partition(' ')
        raw = raw.strip() if scheme.lower() == 'bearer' else ''
        tok = None
        if in_url:
            for v in in_url[:3]:
                await _threaded(_burn, v)
        elif raw:
            tok = await _threaded(_verify, raw)
        if tok is None:
            m = tokens.TOKEN_RE.match(raw) if raw else None
            logger.info('MCP auth refused (token id %s)', m.group(1) if m else '-')
            challenge = 'Bearer realm="limes"' + (', error="invalid_token"' if raw or in_url else '')
            return await _reply(401, json.dumps({'error': 'unauthorized'}), {'WWW-Authenticate': challenge})(
                scope, receive, send)
        wait = await _threaded(_take_request, tok)
        if wait or _open.get(tok.pk, 0) >= MAX_OPEN:
            return await _reply(429, json.dumps({'error': 'rate_limited'}), {'Retry-After': str(max(1, wait))})(
                scope, receive, send)
        scope.setdefault('state', {})['limes_token_pk'] = tok.pk
        _open[tok.pk] = _open.get(tok.pk, 0) + 1
        try:
            await self.app(scope, receive, send)
        finally:
            _open[tok.pk] -= 1
            if not _open[tok.pk]:
                del _open[tok.pk]


def build_app():
    if not settings.MCP_ENABLED:
        async def off(request):
            return PlainTextResponse(NOT_ENABLED, status_code=404)
        return Starlette(routes=[Route('/{path:path}', off, methods=['GET', 'POST', 'DELETE', 'PUT', 'PATCH', 'OPTIONS', 'HEAD'])])
    return BearerAuth(build_server().streamable_http_app(), TransportSecurityMiddleware(transport_security()))


application = build_app()
