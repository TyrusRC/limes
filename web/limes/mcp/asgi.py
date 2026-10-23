"""ASGI entrypoint for the HTTP transport: transport security, then bearer auth, then the FastMCP app."""
import json
import logging
from urllib.parse import parse_qs
import anyio.to_thread
from django.conf import settings
from django.db import close_old_connections
from mcp.server.transport_security import TransportSecurityMiddleware
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Route
import limes  # noqa: F401  (limes/celery.py runs django.setup())
from limes.mcp import tokens
from limes.mcp.server import build_server, transport_security

# NOTE: static personal tokens instead of OAuth 2.1 (spec SHOULD for HTTP); upgrade path: RFC 9728 protected-resource
# metadata, an authorization server, tokens with audience /mcp.
logger = logging.getLogger(__name__)
QUERY_TOKEN_KEYS = ('token', 'access_token', 'api_key')
NOT_ENABLED = 'MCP is not enabled on this instance'


def _verify(raw):
    close_old_connections()
    try:
        return tokens.verify(raw)
    finally:
        close_old_connections()


class BearerAuth:
    def __init__(self, app, security: TransportSecurityMiddleware):
        self.app, self.security = app, security

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        refusal = await self.security.validate_request(Request(scope), is_post=False)
        if refusal is not None:
            return await refusal(scope, receive, send)
        query = parse_qs(scope.get('query_string', b'').decode('latin-1'))
        auth = Request(scope).headers.get('authorization', '')
        scheme, _, raw = auth.partition(' ')
        raw = raw.strip() if scheme.lower() == 'bearer' else ''
        tok = None
        if raw and not any(k in query for k in QUERY_TOKEN_KEYS):
            tok = await anyio.to_thread.run_sync(_verify, raw)
        if tok is None:
            m = tokens.TOKEN_RE.match(raw) if raw else None
            logger.info('MCP auth refused (token id %s)', m.group(1) if m else '-')
            challenge = 'Bearer realm="limes"' + (', error="invalid_token"' if raw else '')
            resp = Response(json.dumps({'error': 'unauthorized'}), status_code=401, media_type='application/json',
                            headers={'WWW-Authenticate': challenge})
            return await resp(scope, receive, send)
        scope.setdefault('state', {})['limes_token_pk'] = tok.pk
        await self.app(scope, receive, send)


def build_app():
    if not settings.MCP_ENABLED:
        async def off(request):
            return PlainTextResponse(NOT_ENABLED, status_code=404)
        return Starlette(routes=[Route('/{path:path}', off, methods=['GET', 'POST', 'DELETE', 'PUT', 'PATCH'])])
    return BearerAuth(build_server().streamable_http_app(), TransportSecurityMiddleware(transport_security()))


application = build_app()
