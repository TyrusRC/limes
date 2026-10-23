import os
import anyio
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from limes.mcp import tokens
from limes.mcp.server import build_server


class Command(BaseCommand):
    help = 'Serve MCP over stdio for one personal token in LIMES_MCP_TOKEN (stdout carries only the protocol).'

    def handle(self, *args, **options):
        if not settings.MCP_ENABLED:
            raise CommandError('MCP is not enabled on this instance')
        tok = tokens.verify(os.environ.pop('LIMES_MCP_TOKEN', None))  # popped: not inherited by any child process
        if tok is None:
            raise CommandError('LIMES_MCP_TOKEN is missing or not valid')
        server = build_server(stdio_token_pk=tok.pk)
        anyio.run(server.run_stdio_async)
