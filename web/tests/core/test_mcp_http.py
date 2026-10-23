"""MCP over Streamable HTTP and stdio: transport security, bearer auth, tool listing, error shape, no leaks."""
import json
import os
import re
import subprocess
import sys
from io import StringIO
from pathlib import Path
from unittest import mock
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.test import TransactionTestCase, override_settings
from django.utils import timezone
from django_redis import get_redis_connection
from rolepermissions.roles import assign_role
from starlette.testclient import TestClient
from dashboard.models import McpCallLog, Project
from dashboard.views import on_user_logged_in
from limes.mcp import registry, tokens
from limes.mcp.tokens import create_token

WEB = Path(__file__).resolve().parents[2]
HEADERS = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream',
           'MCP-Protocol-Version': '2025-06-18'}


@override_settings(MCP_ENABLED=True, DOMAIN_NAME='limes.test', MCP_ALLOWED_HOSTS=['testserver'],
                   MCP_ALLOWED_ORIGINS=['https://ok.test'], MCP_WRITES_ENABLED=False)
class McpHttpTests(TransactionTestCase):
    def setUp(self):
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        conn = get_redis_connection('default')
        for k in conn.scan_iter('limes:mcp:rate:*'):
            conn.delete(k)
        self.admin = User.objects.create_user('http_admin', password='p')
        assign_role(self.admin, 'sys_admin')
        for s in ('h1', 'h2'):
            Project.objects.create(name=s, slug=s, insert_date=timezone.now())
        self.tok, self.raw = create_token(self.admin, 'http', 90, 'read')

    def app(self):
        from limes.mcp.asgi import build_app
        return build_app()

    def rpc(self, c, method, params=None, raw='default', headers=None, url='/mcp'):
        h = dict(HEADERS)
        raw = self.raw if raw == 'default' else raw
        if raw:
            h['Authorization'] = f'Bearer {raw}'
        h.update(headers or {})
        body = {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}}
        return c.post(url, json=body, headers=h)

    def call(self, c, name, args=None, **kw):
        return self.rpc(c, 'tools/call', {'name': name, 'arguments': args or {}}, **kw)

    def test_transport_security_explicitly_enabled(self):
        from limes.mcp.server import allowed_hosts, transport_security
        ts = transport_security()
        self.assertIs(ts.enable_dns_rebinding_protection, True)
        self.assertIn('limes.test', ts.allowed_hosts)
        self.assertIn('limes.test:*', ts.allowed_hosts)
        self.assertNotIn('*', ts.allowed_hosts)
        with override_settings(DOMAIN_NAME='limes.test:8443', MCP_ALLOWED_HOSTS=['*', 'limes.test', 'x.test']):
            hosts = allowed_hosts()
            self.assertNotIn('*', hosts)
            self.assertEqual(len(hosts), len(set(hosts)))
            self.assertIn('x.test', hosts)
            self.assertNotIn('limes.test:8443', hosts)
        with override_settings(MCP_ALLOWED_ORIGINS=[]):
            self.assertEqual(transport_security().allowed_origins, [])

    def test_bad_host_bad_origin_missing_token(self):
        with TestClient(self.app()) as c:
            self.assertEqual(self.call(c, 'list_projects', headers={'Host': 'evil.test'}).status_code, 421)
            self.assertEqual(self.call(c, 'list_projects', headers={'Origin': 'https://evil.test'}).status_code, 403)
            r = self.call(c, 'list_projects', raw=None)
            self.assertEqual(r.status_code, 401)
            self.assertTrue(r.headers['www-authenticate'].startswith('Bearer realm="limes"'))
            self.assertNotIn('invalid_token', r.headers['www-authenticate'])
            r = self.call(c, 'list_projects', raw='lmk_bad')
            self.assertEqual(r.status_code, 401)
            self.assertIn('error="invalid_token"', r.headers['www-authenticate'])
            self.assertEqual(r.json(), {'error': 'unauthorized'})
            r = self.call(c, 'list_projects', raw=None, url=f'/mcp?token={self.raw}')
            self.assertEqual(r.status_code, 401)
            r = self.call(c, 'list_projects')
            self.assertEqual(r.status_code, 200, r.text)
            res = r.json()['result']
            self.assertFalse(res['isError'])
            self.assertEqual(sorted(i['slug'] for i in res['structuredContent']['data']['items']), ['h1', 'h2'])
            r = self.call(c, 'list_projects', headers={'Origin': 'https://ok.test'})
            self.assertEqual(r.status_code, 200)

    def test_tools_list_and_annotations(self):
        def listing(**s):
            with override_settings(**s), TestClient(self.app()) as c:
                r = self.rpc(c, 'tools/list')
                self.assertEqual(r.status_code, 200, r.text)
                return {t['name']: t for t in r.json()['result']['tools']}
        off = listing(MCP_WRITES_ENABLED=False)
        writes = {n for n, s in registry.load_tools().items() if s.write}
        self.assertEqual(len(writes), 6)
        self.assertFalse(writes & set(off))
        for n, t in off.items():
            self.assertIs(t['annotations']['readOnlyHint'], True, n)
            self.assertIs(t['annotations']['openWorldHint'], False, n)
        self.assertEqual(off['list_assets']['inputSchema']['properties']['limit']['maximum'], 200)
        self.assertNotIn('caller', off['list_assets']['inputSchema']['properties'])
        self.assertNotIn('ctx', off['list_assets']['inputSchema']['properties'])
        on = listing(MCP_WRITES_ENABLED=True)
        self.assertTrue(writes <= set(on))
        self.assertIs(on['revoke_waiver']['annotations']['destructiveHint'], True)

    def test_errors_are_tool_errors(self):
        other = Project.objects.create(name='h3', slug='h3', insert_date=timezone.now())
        with TestClient(self.app()) as c:
            r = self.call(c, 'get_asset', {'project': 'h1', 'asset_id': 999999})
            res = r.json()['result']
            self.assertTrue(res['isError'])
            self.assertEqual(res['structuredContent']['error']['code'], 'not_found')
            r = self.call(c, 'list_assets', {'project': 'h1', 'limit': 500})
            self.assertNotIn('Traceback', r.text)
            body = r.json()
            self.assertTrue('error' in body or body['result']['isError'])
        del other

    def test_revocation_applies_to_next_http_call(self):
        with TestClient(self.app()) as c:
            self.assertEqual(self.call(c, 'list_projects').status_code, 200)
            tokens.revoke(self.tok)
            self.assertEqual(self.call(c, 'list_projects').status_code, 401)

    def test_no_connection_leak(self):
        def conns():
            with connection.cursor() as cur:
                cur.execute('SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()')
                return cur.fetchone()[0]
        with TestClient(self.app()) as c:
            self.call(c, 'list_projects')  # warm up
            before = conns()
            for _ in range(25):
                self.assertEqual(self.call(c, 'list_projects').status_code, 200)
            after = conns()
        self.assertLessEqual(after, before)

    def test_token_never_logged(self):
        _, raw2 = create_token(self.admin, 'http2', 90, 'read')
        bad = 'lmk_' + 'a1b2c3d4' + '_' + 'Z' * 43
        secrets_ = [r.rsplit('_', 1)[1] for r in (self.raw, raw2, bad)]
        with self.assertLogs('', level='DEBUG') as cm, TestClient(self.app()) as c:
            self.assertEqual(self.call(c, 'list_projects', args={'x': 1}, raw=bad).status_code, 401)
            self.call(c, 'list_projects')
            self.call(c, 'list_projects', raw=raw2)
        for rec in cm.records:
            for s in secrets_:
                self.assertNotIn(s, rec.getMessage())
        for row in McpCallLog.objects.all():
            for s in secrets_:
                self.assertNotIn(s, row.arguments)
        self.assertTrue(any('a1b2c3d4' in r.getMessage() and 'refused' in r.getMessage() for r in cm.records))

    def test_disabled_server_404(self):
        with override_settings(MCP_ENABLED=False), TestClient(self.app()) as c:
            for path in ('/mcp', '/anything'):
                r = c.post(path, json={}, headers=HEADERS)
                self.assertEqual(r.status_code, 404)
                self.assertIn('MCP is not enabled on this instance', r.text)

    def test_stdio_command(self):
        env = {k: v for k, v in os.environ.items() if k != 'LIMES_MCP_TOKEN'}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(CommandError):
                call_command('mcp_stdio')
        junk = 'lmk_junkjunk_' + 'Q' * 43
        with mock.patch.dict(os.environ, {'LIMES_MCP_TOKEN': junk}):
            with self.assertRaises(CommandError) as cm:
                call_command('mcp_stdio')
        self.assertNotIn(junk, str(cm.exception))
        self.assertNotIn('Q' * 43, str(cm.exception))
        with mock.patch.dict(os.environ, {'LIMES_MCP_TOKEN': self.raw}), \
                mock.patch('dashboard.management.commands.mcp_stdio.anyio.run') as run, \
                mock.patch('dashboard.management.commands.mcp_stdio.build_server') as bs:
            call_command('mcp_stdio')
        bs.assert_called_once_with(stdio_token_pk=self.tok.pk)
        run.assert_called_once()
        with override_settings(MCP_ENABLED=False), self.assertRaises(CommandError):
            call_command('mcp_stdio')

    def test_manage_py_stdout_clean_for_stdio(self):
        p = subprocess.run([sys.executable, str(WEB / 'manage.py'), 'mcp_stdio'],
                           env={**os.environ, 'LIMES_MCP_ENABLED': 'true', 'LIMES_MCP_TOKEN': 'junk'},
                           capture_output=True, timeout=60)
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(p.stdout, b'')
        self.assertIn(b'not valid', p.stderr)
