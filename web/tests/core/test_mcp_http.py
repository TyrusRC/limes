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
from startScan.asset_models import Asset
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
            _, leaked = create_token(self.admin, 'leaked', 90, 'read')
            r = self.call(c, 'list_projects', raw=None, url=f'/mcp?token={leaked}')
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
        self.assertEqual(len(writes), 7)
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
        foreign = Asset.objects.create(project=other, kind='root_domain', value='z.com', scope_tier='owned_root')
        with TestClient(self.app()) as c:
            for aid in (999999, foreign.id):  # missing, and another project's real asset: same answer
                r = self.call(c, 'get_asset', {'project': 'h1', 'asset_id': aid})
                res = r.json()['result']
                self.assertTrue(res['isError'])
                self.assertEqual(res['structuredContent']['error']['code'], 'not_found')
            r = self.call(c, 'list_assets', {'project': 'h1', 'limit': 500})
            self.assertNotIn('Traceback', r.text)
            body = r.json()
            self.assertTrue('error' in body or body['result']['isError'])

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
                for method in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'):
                    r = c.request(method, path, headers=HEADERS)
                    self.assertEqual(r.status_code, 404, (method, path))
                    if method != 'HEAD':
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
            self.assertNotIn('LIMES_MCP_TOKEN', os.environ)  # not left for child processes
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

    # --- review fixes ---
    def test_token_in_url_is_burned(self):
        with self.assertLogs('limes.mcp.asgi', level='WARNING') as cm, TestClient(self.app()) as c:
            r = self.call(c, 'list_projects', raw=None, url=f'/mcp?access_token={self.raw}')
            self.assertEqual(r.status_code, 401)
            self.assertEqual(self.call(c, 'list_projects').status_code, 401)  # the leaked token is now revoked
        self.tok.refresh_from_db()
        self.assertIsNotNone(self.tok.revoked_at)
        text = ' '.join(rec.getMessage() for rec in cm.records)
        self.assertIn(self.tok.token_id, text)
        self.assertNotIn(self.raw.rsplit('_', 1)[1], text)

    def test_unauthenticated_floods_are_bounded_by_the_limiter(self):
        import threading
        import time
        from concurrent.futures import ThreadPoolExecutor
        from limes.mcp import server
        lock, state = threading.Lock(), {'now': 0, 'max': 0}

        def slow_verify(raw):
            with lock:
                state['now'] += 1
                state['max'] = max(state['max'], state['now'])
            time.sleep(0.3)
            with lock:
                state['now'] -= 1
            return None
        with mock.patch('limes.mcp.asgi.tokens.verify', slow_verify), TestClient(self.app()) as c:
            with ThreadPoolExecutor(30) as ex:
                list(ex.map(lambda _: self.call(c, 'list_projects', raw='lmk_bad'), range(30)))
        self.assertLessEqual(state['max'], server.MAX_THREADS)

    def test_authenticated_requests_are_rate_limited_and_streams_capped(self):
        with override_settings(MCP_RATE_PER_MIN=2), TestClient(self.app()) as c:
            codes = [self.rpc(c, 'tools/list').status_code for _ in range(8)]
        self.assertIn(429, codes)
        self.assertEqual(codes[0], 200)
        import threading
        import time
        from concurrent.futures import ThreadPoolExecutor
        from limes.mcp.asgi import MAX_OPEN, BearerAuth
        from mcp.server.transport_security import TransportSecurityMiddleware
        from limes.mcp.server import transport_security
        state = {'now': 0, 'max': 0}
        lock = threading.Lock()

        async def slow(scope, receive, send):
            import anyio
            if scope['type'] == 'lifespan':
                while True:
                    m = await receive()
                    await send({'type': 'lifespan.' + m['type'].split('.')[1] + '.complete'})
                    if m['type'] == 'lifespan.shutdown':
                        return
            with lock:
                state['now'] += 1
                state['max'] = max(state['max'], state['now'])
            await anyio.sleep(0.4)
            with lock:
                state['now'] -= 1
            await send({'type': 'http.response.start', 'status': 200, 'headers': []})
            await send({'type': 'http.response.body', 'body': b''})
        app = BearerAuth(slow, TransportSecurityMiddleware(transport_security()))
        with override_settings(MCP_RATE_PER_MIN=1000), TestClient(app) as c:
            with ThreadPoolExecutor(12) as ex:
                codes = list(ex.map(lambda _: self.rpc(c, 'tools/list').status_code, range(12)))
        self.assertIn(429, codes, (codes, state))
        self.assertLessEqual(state['max'], MAX_OPEN)

    def test_tool_call_time_limit(self):
        from limes.mcp import server
        import time
        with mock.patch.object(server, 'TOOL_TIMEOUT', 0.2), \
                mock.patch.object(server, 'run_threaded', lambda *a: time.sleep(1) or {'ok': True}), \
                TestClient(self.app()) as c:
            res = self.call(c, 'list_projects').json()['result']
        self.assertTrue(res['isError'])
        self.assertEqual(res['structuredContent']['error']['code'], 'timeout')

    def test_non_http_scopes_fail_closed(self):
        import anyio
        from limes.mcp.asgi import BearerAuth
        from mcp.server.transport_security import TransportSecurityMiddleware
        from limes.mcp.server import transport_security
        seen = []

        async def inner(scope, receive, send):
            seen.append(scope['type'])
        app = BearerAuth(inner, TransportSecurityMiddleware(transport_security()))
        sent = []

        async def go():
            async def recv():
                return {'type': 'websocket.connect'}

            async def send(m):
                sent.append(m['type'])
            await app({'type': 'lifespan'}, recv, send)
            await app({'type': 'websocket', 'path': '/mcp', 'headers': [], 'query_string': b''}, recv, send)
        anyio.run(go)
        self.assertEqual(seen, ['lifespan'])
        self.assertEqual(sent, ['websocket.close'])

    def test_uvicorn_loggers_survive_django_logging(self):
        code = ("import logging, sys\nlogging.getLogger('uvicorn.error'); logging.getLogger('uvicorn.access')\n"
                "import limes\nl = logging.getLogger('uvicorn.error')\nassert not l.disabled\n"
                "assert not logging.getLogger('uvicorn.access').disabled\n"
                "try:\n    1/0\nexcept ZeroDivisionError:\n    l.exception('Exception in ASGI application')\n")
        p = subprocess.run([sys.executable, '-c', code], capture_output=True, timeout=60,
                           env={**os.environ, 'PYTHONPATH': str(WEB), 'DJANGO_SETTINGS_MODULE': 'limes.settings'})
        self.assertEqual(p.returncode, 0, p.stderr[-800:])
        self.assertIn(b'Traceback', p.stdout + p.stderr)

    def test_uvicorn_access_line_with_a_url_token_is_never_emitted(self):
        """The access line carries the query string; Django's logging config must not switch it back on."""
        code = ("import logging, io, sys\nimport limes\nbuf = io.StringIO()\n"
                "a = logging.getLogger('uvicorn.access')\na.addHandler(logging.StreamHandler(buf))\n"
                "a.info('%s - \"%s %s HTTP/%s\" %d', '1.2.3.4:1', 'GET', '/mcp?token=lmk_aaaaaaaa_PLANTEDVALUE', '1.1', 404)\n"
                "print('LEAK' if 'PLANTEDVALUE' in buf.getvalue() else 'CLEAN')\n")
        p = subprocess.run([sys.executable, '-c', code], capture_output=True, timeout=60,
                           env={**os.environ, 'PYTHONPATH': str(WEB), 'DJANGO_SETTINGS_MODULE': 'limes.settings'})
        self.assertEqual(p.returncode, 0, p.stderr[-800:])
        self.assertIn(b'CLEAN', p.stdout)
        self.assertNotIn(b'PLANTEDVALUE', p.stdout + p.stderr)

    def test_deploy_config(self):
        root = WEB.parent
        nginx = ''.join(f.read_text() for f in sorted((root / 'config/nginx').iterdir()))
        self.assertIn('error_page                                  502 = @mcp_off', nginx)
        self.assertNotIn('502 504', nginx)
        self.assertRegex(nginx, r'log_format\s+mcp\s+[^;]*\$uri')
        self.assertNotRegex(re.search(r'log_format\s+mcp[^;]*;', nginx).group(0), r'\$request\b|\$request_uri|\$args')

    # --- final review ---
    def test_wrong_typed_call_is_audited_rate_limited_and_does_not_echo_input(self):
        secret = 'SECRETVALUE' + 'z' * 20
        with TestClient(self.app()) as c:
            r = self.call(c, 'get_asset', {'project': 'h1', 'asset_id': secret})
            res = r.json()['result']
            self.assertTrue(res['isError'])
            self.assertEqual(res['structuredContent']['error']['code'], 'invalid')
            self.assertNotIn(secret, r.text)
            r = self.call(c, 'get_asset', {'project': 'h1'})  # missing argument
            self.assertEqual(r.json()['result']['structuredContent']['error']['code'], 'invalid')
        rows = McpCallLog.objects.filter(tool='get_asset')
        self.assertEqual(rows.count(), 2)
        self.assertEqual({r.outcome for r in rows}, {'invalid'})
        # the per-call limit counts them
        with override_settings(MCP_RATE_PER_MIN=2), TestClient(self.app()) as c:
            codes = [self.call(c, 'get_asset', {'project': 'h1', 'asset_id': 'x'}).json()['result']['structuredContent']
                     ['error']['code'] for _ in range(4)]
        self.assertIn('rate_limited', codes)

    def test_tools_list_still_strict_after_permissive_arguments(self):
        with TestClient(self.app()) as c:
            tools = {t['name']: t for t in self.rpc(c, 'tools/list').json()['result']['tools']}
        props = tools['get_asset']['inputSchema']
        self.assertEqual(props['properties']['asset_id']['type'], 'integer')
        self.assertIn('asset_id', props['required'])

    def test_auth_has_its_own_limiter_and_nginx_limits_requests(self):
        from limes.mcp import asgi, server
        self.assertIsNot(asgi.AUTH_LIMITER, server.LIMITER)
        nginx = ''.join(f.read_text() for f in sorted((WEB.parent / 'config/nginx').iterdir()))
        self.assertRegex(nginx, r'limit_req_zone\s+\$binary_remote_addr\s+zone=mcp:\d+m\s+rate=\d+r/s')
        self.assertRegex(nginx, r'limit_req\s+zone=mcp\s+burst=\d+')

    def test_docs_state_the_risky_settings(self):
        docs = (WEB.parent / 'docs/mcp.md').read_text()
        self.assertIn('candidates only by default', docs)
        self.assertNotIn('(candidates only,', docs)
        self.assertRegex(docs, r'(?s)LIMES_MCP_ADD_TIER.{0,800}(active|scan target)')
        env = (WEB.parent / '.env.example').read_text()
        self.assertRegex(env, r'(?is)WARNING.{0,400}LIMES_MCP_ADD_TIER|LIMES_MCP_ADD_TIER.{0,10}\n?.*WARNING')
        self.assertRegex(docs, r'destructiveHint[^.]*add_assets[^.]*waive_issue|add_assets[^.]*waive_issue[^.]*destructive')
