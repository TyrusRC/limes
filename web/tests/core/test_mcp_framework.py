import json
from datetime import timedelta
from unittest import mock
from django.test import override_settings
from django.utils import timezone
from redis.exceptions import RedisError
from rolepermissions.roles import assign_role, clear_roles
from dashboard.models import McpCallLog
from limes.definitions import PERM_MODIFY_SYSTEM_CONFIGURATIONS, PERM_MODIFY_TARGETS
from limes.mcp import access, ratelimit, registry, results, tokens
from limes.mcp.access import McpError
from limes.mcp.registry import REGISTRY
from limes.mcp.results import Limit, RESULT_BUDGET
from tests.core.mcp_base import McpBase


class FrameworkTests(McpBase):
    def reg(self, fn, **kw):
        registry.tool(title=fn.__name__, **kw)(fn)
        self.addCleanup(REGISTRY.pop, fn.__name__)

    def echo_tools(self):
        def t_echo(caller, project: str = '', note: str = ''):
            """echo"""
            return {'who': caller.user.username}

        def t_admin_only(caller):
            """admin"""
            return {}
        self.reg(t_echo)
        self.reg(t_admin_only, perm=PERM_MODIFY_SYSTEM_CONFIGURATIONS)

    def test_authority_is_evaluated_per_call(self):
        self.echo_tools()
        self.assertEqual(self.data(self.call('t_admin_only')), {})
        clear_roles(self.admin)
        assign_role(self.admin, 'auditor')
        self.assertEqual(self.err(self.call('t_admin_only')), 'forbidden')
        self.assertEqual(self.data(self.call('t_echo', self.t_tester))['who'], 'tester')
        tokens.revoke(self.t_tester)
        self.assertEqual(self.err(self.call('t_echo', self.t_tester)), 'unauthorized')
        self.assertEqual(self.data(self.call('t_echo', self.t_aud))['who'], 'aud')
        self.t_aud.expires_at = timezone.now() - timedelta(seconds=1)
        self.t_aud.save()
        self.assertEqual(self.err(self.call('t_echo', self.t_aud)), 'unauthorized')
        self.assertEqual(self.data(self.call('t_echo', self.t_admin_ro))['who'], 'admin')
        self.admin.is_active = False
        self.admin.save()
        self.assertEqual(self.err(self.call('t_echo', self.t_admin_ro)), 'unauthorized')
        self.assertEqual(self.err(registry.call_tool('t_echo', None, {})), 'unauthorized')
        self.assertEqual(self.err(registry.call_tool('t_echo', 10 ** 9, {})), 'unauthorized')

    def test_project_for_same_message(self):
        caller = access.resolve_caller(self.t_admin.pk)
        self.assertEqual(access.project_for(caller, 'p1'), self.p1)
        with self.assertRaises(McpError) as cm:
            access.project_for(caller, 'nope')
        self.assertEqual((cm.exception.code, cm.exception.message), ('not_found', 'project not found'))

    def test_require_write_three_keys(self):
        def t_write(caller):
            """w"""
            return {'done': True}
        self.reg(t_write, write=True, perm=PERM_MODIFY_TARGETS)
        with override_settings(MCP_WRITES_ENABLED=False):
            self.assertEqual(self.err(self.call('t_write')), 'writes_disabled')
        with override_settings(MCP_WRITES_ENABLED=True):
            env = self.call('t_write', self.t_admin_ro)
            self.assertEqual(self.err(env), 'forbidden')
            self.assertEqual(env['error']['message'], 'this token is read-only')
            self.assertEqual(self.err(self.call('t_write', self.t_aud)), 'forbidden')
            self.assertTrue(self.data(self.call('t_write'))['done'])

    def test_write_tool_needs_a_permission(self):
        def t_bad(caller):
            """x"""
        with self.assertRaises(ValueError):
            registry.tool(title='x', write=True)(t_bad)
        self.assertNotIn('t_bad', REGISTRY)

    def test_duplicate_name_refused(self):
        self.echo_tools()

        def t_echo(caller):
            """dup"""
        with self.assertRaises(ValueError):
            registry.tool(title='x')(t_echo)

    @override_settings(MCP_RATE_PER_MIN=5, MCP_WRITE_RATE_PER_MIN=2, MCP_WRITES_ENABLED=True)
    def test_rate_limits(self):
        self.echo_tools()

        def t_write(caller):
            """w"""
            return {}
        self.reg(t_write, write=True, perm=PERM_MODIFY_TARGETS)
        for _ in range(5):
            self.data(self.call('t_echo'))
        env = self.call('t_echo')
        self.assertEqual(self.err(env), 'rate_limited')
        self.assertGreaterEqual(env['error']['retry_after_seconds'], 1)
        self.data(self.call('t_write', self.t_tester))
        self.data(self.call('t_write', self.t_tester))
        self.assertEqual(self.err(self.call('t_write', self.t_tester)), 'rate_limited')
        k, t = 'limes:mcp:rate:test:k', 1000.0
        self.assertEqual(ratelimit.take(k, 1, 60, now=t), 0)
        self.assertGreaterEqual(ratelimit.take(k, 1, 60, now=t + 1), 1)
        self.assertEqual(ratelimit.take(k, 1, 60, now=t + 61), 0)
        with mock.patch('limes.mcp.access.get_redis_connection', side_effect=RedisError):
            self.assertEqual(self.err(self.call('t_echo', self.t_aud)), 'unavailable')

    def test_errors_never_leak(self):
        def t_boom(caller):
            """b"""
            raise RuntimeError('db password=hunter2')

        def t_lim(caller, limit: Limit = 50):
            """l"""
            return {'limit': limit}
        self.reg(t_boom)
        self.reg(t_lim)
        with self.assertLogs('limes.mcp.registry', 'ERROR'):
            env = self.call('t_boom')
        self.assertEqual(self.err(env), 'internal')
        self.assertNotIn('hunter2', json.dumps(env))
        env = self.call('t_lim', limit=500)
        self.assertEqual(self.err(env), 'invalid')
        self.assertNotIn('500', env['error']['message'])
        self.assertEqual(self.data(self.call('t_lim', limit=7)), {'limit': 7})
        self.assertEqual(self.err(self.call('t_lim', bogus='x')), 'invalid')
        self.assertEqual(self.err(self.call('t_lim', caller='x')), 'invalid')
        env = self.call('no_such_tool')
        self.assertEqual((self.err(env), env['error']['message']), ('invalid', 'unknown tool'))

    def test_every_call_audited(self):
        self.echo_tools()

        def t_write(caller):
            """w"""
            return {}
        self.reg(t_write, write=True, perm=PERM_MODIFY_TARGETS)
        raw = self.raw['t_tester']
        with override_settings(MCP_WRITES_ENABLED=True):
            self.data(self.call('t_echo', project='p1', note=raw))
            self.assertEqual(self.err(self.call('t_write', self.t_aud)), 'forbidden')
            tokens.revoke(self.t_tester)
            self.assertEqual(self.err(self.call('t_echo', self.t_tester)), 'unauthorized')
        rows = list(McpCallLog.objects.order_by('id'))
        self.assertEqual([r.outcome for r in rows], ['ok', 'forbidden', 'unauthorized'])
        self.assertEqual((rows[0].project, rows[0].write), ('p1', False))
        self.assertTrue(rows[1].write)
        self.assertEqual(rows[2].token_public_id, self.t_tester.token_id)
        self.assertNotIn(raw.split('_', 2)[2], ''.join(r.arguments for r in rows))
        self.assertIsNotNone(self.t_admin.__class__.objects.get(pk=self.t_admin.pk).last_used_at)

    def test_clean_and_untrusted(self):
        self.assertEqual(results.clean('a\x1b[31mb‮c\x00d\ne\tf'), 'a[31mbcd\ne\tf')
        c = results.clean('x' * 5000)
        self.assertEqual(len(c), 2000)
        self.assertTrue(c.endswith('…'))
        self.assertIsNone(results.untrusted(None))
        self.assertEqual(results.untrusted(12), {'untrusted_text': '12'})
        self.assertEqual(len(results.untrusted('y' * 9, cap=5)['untrusted_text']), 5)

    def test_page_budget_and_cursor(self):
        rows = [{'i': i, 'pad': 'x' * 1500} for i in range(300)]
        seen, cursor, first = [], None, None
        while True:
            p = results.page(rows, cursor, 200, lambda r: r)
            first = first or p
            self.assertLessEqual(len(json.dumps(p['items'])), RESULT_BUDGET)
            seen += [r['i'] for r in p['items']]
            cursor = p['next_cursor']
            if cursor is None:
                break
        self.assertLess(len(first['items']), 200)
        self.assertTrue(first['truncated'])
        self.assertEqual(seen, list(range(300)))
        small = [{'i': i} for i in range(120)]
        p = results.page(small, None, 50, lambda r: r)
        self.assertEqual((len(p['items']), p['truncated']), (50, False))
        self.assertIsNotNone(p['next_cursor'])
        last = results.page(small, results.page(small, p['next_cursor'], 50, lambda r: r)['next_cursor'], 50, lambda r: r)
        self.assertEqual((len(last['items']), last['next_cursor']), (20, None))
        one = results.page([{'pad': 'x' * (RESULT_BUDGET + 10)}], None, 5, lambda r: r)
        self.assertEqual(len(one['items']), 1)
        for bad in ('junk', 'c1.!!', 'c1.' + 'LTE='):
            with self.assertRaises(McpError) as cm:
                results.page(small, bad, 50, lambda r: r)
            self.assertEqual(cm.exception.code, 'invalid')


class HardeningTests(McpBase):
    def reg(self, fn, **kw):
        registry.tool(title=fn.__name__, **kw)(fn)
        self.addCleanup(REGISTRY.pop, fn.__name__)

    def test_forged_cursors_are_invalid(self):
        import base64
        def enc(v):
            return 'c1.' + base64.urlsafe_b64encode(v.encode()).decode()
        for bad in (enc('9' * 20), enc('9' * 70), enc('-1'), enc('abc'), enc(str(10 ** 7 + 1)), 'x1.' + enc('1')[3:], 'c1.', 'c2.MQ=='):
            with self.assertRaises(McpError, msg=bad) as cm:
                results.page([1, 2, 3], bad, 5, lambda r: r)
            self.assertEqual((cm.exception.code, cm.exception.message), ('invalid', 'bad cursor'))
        self.assertEqual(results.page([1, 2, 3], enc('1'), 5, lambda r: r)['items'], [2, 3])

    def test_clean_strips_surrogates_and_separators(self):
        import pydantic_core
        hostile = 'a\ud800b\udfffc\u2028d\u2029e'
        self.assertEqual(results.clean(hostile), 'abcde')
        env = results.ok({results.clean('k\ud800\u2028'): results.untrusted(hostile)})
        self.assertEqual(env['data'], {'k': {'untrusted_text': 'abcde'}})
        json.dumps(env, ensure_ascii=False).encode('utf-8')
        pydantic_core.to_json(env)

    def test_clean_scans_a_bounded_prefix(self):
        with mock.patch.object(results.unicodedata, 'category', wraps=results.unicodedata.category) as cat:
            out = results.clean('x' * 5_000_000)
        self.assertEqual(len(out), 2000)
        self.assertLessEqual(cat.call_count, 2000 * 4)

    def test_unauthenticated_calls_are_cheap(self):
        def t_echo(caller):
            """e"""
            return {}
        self.reg(t_echo)
        tokens.revoke(self.t_tester)
        conn = ratelimit.get_redis_connection('default')
        for name in ('t_echo', 'no_such_tool'):
            self.assertEqual(self.err(self.call(name, self.t_tester)), 'unauthorized')
            self.assertEqual(self.err(registry.call_tool(name, None, {})), 'unauthorized')
            self.assertEqual(self.err(registry.call_tool(name, 10 ** 9, {})), 'unauthorized')
        self.assertEqual(list(conn.scan_iter('limes:mcp:rate:*')), [])
        self.assertEqual(McpCallLog.objects.filter(token__isnull=True).count(), 0)
        self.assertEqual(McpCallLog.objects.count(), 2)  # only the known (revoked) token is attributable
        env = self.call('no_such_tool')
        self.assertEqual((self.err(env), env['error']['message']), ('invalid', 'unknown tool'))

    @override_settings(MCP_RATE_PER_MIN=3)
    def test_buckets_are_per_token(self):
        def t_echo(caller):
            """e"""
            return {}
        self.reg(t_echo)
        for _ in range(3):
            self.data(self.call('t_echo', self.t_admin))
        self.assertEqual(self.err(self.call('t_echo', self.t_admin)), 'rate_limited')
        self.data(self.call('t_echo', self.t_admin_ro))  # same user, other token: own bucket

    def test_open_world_hint(self):
        def t_a(caller):
            """a"""

        def t_b(caller):
            """b"""
        self.reg(t_a)
        self.reg(t_b, open_world=True)
        self.assertFalse(registry.annotations(REGISTRY['t_a'])['openWorldHint'])
        self.assertTrue(registry.annotations(REGISTRY['t_b'])['openWorldHint'])

    def test_varargs_refused(self):
        def t_va(caller, *a):
            """x"""

        def t_kw(caller, **kw):
            """x"""
        for fn in (t_va, t_kw):
            with self.assertRaises(ValueError):
                registry.tool(title='x')(fn)
            self.assertNotIn(fn.__name__, REGISTRY)

    def test_fail_closed_is_logged_once_a_minute(self):
        def t_echo(caller):
            """e"""
            return {}
        self.reg(t_echo)
        access._last_warn = 0.0
        with mock.patch('limes.mcp.access.get_redis_connection', side_effect=RedisError):
            with self.assertLogs('limes.mcp.access', 'WARNING') as cm:
                self.call('t_echo')
                self.call('t_echo')
        self.assertEqual(len(cm.output), 1)
        self.assertNotIn('lmk_', cm.output[0])
