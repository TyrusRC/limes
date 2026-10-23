"""Shared fixture for the MCP tests (not a test module)."""
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.test import TestCase, override_settings
from django.utils import timezone
from django_redis import get_redis_connection
from rolepermissions.roles import assign_role
from dashboard.models import Project
from dashboard.views import on_user_logged_in
from limes.mcp import registry
from limes.mcp.tokens import create_token


class McpBase(TestCase):
    def setUp(self):
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        conn = get_redis_connection('default')  # fakeredis persists across tests
        for k in conn.scan_iter('limes:mcp:rate:*'):
            conn.delete(k)
        self.admin = self._user('admin', 'sys_admin')
        self.tester = self._user('tester', 'penetration_tester')
        self.aud = self._user('aud', 'auditor')
        self.p1 = Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())
        self.p2 = Project.objects.create(name='p2', slug='p2', insert_date=timezone.now())
        self.raw = {}
        with override_settings(MCP_WRITES_ENABLED=True):
            self.t_admin = self._token('t_admin', self.admin, 'read_write')
            self.t_admin_ro = self._token('t_admin_ro', self.admin, 'read')
            self.t_tester = self._token('t_tester', self.tester, 'read_write')
            self.t_aud = self._token('t_aud', self.aud, 'read_write')

    def _user(self, name, role):
        u = User.objects.create_user(name, password='p')
        assign_role(u, role)
        return u

    def _token(self, name, user, scope):
        tok, raw = create_token(user, name, 90, scope)
        self.raw[name] = raw
        return tok

    def call(self, name, token=None, **args):
        return registry.call_tool(name, (token or self.t_admin).pk, args)

    def data(self, env):
        self.assertTrue(env['ok'], env)
        return env['data']

    def err(self, env):
        self.assertFalse(env['ok'], env)
        return env['error']['code']

    def outside_untrusted(self, obj):
        """Every string in obj that is not directly under an 'untrusted_text' key (keys excluded)."""
        out = []
        if isinstance(obj, str):
            out.append(obj)
        elif isinstance(obj, dict):
            for k, v in obj.items():
                if k != 'untrusted_text':
                    out.extend(self.outside_untrusted(v))
        elif isinstance(obj, (list, tuple)):
            for v in obj:
                out.extend(self.outside_untrusted(v))
        return out
