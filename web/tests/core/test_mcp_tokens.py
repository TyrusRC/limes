import hashlib
from datetime import timedelta
from django.conf import settings
from django.contrib.auth.models import User
from django.db import connection
from django.forms.models import model_to_dict
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from dashboard.models import McpCallLog
from limes.celery_routing import TASK_PLAN
from limes.mcp import audit
from limes.mcp.tokens import TOKEN_RE, TokenError, create_token, revoke, touch, verify


class TokenTests(TestCase):
    def setUp(self):
        self.u = User.objects.create_user('tok-user', password='x')

    def test_create_and_verify(self):
        tok, raw = create_token(self.u, ' laptop ', 90, 'read')
        self.assertTrue(TOKEN_RE.match(raw))
        self.assertTrue(raw.startswith('lmk_' + tok.token_id + '_'))
        self.assertEqual(tok.name, 'laptop')
        self.assertLess(abs(tok.expires_at - (timezone.now() + timedelta(days=90))), timedelta(minutes=1))
        self.assertEqual(tok.token_hash, hashlib.sha256(raw.encode()).hexdigest())
        secret = raw.split('_', 2)[2]
        self.assertNotIn(secret, str(model_to_dict(tok)))
        self.assertNotIn(secret, repr(tok) + str(tok))
        self.assertEqual(verify(raw), tok)

    def test_verify_refuses(self):
        tok, raw = create_token(self.u, 'a', 90, 'read')
        other = 'lmk_' + ('z' if tok.token_id[0] != 'z' else 'y') + tok.token_id[1:] + raw[12:]
        last = 'A' if raw[-1] != 'A' else 'B'
        for bad in (None, '', 'Bearer ' + raw, raw[:-1] + last, other, raw + 'x'):
            self.assertIsNone(verify(bad), bad)
        self.assertIsNone(verify(raw, now=tok.expires_at + timedelta(seconds=1)))
        self.assertEqual(verify(raw), tok)
        self.u.is_active = False
        self.u.save()
        self.assertIsNone(verify(raw))
        self.u.is_active = True
        self.u.save()
        self.assertTrue(revoke(tok))
        self.assertFalse(revoke(tok))
        self.assertIsNone(verify(raw))

    def test_create_validates(self):
        for args in (('', 90, 'read'), ('x' * 101, 90, 'read'), ('n', 7, 'read'), ('n', 90, 'admin')):
            with self.assertRaises(TokenError):
                create_token(self.u, *args)
        with override_settings(MCP_WRITES_ENABLED=False):
            with self.assertRaises(TokenError):
                create_token(self.u, 'n', 90, 'read_write')
        with override_settings(MCP_WRITES_ENABLED=True):
            tok, _ = create_token(self.u, 'n', 90, 'read_write')
            self.assertEqual(tok.scope, 'read_write')

    def test_touch_at_most_once_a_minute(self):
        tok, _ = create_token(self.u, 'a', 90, 'read')
        now = timezone.now()
        with CaptureQueriesContext(connection) as q:
            touch(tok, now)
        self.assertEqual(len(q), 1)
        tok.refresh_from_db()
        self.assertEqual(tok.last_used_at, now)
        with CaptureQueriesContext(connection) as q:
            touch(tok, now + timedelta(seconds=30))
        self.assertEqual(len(q), 1)
        tok.refresh_from_db()
        self.assertEqual(tok.last_used_at, now)
        with CaptureQueriesContext(connection) as q:
            touch(tok, now + timedelta(seconds=61))
        self.assertEqual(len(q), 1)
        tok.refresh_from_db()
        self.assertEqual(tok.last_used_at, now + timedelta(seconds=61))


class AuditTests(TestCase):
    def test_scrub_args(self):
        out = audit.scrub_args({'project': 'p1', 'api_key': 'S3', 'nested': {'Authorization': 'Bearer x'},
                                'items': [{'password': 'pw'}], 'text': 'y' * 5000})
        for leak in ('S3', 'Bearer x', '"pw"'):
            self.assertNotIn(leak, out)
        self.assertIn('"api_key": "***"', out)
        self.assertLessEqual(len(out), 1024)

    def test_log_call_and_purge(self):
        audit.log_call(token_pk=None, token_public_id='abcd1234', user_id=None, tool='list_projects', project='p1',
                       args={'a': 1}, outcome='ok', write=False, duration_ms=5)
        row = McpCallLog.objects.get()
        self.assertEqual((row.token_public_id, row.tool, row.arguments), ('abcd1234', 'list_projects', '{"a": 1}'))
        now = timezone.now()
        old = McpCallLog.objects.create(token_public_id='x', tool='t', outcome='ok', duration_ms=1,
                                        created_at=now - timedelta(days=91))
        keep = McpCallLog.objects.create(token_public_id='x', tool='t', outcome='ok', duration_ms=1,
                                         created_at=now - timedelta(days=89))
        self.assertEqual(audit.purge_mcp_logs(), {'deleted': 1})
        self.assertFalse(McpCallLog.objects.filter(pk=old.pk).exists())
        self.assertTrue(McpCallLog.objects.filter(pk=keep.pk).exists())

    def test_purge_task_routed_and_scheduled(self):
        self.assertIn('purge_mcp_logs', TASK_PLAN)
        self.assertEqual(settings.CELERY_BEAT_SCHEDULE['purge-mcp-logs']['task'], 'purge_mcp_logs')
        self.assertIn('limes.mcp.audit', settings.CELERY_IMPORTS)
