import hashlib
from datetime import timedelta
from unittest import mock
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

    def test_verify_uses_compare_digest(self):
        import hmac
        from limes.mcp import tokens
        _, raw = create_token(self.u, 'a', 90, 'read')
        with mock.patch.object(tokens.hmac, 'compare_digest', wraps=hmac.compare_digest) as cd:
            self.assertIsNotNone(verify(raw))
        cd.assert_called_once()

    def test_id_collision_is_retried(self):
        from limes.mcp import tokens
        first, _ = create_token(self.u, 'a', 90, 'read')
        ids = iter(list(first.token_id) + list('abcdefgh'))
        with mock.patch.object(tokens.secrets, 'choice', side_effect=lambda a: next(ids)):
            tok, _ = create_token(self.u, 'b', 90, 'read')
        self.assertEqual(tok.token_id, 'abcdefgh')

    def test_verify_db_error_fails_closed_and_logs_no_token(self):
        from limes.mcp import tokens
        _, raw = create_token(self.u, 'a', 90, 'read')
        with mock.patch.object(tokens.ApiToken.objects, 'select_related', side_effect=RuntimeError(raw)):
            with self.assertLogs('limes.mcp.tokens', 'WARNING') as cm:
                self.assertIsNone(verify(raw))
        self.assertIn('RuntimeError', cm.output[0])
        self.assertNotIn(raw, cm.output[0])

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

    def test_scrub_token_shaped_values(self):
        from limes.mcp.tokens import create_token
        u = User.objects.create_user('scrub-user', password='x')
        tok, raw = create_token(u, 'a', 90, 'read')
        secret = raw.split('_', 2)[2]
        out = audit.scrub_args({'text': 'my token ' + raw + ' ok', 'items': [{'note': [raw]}, (raw,)],
                                'Api_Key': 'S3'})
        self.assertNotIn(secret, out)
        self.assertIn('lmk_%s_***' % tok.token_id, out)
        self.assertIn('"Api_Key": "***"', out)

    def test_log_call_long_fields_do_not_lose_the_row(self):
        audit.log_call(token_pk=None, token_public_id='abcd1234', user_id=None, tool='t' * 100, project='p' * 80,
                       args={}, outcome='ok', write=False, duration_ms=1)
        row = McpCallLog.objects.get()
        self.assertEqual((len(row.tool), len(row.project)), (64, 50))

    def test_purge_in_batches(self):
        old = timezone.now() - timedelta(days=100)
        for _ in range(5):
            McpCallLog.objects.create(token_public_id='x', tool='t', outcome='ok', duration_ms=1, created_at=old)
        with mock.patch.object(audit, 'PURGE_BATCH', 2):
            self.assertEqual(audit.purge_mcp_logs(), {'deleted': 5})
        self.assertEqual(McpCallLog.objects.count(), 0)

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
