import re
from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.forms.models import model_to_dict
from django.test import Client, TestCase, override_settings
from django.utils import timezone
from dashboard.models import ApiToken, Project
from dashboard.views import on_user_logged_in
from limes.mcp import tokens
from limes.mcp.tokens import TOKEN_FIND_RE, create_token, verify


@override_settings(MCP_ENABLED=True, MCP_WRITES_ENABLED=False)
class ApiTokensPageTests(TestCase):
    def setUp(self):
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())
        self.u = User.objects.create_user('me', password='p')
        self.other = User.objects.create_user('other', password='p')
        self.c = Client()
        self.c.force_login(self.u)
        self.url = '/p1/api-tokens/'

    def create(self, **kw):
        data = {'action': 'create', 'name': 'laptop', 'days': '90', 'scope': 'read'}
        data.update(kw)
        return self.c.post(self.url, data)

    def test_create_shows_once(self):
        r = self.create()
        self.assertEqual(r.status_code, 200)
        self.assertIn('no-store', r['Cache-Control'])
        found = TOKEN_FIND_RE.findall(r.content.decode())
        self.assertEqual(len(found), 1)
        raw = TOKEN_FIND_RE.search(r.content.decode()).group(0)
        self.assertTrue(verify(raw))
        self.assertIn('You will not see this again', r.content.decode())
        secret = found[0][1]
        body = self.c.get(self.url).content.decode()
        self.assertNotIn(raw, body)
        self.assertNotIn(secret, body)
        tok = ApiToken.objects.get(user=self.u)
        self.assertIn(tok.token_id, body)
        for v in model_to_dict(tok).values():
            self.assertNotIn(secret, str(v))
        self.assertNotIn(raw, str(model_to_dict(tok)))

    def test_lists_only_own_and_revoke_scoped(self):
        create_token(self.other, 'othertoken', 90, 'read')
        mine, _ = create_token(self.u, 'mytoken', 90, 'read')
        theirs = ApiToken.objects.get(user=self.other)
        body = self.c.get(self.url).content.decode()
        self.assertIn('mytoken', body)
        self.assertNotIn('othertoken', body)
        r = self.c.post(self.url, {'action': 'revoke', 'token_id': theirs.token_id})
        self.assertEqual(r.status_code, 404)
        theirs.refresh_from_db()
        self.assertIsNone(theirs.revoked_at)
        r = self.c.post(self.url, {'action': 'revoke', 'token_id': mine.token_id})
        self.assertEqual(r.status_code, 302)
        mine.refresh_from_db()
        self.assertIsNotNone(mine.revoked_at)
        self.assertIn('revoked', self.c.get(self.url).content.decode())

    def test_scope_offer_follows_server_setting(self):
        self.assertNotIn('value="read_write"', self.c.get(self.url).content.decode())
        r = self.create(scope='read_write')
        self.assertEqual(ApiToken.objects.count(), 0)
        self.assertIn('write tokens are disabled', r.content.decode())
        with override_settings(MCP_WRITES_ENABLED=True):
            self.assertIn('value="read_write"', self.c.get(self.url).content.decode())

    def test_validation(self):
        for kw in ({'days': '7'}, {'name': ''}, {'days': 'abc'}):
            r = self.create(**kw)
            self.assertEqual(r.status_code, 200)
            self.assertIn('l-form-error', r.content.decode())
        self.assertEqual(ApiToken.objects.count(), 0)

    def test_name_escaped(self):
        evil = '<img src=x onerror=alert(1)>'
        r = self.create(name=evil)
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;', r.content.decode())
        self.assertNotIn(evil, r.content.decode())
        self.assertNotIn(evil, self.c.get(self.url).content.decode())

    def test_csrf_enforced(self):
        c = Client(enforce_csrf_checks=True)
        c.force_login(self.u)
        r = c.post(self.url, {'action': 'create', 'name': 'x', 'days': '90', 'scope': 'read'})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(ApiToken.objects.count(), 0)

    def test_menu_link_follows_setting(self):
        self.assertIn('/api-tokens/', self.c.get('/p1/dashboard/').content.decode())
        with override_settings(MCP_ENABLED=False):
            self.assertNotIn('/api-tokens/', self.c.get('/p1/dashboard/').content.decode())

    def test_disabled_redirects_and_unknown_project_is_not_found(self):
        with override_settings(MCP_ENABLED=False):
            self.assertEqual(self.c.get(self.url).status_code, 302)
            self.assertIn('404', self.c.get(self.url)['Location'])
        self.assertEqual(self.c.get('/nope/api-tokens/').status_code, 404)  # same answer as a project that is not yours
