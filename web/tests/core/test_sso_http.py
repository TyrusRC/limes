"""Every request to the provider goes through sso.http.fetch: https only, public addresses only, pinned, no redirects."""
import json
from unittest import mock

import requests
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, override_settings

from sso import http, provider
from tests.core.sso_base import ISSUER, SsoBase, sign

PUBLIC = '93.184.216.34'
REAL_FETCH = http.fetch  # before SsoBase replaces it


class Resp:
    def __init__(self, status=200, body=b'{}', chunks=None):
        self.status_code, self._chunks, self.closed = status, chunks or [body], False

    def iter_content(self, n):
        yield from self._chunks

    def close(self):
        self.closed = True


class Session:
    """Stands in for requests.Session: records what it was asked to fetch."""
    last = None
    reply = Resp()

    def __init__(self):
        self.trust_env, self.cookies, self.calls = True, None, []
        Session.last = self

    def mount(self, *a):
        pass

    def get(self, url, **kw):
        self.calls.append(('get', url, kw))
        return Session.reply

    def post(self, url, **kw):
        self.calls.append(('post', url, kw))
        return Session.reply


def resolver(*answers):
    def resolve(name, rdtype):
        if rdtype == 'A':
            return [a for a in answers if ':' not in a]
        return [a for a in answers if ':' in a]
    return resolve


class FetchTest(SimpleTestCase):
    def fetch(self, url, method='get', answers=(PUBLIC,), **kw):
        return http.fetch(method, url, resolve=resolver(*answers), session_factory=Session, **kw)

    def test_refuses_what_is_not_https_on_a_public_host(self):
        for url in ('http://idp.example.com/x', 'ftp://idp.example.com/', 'https://user:pw@idp.example.com/',
                    'https://idp.example.com\\@evil.example/', '//idp.example.com/', 'file:///etc/passwd', '', 'https:///x',
                    'https://127.0.0.1/', 'https://[::1]/', 'https://10.1.2.3/', 'https://169.254.169.254/latest/meta-data/',
                    'https://192.168.0.1/', 'https://0.0.0.0/', 'https://localhost/', 'https://db.internal/',
                    'https://[::ffff:127.0.0.1]/', 'https://2130706433/', 'https://0x7f000001/', 'https://idp.example.com:99999/'):
            Session.last = None
            with self.assertRaises(http.FetchError, msg=url):
                self.fetch(url)
            self.assertIsNone(Session.last, f'{url}: a connection was prepared')

    def test_refuses_names_that_resolve_to_private_addresses(self):
        for answers in (('127.0.0.1',), ('10.0.0.5',), ('169.254.169.254',), ('::1',), (PUBLIC, '10.0.0.5'), ('fd00::1',), ()):
            Session.last = None
            with self.assertRaises(http.FetchError, msg=answers):
                self.fetch('https://idp.example.com/x', answers=answers)
            self.assertIsNone(Session.last)

    def test_connects_to_the_vetted_ip_with_the_name_as_host_header(self):
        Session.reply = Resp(200, b'{"ok":1}')
        status, body = self.fetch('https://idp.example.com/.well-known/openid-configuration?x=1')
        self.assertEqual((status, body), (200, b'{"ok":1}'))
        method, url, kw = Session.last.calls[0]
        self.assertEqual(url, f'https://{PUBLIC}/.well-known/openid-configuration?x=1')
        self.assertEqual(kw['headers']['Host'], 'idp.example.com')
        self.assertIs(kw['allow_redirects'], False)
        self.assertNotIn('verify', kw)  # the default, True: never switched off
        self.assertFalse(Session.last.trust_env)
        self.assertTrue(Session.reply.closed)

    def test_post_sends_the_form_and_basic_auth_to_the_pinned_address(self):
        Session.reply = Resp(200, b'{}')
        self.fetch('https://idp.example.com/token', 'post', data={'code': 'c'}, auth=('id', 's'))
        method, url, kw = Session.last.calls[0]
        self.assertEqual((method, url, kw['data'], kw['auth']), ('post', f'https://{PUBLIC}/token', {'code': 'c'}, ('id', 's')))

    def test_a_redirect_is_reported_not_followed(self):
        Session.reply = Resp(302, b'')
        status, _ = self.fetch('https://idp.example.com/x')
        self.assertEqual(status, 302)
        self.assertIs(Session.last.calls[0][2]['allow_redirects'], False)

    def test_size_cap_and_transport_errors(self):
        Session.reply = Resp(200, chunks=[b'x' * 300000, b'x' * 300000])
        with self.assertRaises(http.FetchError):
            self.fetch('https://idp.example.com/x')

        class Boom(Session):
            def get(self, *a, **k):
                raise requests.exceptions.SSLError('secret detail https://idp.example.com/?code=abc')
        with self.assertRaises(http.FetchError) as cm:
            http.fetch('get', 'https://idp.example.com/x', resolve=resolver(PUBLIC), session_factory=Boom)
        self.assertNotIn('code=abc', str(cm.exception))
        self.assertNotIn('secret detail', str(cm.exception))

    def test_only_get_and_post(self):
        with self.assertRaises(http.FetchError):
            self.fetch('https://idp.example.com/', 'delete')


class DiscoveryTest(SsoBase):
    def discovery_with(self, **over):
        self.idp.discovery = {**self.idp.discovery, **over}
        cache.clear()

    def test_issuer_must_match_exactly(self):
        for issuer in (ISSUER + '/', 'https://evil.example.test', 'http://idp.example.com'):
            self.discovery_with(issuer=issuer)
            with self.assertRaises(provider.ProviderError) as cm:
                provider.discovery()
            self.assertEqual(cm.exception.reason, 'discovery_issuer_mismatch')

    def test_endpoints_must_be_https(self):
        for name in ('authorization_endpoint', 'token_endpoint', 'jwks_uri'):
            for bad in ('http://idp.example.com/x', 'javascript:alert(1)', '', None, 5, 'https://u:p@idp.example.com/x'):
                self.discovery_with(**{name: bad})
                with self.assertRaises(provider.ProviderError, msg=(name, bad)):
                    provider.discovery()

    def test_pkce_s256_must_be_offered_if_the_list_is_given(self):
        self.discovery_with(code_challenge_methods_supported=['plain'])
        with self.assertRaises(provider.ProviderError):
            provider.discovery()

    def test_discovery_is_cached(self):
        provider.discovery()
        provider.discovery()
        self.assertEqual(sum(1 for m, u in self.idp.calls if u.endswith('openid-configuration')), 1)

    def test_a_jwks_uri_pointing_inside_is_refused_by_the_real_fetch(self):
        real = REAL_FETCH
        self.idp.discovery['jwks_uri'] = 'https://169.254.169.254/keys'

        def route(method, url, **kw):
            return self.idp.fetch(method, url, **kw) if url.startswith(ISSUER) else real(method, url, **kw)
        with mock.patch('sso.http.fetch', side_effect=route):
            with self.assertRaises(provider.ProviderError) as cm:
                provider.validate_id_token(sign({'sub': 'x'}), 'n')
        self.assertEqual(cm.exception.reason, 'jwks_unreachable')

    def test_a_private_issuer_never_gets_a_request_and_login_fails_cleanly(self):
        with override_settings(OIDC_ISSUER='https://10.0.0.5'):
            with mock.patch('sso.http.fetch', side_effect=REAL_FETCH) as f:
                r = self.client.get('/sso/login/')
        self.assertEqual((r.status_code, r['Location']), (302, '/login/'))
        self.assertTrue(f.called)  # asked, and refused inside fetch: nothing was connected to

    def test_non_json_and_non_200_discovery(self):
        for reply in ((200, b'<html>'), (200, b'[]'), (500, b'{}'), (404, b'')):
            cache.clear()
            with mock.patch('sso.http.fetch', return_value=reply):
                with self.assertRaises(provider.ProviderError):
                    provider.discovery()


class PagesTest(SsoBase):
    def test_button_only_when_enabled_and_working(self):
        page = self.client.get('/login/').content.decode()
        self.assertIn('Sign in with SSO', page)
        self.assertIn('name="password"', page)
        for ov in ({'OIDC_ENABLED': False}, {'OIDC_CLIENT_SECRET': ''}, {'OIDC_ISSUER': 'http://idp.example.com'},
                   {'OIDC_REDIRECT_BASE': ''}, {'OIDC_REDIRECT_BASE': 'https://x.example/path'},
                   {'OIDC_REDIRECT_BASE': 'http://limes.example.test'}):
            with override_settings(**ov):
                self.assertNotIn('Sign in with SSO', self.client.get('/login/').content.decode(), ov)
                self.assertEqual(self.client.get('/sso/login/').status_code, 404, ov)
                self.assertEqual(self.client.get('/sso/callback/').status_code, 404, ov)

    def test_button_carries_next_escaped(self):
        page = self.client.get('/login/?next=/p1/assets%3Fa%3D1%26b%3D%22%3E%3Cscript%3E').content.decode()
        self.assertNotIn('"><script>', page)
        self.assertIn('/sso/login/?next=', page)

    def test_local_login_switch(self):
        from django.contrib.auth import get_user_model
        get_user_model().objects.create_user('pw', password='pw-123456')
        with override_settings(LOCAL_LOGIN=False):
            page = self.client.get('/login/').content.decode()
            self.assertIn('Sign in with SSO', page)
            self.assertNotIn('name="password"', page)
            r = self.client.post('/login/', {'username': 'pw', 'password': 'pw-123456'})
            self.assertEqual(r.status_code, 403)
            self.assertNotIn('_auth_user_id', self.client.session)
        r = self.client.post('/login/', {'username': 'pw', 'password': 'pw-123456'})  # on again
        self.assertEqual(r.status_code, 302)

    def test_a_broken_sso_config_cannot_lock_everyone_out(self):
        from django.contrib.auth import get_user_model
        get_user_model().objects.create_user('pw', password='pw-123456')
        with override_settings(LOCAL_LOGIN=False, OIDC_CLIENT_SECRET=''):
            self.assertIn('name="password"', self.client.get('/login/').content.decode())
            self.assertEqual(self.client.post('/login/', {'username': 'pw', 'password': 'pw-123456'}).status_code, 302)

    def test_sso_pages_work_without_a_session_and_only_with_get(self):
        self.assertEqual(self.client.get('/sso/login/').status_code, 302)
        self.assertEqual(self.client.post('/sso/login/').status_code, 405)
        self.assertEqual(self.client.post('/sso/callback/').status_code, 405)
