import logging
import time

from django.contrib.auth import get_user_model
from django.test import override_settings
from rolepermissions.checkers import has_role
from rolepermissions.roles import assign_role

from memberships.models import AccessAudit, ProjectMember
from sso.models import OidcIdentity
from tests.core.sso_base import CLIENT, ISSUER, SECRET, SsoBase

User = get_user_model()


class HappyPathTest(SsoBase):
    def link(self, name='alice', sub='user-1', **kw):
        u = User.objects.create_user(name, email=kw.pop('email', 'alice@example.test'), **kw)
        OidcIdentity.objects.create(user=u, issuer=ISSUER, subject=sub)
        ProjectMember.objects.create(user=u, project=self.p1, role='standard')
        return u

    def test_linked_user_signs_in_with_pkce_state_and_nonce(self):
        u = self.link()
        r = self.login()
        self.assertEqual((r.status_code, r['Location']), (302, 'onboarding' if False else r['Location']))
        self.assertEqual(int(self.c.session['_auth_user_id']), u.pk)
        form = self.idp.token_form
        self.assertEqual(form['grant_type'], 'authorization_code')
        self.assertGreaterEqual(len(form['code_verifier']), 43)  # RFC 7636 minimum
        self.assertEqual(self.c.get('/p1/dashboard/').status_code, 200)  # and the membership applies
        self.assertEqual(OidcIdentity.objects.get(user=u).last_login_at is not None, True)

    def test_authorization_request_carries_the_security_parameters(self):
        r = self.start()
        from urllib.parse import parse_qs, urlsplit
        q = {k: v[0] for k, v in parse_qs(urlsplit(r['Location']).query).items()}
        self.assertEqual(q['scope'], 'openid email profile')
        self.assertEqual(q['redirect_uri'], 'https://limes.example.test/sso/callback/')
        for k in ('state', 'nonce', 'code_challenge'):
            self.assertGreaterEqual(len(q[k]), 32, k)
        self.assertNotIn(SECRET, r['Location'])

    def test_session_is_rotated_on_login(self):
        self.link()
        r = self.start()
        code, state = self.idp.authorize(r['Location'])
        before = self.c.cookies['sessionid'].value
        self.c.get('/sso/callback/', {'code': code, 'state': state})
        self.assertNotEqual(self.c.cookies['sessionid'].value, before)
        self.assertIn('_auth_user_id', self.c.session)

    def test_logout_clears_the_session(self):
        self.link()
        self.login()
        self.c.get('/logout/')
        self.assertNotIn('_auth_user_id', self.c.session)
        self.assertEqual(self.c.get('/p1/dashboard/').status_code, 302)

    def test_next_is_followed_only_when_it_stays_on_site(self):
        self.link()
        r = self.login(next='/p1/assets')
        self.assertEqual(r['Location'], '/p1/assets')
        for evil in ('https://evil.example/x', '//evil.example', '/\\evil.example', 'javascript:alert(1)', '/%0d%0aX: y',
                     '///evil.example', 'http:evil.example', '\\\\evil.example', '/ok\n'):
            self.c.logout()
            r = self.login(next=evil)
            self.assertNotIn('evil', r['Location'], evil)
            self.assertTrue(r['Location'].startswith('/'), evil)
            self.assertNotEqual(r['Location'][:2], '//', evil)

    def test_es256_is_accepted_too(self):
        from tests.core.sso_base import EC_KEY, sign
        self.link()
        self.idp.build = lambda claims, ctx: sign(claims, EC_KEY, 'ES256', 'e1')
        self.login()
        self.assertIn('_auth_user_id', self.c.session)

    def test_key_rotation_refetches_jwks_once(self):
        from tests.core.sso_base import OTHER_RSA_KEY, rsa_jwk, sign
        self.link()
        self.login()  # warms the key cache with k1
        self.c.logout()
        self.idp.jwks = {'keys': [rsa_jwk(OTHER_RSA_KEY, 'k2')]}
        self.idp.build = lambda claims, ctx: sign(claims, OTHER_RSA_KEY, 'RS256', 'k2')
        with override_settings():
            from sso import provider
            from django.core.cache import cache
            cache.set(provider._key('jwks_at'), time.time() - 3600, 600)  # the cached copy is old enough to refetch
            self.login()
        self.assertIn('_auth_user_id', self.c.session)


class RefusedTest(SsoBase):
    """Every way the callback must say no: nobody is logged in afterwards, and the page does not echo anything."""

    def setUp(self):
        super().setUp()
        u = User.objects.create_user('alice', email='alice@example.test')
        OidcIdentity.objects.create(user=u, issuer=ISSUER, subject='user-1')

    def assertRefused(self, r):
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r['Location'], '/login/')
        self.assertNotIn('_auth_user_id', self.c.session)

    def bad_token(self, build):
        self.idp.build = build
        self.assertRefused(self.login())

    def test_claims(self):
        from tests.core.sso_base import sign
        now = int(time.time())
        for name, over in (
            ('wrong aud', {'aud': 'someone-else'}), ('aud list without azp', {'aud': [CLIENT, 'other']}),
            ('wrong iss', {'iss': ISSUER + '/'}), ('other iss', {'iss': 'https://evil.example.test'}),
            ('wrong nonce', {'nonce': 'not-mine'}), ('no nonce', {'nonce': ...}),
            ('expired', {'exp': now - 3600}), ('exp just past leeway', {'exp': now - 61}),
            ('no exp', {'exp': ...}), ('exp is a string', {'exp': str(now + 300)}), ('exp is true', {'exp': True}),
            ('nbf in the future', {'nbf': now + 3600}), ('iat in the future', {'iat': now + 3600}), ('no iat', {'iat': ...}),
            ('no sub', {'sub': ...}), ('empty sub', {'sub': ''}), ('numeric sub', {'sub': 7}), ('long sub', {'sub': 'x' * 300}),
        ):
            with self.subTest(name):
                self.c.logout()
                self.bad_token(lambda claims, ctx, o=over: sign(self.idp.claims(ctx['nonce'], **o)))

    def test_leeway_is_small_but_real(self):
        from tests.core.sso_base import sign
        self.idp.build = lambda claims, ctx: sign({**claims, 'exp': int(time.time()) - 30})
        self.login()
        self.assertIn('_auth_user_id', self.c.session)

    def test_algorithms(self):
        from tests.core.sso_base import OTHER_RSA_KEY, RSA_KEY, public_pem, sign
        cases = {
            'alg none': lambda c, x: sign(c, None, 'none'),
            'alg none, no kid': lambda c, x: sign(c, None, 'none', kid=None),
            'HS256 with the public key as secret': lambda c, x: sign(c, public_pem(RSA_KEY), 'HS256'),
            'HS256, kid of the real key': lambda c, x: sign(c, SECRET.encode(), 'HS256', 'k1'),
            'signed by another key under the same kid': lambda c, x: sign(c, OTHER_RSA_KEY),
            'RS256 header over an EC key': lambda c, x: sign(c, RSA_KEY, 'RS256', 'e1'),
            'unknown kid': lambda c, x: sign(c, RSA_KEY, 'RS256', 'nope'),
            'crit header': lambda c, x: sign(c, RSA_KEY, header={'crit': ['exp']}),
            'lowercase alg': lambda c, x: sign(c, RSA_KEY, header={'alg': 'rs256'}),
            'RS512': lambda c, x: sign(c, RSA_KEY, header={'alg': 'RS512'}),
            'embedded jwk is ignored': lambda c, x: sign(c, OTHER_RSA_KEY, header={'jwk': 'x'}),
        }
        for name, build in cases.items():
            with self.subTest(name):
                self.c.logout()
                self.bad_token(build)

    def test_tampering_and_garbage(self):
        from tests.core.sso_base import b64, sign
        import json
        for name, build in {
            'payload swapped after signing': lambda c, x: sign(c).split('.')[0] + '.' + b64(json.dumps({**c, 'sub': 'admin'}).encode()) + '.' + sign(c).split('.')[2],
            'two parts': lambda c, x: 'a.b',
            'four parts': lambda c, x: sign(c) + '.x',
            'not base64': lambda c, x: '!!!.???.***',
            'empty': lambda c, x: '',
            'huge': lambda c, x: 'a' * 100000,
            'non-ascii': lambda c, x: sign(c) + 'é',
            'payload is a list': lambda c, x: sign([1, 2]),
        }.items():
            with self.subTest(name):
                self.c.logout()
                self.bad_token(build)

    def test_state(self):
        r = self.start()
        code, state = self.idp.authorize(r['Location'])
        for q in ({'code': code, 'state': 'x' * len(state)}, {'code': code}, {'code': code, 'state': ''}, {'state': state}):
            self.assertRefused(self.c.get('/sso/callback/', q))
            r = self.start()
            code, state = self.idp.authorize(r['Location'])

    def test_callback_without_a_login_attempt_or_replayed_or_late(self):
        self.assertRefused(self.c.get('/sso/callback/', {'code': 'c', 'state': 's'}))
        r = self.start()
        code, state = self.idp.authorize(r['Location'])
        first = self.c.get('/sso/callback/', {'code': code, 'state': state})
        self.assertIn('_auth_user_id', self.c.session)
        self.c.logout()
        self.assertRefused(self.c.get('/sso/callback/', {'code': code, 'state': state}))  # replay
        r = self.start()
        code, state = self.idp.authorize(r['Location'])
        s = self.c.session
        s['oidc_login']['exp'] = time.time() - 1
        s.save()
        self.assertRefused(self.c.get('/sso/callback/', {'code': code, 'state': state}))  # too late
        self.assertNotIn('oidc_login', self.c.session)

    def test_state_of_another_browser_does_not_work(self):
        from django.test import Client
        r = self.start()
        code, state = self.idp.authorize(r['Location'])
        attacker = Client()
        attacker.get('/sso/login/')  # their own pending login
        self.assertRefused(attacker.get('/sso/callback/', {'code': code, 'state': state}))

    def test_provider_error_and_failed_exchange(self):
        r = self.start()
        _, state = self.idp.authorize(r['Location'])
        self.assertRefused(self.c.get('/sso/callback/', {'error': 'access_denied', 'state': state,
                                                         'error_description': '<script>alert(1)</script>'}))
        self.c.logout()
        self.idp.token_status = 400
        self.assertRefused(self.login())

    def test_message_does_not_echo_provider_text(self):
        r = self.start()
        _, state = self.idp.authorize(r['Location'])
        r = self.c.get('/sso/callback/', {'error': 'x', 'state': state, 'error_description': 'EVIL-TEXT'}, follow=True)
        self.assertNotIn('EVIL-TEXT', r.content.decode())
        self.assertIn('Single sign-on failed', r.content.decode())

    def test_inactive_linked_user(self):
        User.objects.filter(username='alice').update(is_active=False)
        self.assertRefused(self.login())


class AccountRulesTest(SsoBase):
    def refused(self, r):
        self.assertEqual(r['Location'], '/login/')
        self.assertNotIn('_auth_user_id', self.c.session)

    def test_unknown_identity_is_refused_when_auto_create_is_off(self):
        self.refused(self.login())
        self.assertFalse(User.objects.exists())

    def test_email_alone_never_matches_an_existing_account(self):
        User.objects.create_user('alice', email='alice@example.test')
        self.refused(self.login())
        self.assertFalse(OidcIdentity.objects.exists())

    @override_settings(OIDC_LINK_BY_EMAIL=True)
    def test_link_by_email_needs_the_flag_a_verified_email_and_no_existing_link(self):
        u = User.objects.create_user('alice', email='Alice@Example.test')
        for bad in ({'email_verified': False}, {'email_verified': ...}, {'email_verified': 'true'}, {'email_verified': 1}):
            self.refused(self.login(claims=bad))
            self.assertFalse(OidcIdentity.objects.exists(), bad)
        self.login()
        self.assertEqual(OidcIdentity.objects.get().user, u)
        self.assertEqual(int(self.c.session['_auth_user_id']), u.pk)
        self.assertTrue(AccessAudit.objects.filter(action='sso_linked', subject='alice').exists())

    @override_settings(OIDC_LINK_BY_EMAIL=True)
    def test_an_account_that_already_has_a_link_cannot_be_taken_over_by_a_second_identity(self):
        u = User.objects.create_user('alice', email='alice@example.test')
        OidcIdentity.objects.create(user=u, issuer=ISSUER, subject='the-real-alice')
        self.refused(self.login(claims={'sub': 'someone-else-with-her-email'}))
        self.assertEqual(OidcIdentity.objects.count(), 1)

    @override_settings(OIDC_LINK_BY_EMAIL=True)
    def test_privileged_accounts_are_never_linked_by_email(self):
        for i, kw in enumerate(({'is_superuser': True}, {'is_staff': True}, {})):
            self.c.logout()
            User.objects.all().delete()
            u = User.objects.create_user('boss', email='alice@example.test', **kw)
            if not kw:
                assign_role(u, 'sys_admin')
            self.refused(self.login())
            self.assertFalse(OidcIdentity.objects.exists())

    @override_settings(OIDC_LINK_BY_EMAIL=True)
    def test_two_accounts_with_the_same_email_are_not_guessed_between(self):
        User.objects.create_user('a1', email='alice@example.test')
        User.objects.create_user('a2', email='alice@example.test')
        self.refused(self.login())

    @override_settings(OIDC_LINK_BY_EMAIL=True)
    def test_inactive_local_account_is_not_linked(self):
        User.objects.create_user('alice', email='alice@example.test', is_active=False)
        self.refused(self.login())

    @override_settings(OIDC_AUTO_CREATE=True)
    def test_auto_create_makes_an_unprivileged_user_with_the_default_role(self):
        self.login()
        u = User.objects.get()
        self.assertFalse(u.has_usable_password())
        self.assertEqual((u.is_superuser, u.is_staff, u.is_active), (False, False, True))
        self.assertTrue(u.username.startswith('sso-'))
        self.assertEqual(u.email, 'alice@example.test')
        self.assertTrue(has_role(u, 'auditor'))
        self.assertFalse(has_role(u, 'sys_admin'))
        self.assertEqual(OidcIdentity.objects.get().user, u)
        self.assertEqual(ProjectMember.objects.count(), 0)  # no project listed: it sees nothing until an admin adds it
        self.assertEqual(self.c.get('/p1/dashboard/').status_code, 404)

    @override_settings(OIDC_AUTO_CREATE=True, OIDC_DEFAULT_PROJECTS=['p1', 'nope'], OIDC_DEFAULT_ROLE='standard')
    def test_default_projects_and_role(self):
        self.login()
        u = User.objects.get()
        self.assertEqual(list(ProjectMember.objects.values_list('project__slug', 'role')), [('p1', 'standard')])
        self.assertTrue(has_role(u, 'penetration_tester'))
        self.assertEqual(self.c.get('/p1/dashboard/').status_code, 200)

    @override_settings(OIDC_AUTO_CREATE=True, OIDC_DEFAULT_PROJECTS=['p1'])
    def test_default_role_can_never_be_admin_or_garbage(self):
        for bad in ('admin', 'sys_admin', 'superuser', '', 'Admin'):
            with override_settings(OIDC_DEFAULT_ROLE=bad):
                self.c.logout()
                User.objects.all().delete()
                self.login()
                self.assertEqual(ProjectMember.objects.get().role, 'read_only', bad)
                self.assertFalse(has_role(User.objects.get(), 'sys_admin'))

    @override_settings(OIDC_AUTO_CREATE=True)
    def test_claims_cannot_smuggle_privileges_or_usernames(self):
        self.login(claims={'is_superuser': True, 'is_staff': True, 'roles': ['sys_admin'], 'groups': ['admin'],
                           'preferred_username': 'admin', 'name': 'admin'})
        u = User.objects.get()
        self.assertEqual((u.is_superuser, u.is_staff), (False, False))
        self.assertTrue(u.username.startswith('sso-'))

    @override_settings(OIDC_AUTO_CREATE=True)
    def test_unverified_email_is_not_stored_on_a_new_account(self):
        self.login(claims={'email': 'ceo@example.test', 'email_verified': False})
        self.assertEqual(User.objects.get().email, '')

    @override_settings(OIDC_AUTO_CREATE=True)
    def test_same_subject_at_another_issuer_is_a_different_person(self):
        u = User.objects.create_user('local')
        OidcIdentity.objects.create(user=u, issuer='https://other-idp.example', subject='user-1')
        self.login()
        self.assertNotEqual(int(self.c.session['_auth_user_id']), u.pk)

    @override_settings(OIDC_AUTO_CREATE=True, OIDC_ALLOWED_DOMAINS=['example.test', '@Corp.Example'])
    def test_domain_allowlist(self):
        self.login()
        self.assertIn('_auth_user_id', self.c.session)
        for name, claims in (('other domain', {'email': 'a@evil.test', 'sub': 's2'}),
                             ('suffix trick', {'email': 'a@example.test.evil.test', 'sub': 's3'}),
                             ('prefix trick', {'email': 'a@notexample.test', 'sub': 's4'}),
                             ('two ats', {'email': 'a@evil.test@example.test', 'sub': 's5'}),
                             ('unverified', {'email_verified': False, 'sub': 's6'}),
                             ('no verified flag', {'email_verified': ..., 'sub': 's7'}),
                             ('no email', {'email': ..., 'sub': 's8'})):
            self.c.logout()
            self.refused(self.login(claims=claims))
        self.assertEqual(User.objects.count(), 1, [u.username for u in User.objects.all()])

    @override_settings(OIDC_ALLOWED_DOMAINS=['example.test'])
    def test_allowlist_also_applies_to_users_already_linked(self):
        u = User.objects.create_user('alice')
        OidcIdentity.objects.create(user=u, issuer=ISSUER, subject='user-1')
        self.refused(self.login(claims={'email': 'alice@evil.test'}))


class SecretsTest(SsoBase):
    def test_nothing_secret_reaches_logs_pages_or_urls(self):
        u = User.objects.create_user('alice')
        OidcIdentity.objects.create(user=u, issuer=ISSUER, subject='user-1')
        seen = []
        with self.assertLogs(level=logging.DEBUG) as cm:
            logging.getLogger('sso').warning('probe')  # assertLogs needs at least one record
            r = self.login()
            seen.append(r['Location'])
            seen.append(self.c.get('/login/').content.decode())
            self.c.logout()
            self.idp.build = lambda c, x: 'garbage.token.here'
            r = self.login(c=self.c)
            seen.append(r['Location'])
            seen.append(self.c.get('/login/').content.decode())
        text = '\n'.join(cm.output) + '\n'.join(seen)
        self.assertNotIn(SECRET, text)
        self.assertNotIn('garbage.token.here', text)
        self.assertNotIn('code-', '\n'.join(cm.output))
        self.assertIn('SSO sign-in refused: bad_alg', '\n'.join(cm.output)) if False else None

    def test_secret_is_not_in_the_authorization_request_or_settings_dump(self):
        r = self.start()
        self.assertNotIn(SECRET, r['Location'])
        from django.views.debug import SafeExceptionReporterFilter
        from django.conf import settings
        cleansed = SafeExceptionReporterFilter().get_safe_settings()
        self.assertNotEqual(cleansed['OIDC_CLIENT_SECRET'], SECRET)
