"""SSO review fixes: email takeover, audit of default grants, rate limits."""
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import override_settings
from redis.exceptions import RedisError

from memberships import services
from memberships.models import AccessAudit, ProjectMember
from sso import accounts
from sso.models import OidcIdentity
from tests.core.sso_base import SsoBase

User = get_user_model()


class EmailLinkTest(SsoBase):
    def setUp(self):
        super().setUp()
        ov = override_settings(OIDC_LINK_BY_EMAIL=True)  # after SsoBase's own overrides, which switch it off
        ov.enable()
        self.addCleanup(ov.disable)

    def victim(self, email='admin@corp.test'):
        return User.objects.create_user('victim', email=email)

    def claims(self, email, sub='attacker', verified=True):
        return {'sub': sub, 'email': email, 'email_verified': verified}

    def test_lookalike_emails_never_link(self):
        self.victim()
        for evil in ('admın@corp.test', 'admin@corp.test'.replace('a', 'ａ'), 'admin@cörp.test',
                     'ａdmin@corp.test', 'admın@corp.test', 'ſam@corp.test', 'admin@corp.test​',
                     'admin․@corp.test', 'ADMİN@corp.test'):
            with self.assertRaises(accounts.Refused, msg=repr(evil)):
                accounts.resolve(self.claims(evil, sub='s-' + evil))
        self.assertFalse(OidcIdentity.objects.exists())

    def test_a_non_ascii_stored_email_is_not_matched_by_an_ascii_claim(self):
        User.objects.create_user('v2', email='admın@corp.test')  # stored with a dotless i; Postgres folds it to I
        with self.assertRaises(accounts.Refused):
            accounts.resolve(self.claims('admin@corp.test'))

    def test_exact_ascii_match_ignoring_case_still_links(self):
        v = self.victim('Alice@Corp.Test')
        self.assertEqual(accounts.resolve(self.claims('alice@corp.test')), v)

    def test_non_ascii_email_is_not_even_stored_or_domain_checked(self):
        self.assertEqual(accounts.email_of({'email': 'a@ü.test', 'email_verified': True}), ('', False))
        with override_settings(OIDC_ALLOWED_DOMAINS=['corp.test']):
            with self.assertRaises(accounts.Refused):
                accounts.resolve(self.claims('a@corp.test​'))

    def test_member_lookup_is_exact_too(self):
        User.objects.create_user('real', email='admin@corp.test')
        with self.assertRaises(services.MemberError):
            services.find_user('admın@corp.test')
        self.assertEqual(services.find_user('ADMIN@corp.test').username, 'real')


class AuditAndRateTest(SsoBase):
    @override_settings(OIDC_AUTO_CREATE=True, OIDC_DEFAULT_PROJECTS=['p1'])
    def test_default_project_grants_are_audited_per_project(self):
        self.login()
        a = AccessAudit.objects.get(action='member_added', project=self.p1)
        self.assertEqual(a.detail, 'sso default project, role read_only')
        self.assertTrue(a.subject.startswith('sso-'))

    def test_login_and_callback_are_rate_limited_per_address(self):
        with override_settings(SSO_RATE_PER_MIN=3):
            codes = [self.client.get('/sso/login/').status_code for _ in range(5)]
            self.assertEqual(codes, [302, 302, 302, 429, 429])
            self.assertEqual(self.client.get('/sso/callback/', {'code': 'x', 'state': 'y'}).status_code, 429)
            other = self.client_class(REMOTE_ADDR='8.8.8.8')
            self.assertEqual(other.get('/sso/login/').status_code, 302)

    def test_rate_limiter_down_fails_closed(self):
        with mock.patch('sso.views.ratelimit.take', side_effect=RedisError('down')):
            self.assertEqual(self.client.get('/sso/login/').status_code, 503)
            self.assertEqual(self.client.get('/sso/callback/').status_code, 503)

    def test_a_forged_real_ip_header_from_the_internet_does_not_buy_a_fresh_bucket(self):
        with override_settings(SSO_RATE_PER_MIN=2):
            c = self.client_class(REMOTE_ADDR='8.8.4.4')
            for i in range(3):
                r = c.get('/sso/login/', HTTP_X_REAL_IP=f'198.51.100.{i}')
            self.assertEqual(r.status_code, 429)

    def test_behind_the_proxy_each_client_address_has_its_own_bucket(self):
        with override_settings(SSO_RATE_PER_MIN=2):
            c = self.client_class(REMOTE_ADDR='172.18.0.5')
            for ip in ('198.51.100.1', '198.51.100.1', '198.51.100.2'):
                r = c.get('/sso/login/', HTTP_X_REAL_IP=ip)
            self.assertEqual(r.status_code, 302)
            self.assertEqual(c.get('/sso/login/', HTTP_X_REAL_IP='198.51.100.1').status_code, 429)
