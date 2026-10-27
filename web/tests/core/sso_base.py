"""A fake OpenID provider for the SSO tests (not a test module): real RSA/EC keys, a JWKS, a token endpoint that checks
the PKCE verifier, and a signer that can produce every kind of bad token. sso.http.fetch is replaced by it, so the
tests never touch the network."""
import base64
import hashlib
import hmac
import json
import time
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.core.cache import cache
from django.test import Client, TestCase, override_settings

import tests.core
from dashboard.models import Project
from dashboard.views import on_user_logged_in, on_user_logged_out
from django.utils import timezone

ISSUER = 'https://idp.example.test'
CLIENT = 'limes-client'
SECRET = 'S3CR3T-do-not-leak-9f2a'
BASE = 'https://limes.example.test'
CALLBACK = BASE + '/sso/callback/'

RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EC_KEY = ec.generate_private_key(ec.SECP256R1())


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def _num(n):
    return b64(n.to_bytes((n.bit_length() + 7) // 8, 'big'))


def rsa_jwk(key, kid):
    n = key.public_key().public_numbers()
    return {'kty': 'RSA', 'kid': kid, 'use': 'sig', 'alg': 'RS256', 'n': _num(n.n), 'e': _num(n.e)}


def ec_jwk(key, kid):
    n = key.public_key().public_numbers()
    return {'kty': 'EC', 'crv': 'P-256', 'kid': kid, 'use': 'sig', 'x': _num(n.x), 'y': _num(n.y)}


def public_pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def sign(claims, key=RSA_KEY, alg='RS256', kid='k1', header=None):
    h = {'alg': alg, 'typ': 'JWT'}
    if kid:
        h['kid'] = kid
    h.update(header or {})
    signing = b64(json.dumps(h).encode()) + '.' + b64(json.dumps(claims).encode())
    if alg == 'RS256':
        sig = key.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256())
    elif alg == 'ES256':
        r, s = decode_dss_signature(key.sign(signing.encode(), ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    elif alg == 'HS256':  # `key` is the HMAC secret, e.g. the public key PEM
        sig = hmac.new(key, signing.encode(), hashlib.sha256).digest()
    elif alg == 'none':
        sig = b''
    else:
        raise ValueError(alg)
    return signing + '.' + b64(sig)


class FakeProvider:
    def __init__(self):
        self.jwks = {'keys': [rsa_jwk(RSA_KEY, 'k1'), ec_jwk(EC_KEY, 'e1')]}
        self.discovery = {
            'issuer': ISSUER, 'authorization_endpoint': ISSUER + '/authorize', 'token_endpoint': ISSUER + '/token',
            'jwks_uri': ISSUER + '/keys', 'code_challenge_methods_supported': ['S256'],
            'token_endpoint_auth_methods_supported': ['client_secret_post']}
        self.codes = {}
        self.calls = []
        self.token_form = None
        self.build = None  # test hook: build(claims, ctx) -> id_token string
        self.token_status = 200

    def authorize(self, location, **claims):
        """What the provider does when the browser arrives: remember the request, issue a code."""
        q = {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}
        assert q['response_type'] == 'code' and q['code_challenge_method'] == 'S256', q
        assert q['client_id'] == CLIENT and q['redirect_uri'] == CALLBACK, q
        code = f'code-{len(self.codes)}'
        self.codes[code] = {'challenge': q['code_challenge'], 'nonce': q['nonce'], 'claims': claims}
        return code, q['state']

    def claims(self, _nonce, **over):
        now = int(time.time())
        c = {'iss': ISSUER, 'aud': CLIENT, 'sub': 'user-1', 'exp': now + 300, 'iat': now, 'nonce': _nonce,
             'email': 'alice@example.test', 'email_verified': True}
        c.update(over)
        return {k: v for k, v in c.items() if v is not ...}  # ... removes a claim

    def fetch(self, method, url, data=None, headers=None, auth=None, **kw):
        self.calls.append((method, url))
        if url == ISSUER + '/.well-known/openid-configuration':
            return 200, json.dumps(self.discovery).encode()
        if url == self.discovery['jwks_uri']:
            return 200, json.dumps(self.jwks).encode()
        if url == self.discovery['token_endpoint'] and method == 'post':
            self.token_form = dict(data)
            if self.token_status != 200:
                return self.token_status, b'{"error":"invalid_grant"}'
            entry = self.codes.get(data.get('code'))
            assert entry, 'unknown code'
            assert data['client_secret'] == SECRET and data['redirect_uri'] == CALLBACK
            verifier = data['code_verifier']
            assert b64(hashlib.sha256(verifier.encode()).digest()) == entry['challenge'], 'PKCE mismatch'
            claims = self.claims(entry['nonce'], **entry['claims'])
            token = self.build(claims, entry) if self.build else sign(claims)
            return 200, json.dumps({'id_token': token, 'access_token': 'at', 'token_type': 'Bearer'}).encode()
        raise AssertionError(f'unexpected request {method} {url}')


class SsoBase(TestCase):
    def setUp(self):
        tests.core.ENABLED = False
        for signal, handler in ((user_logged_in, on_user_logged_in), (user_logged_out, on_user_logged_out)):
            signal.disconnect(handler)  # they post flash messages, which a bare Client.logout() has no storage for
            self.addCleanup(signal.connect, handler)
        self.addCleanup(setattr, tests.core, 'ENABLED', True)
        cache.clear()
        self.addCleanup(cache.clear)
        self.idp = FakeProvider()
        patch = mock.patch('sso.http.fetch', side_effect=self.idp.fetch)
        patch.start()
        self.addCleanup(patch.stop)
        ov = override_settings(OIDC_ENABLED=True, OIDC_ISSUER=ISSUER, OIDC_CLIENT_ID=CLIENT, OIDC_CLIENT_SECRET=SECRET,
                               OIDC_REDIRECT_BASE=BASE, OIDC_SCOPES='openid email profile', OIDC_ALLOWED_DOMAINS=[],
                               OIDC_AUTO_CREATE=False, OIDC_DEFAULT_ROLE='read_only', OIDC_DEFAULT_PROJECTS=[],
                               OIDC_LINK_BY_EMAIL=False, LOCAL_LOGIN=True)
        ov.enable()
        self.addCleanup(ov.disable)
        self.p1 = Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())
        self.c = Client()

    def start(self, c=None, **query):
        r = (c or self.c).get('/sso/login/', query)
        return r

    def login(self, c=None, claims=None, next=None):
        """Run the whole dance as the browser would; returns the callback response."""
        c = c or self.c
        r = self.start(c, **({'next': next} if next is not None else {}))
        assert r.status_code == 302 and r['Location'].startswith(ISSUER + '/authorize'), (r.status_code, r.get('Location'))
        code, state = self.idp.authorize(r['Location'], **(claims or {}))
        return c.get('/sso/callback/', {'code': code, 'state': state})
