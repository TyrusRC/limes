"""Talking to the provider: discovery, signing keys and the code exchange. Everything goes through sso.http.fetch."""
import hashlib
import json
import time
from urllib.parse import urlsplit

from django.conf import settings
from django.core.cache import cache

from sso import config, http
from sso.jwt import TokenError, verify

DISCOVERY_TTL = 3600
JWKS_TTL = 300
JWKS_REFETCH_AFTER = 30  # an unknown kid may trigger a refetch, but not more often than this


class ProviderError(Exception):
    """The provider is misconfigured, unreachable or answered wrongly. `reason` is a short code, safe to log."""
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _key(name):
    digest = hashlib.sha256(f'{settings.OIDC_ISSUER}\n{settings.OIDC_CLIENT_ID}'.encode()).hexdigest()[:16]
    return f'limes:sso:{name}:{digest}'


def _get_json(url, what):
    try:
        status, body = http.fetch('get', url)
    except http.FetchError:
        raise ProviderError(f'{what}_unreachable')
    if status != 200:
        raise ProviderError(f'{what}_status')
    try:
        out = json.loads(body)
    except ValueError:
        raise ProviderError(f'{what}_malformed')
    if not isinstance(out, dict):
        raise ProviderError(f'{what}_malformed')
    return out


def _https(url):
    try:
        p = urlsplit(url) if isinstance(url, str) else None
        return bool(p and p.scheme == 'https' and p.hostname and '@' not in p.netloc and not p.fragment)
    except ValueError:
        return False


def discovery():
    cached = cache.get(_key('disc'))
    if cached:
        return cached
    issuer = settings.OIDC_ISSUER
    doc = _get_json(issuer.rstrip('/') + '/.well-known/openid-configuration', 'discovery')
    if doc.get('issuer') != issuer:  # exact match, as the spec demands: a mismatch is a mix-up attack or a typo
        raise ProviderError('discovery_issuer_mismatch')
    for name in ('authorization_endpoint', 'token_endpoint', 'jwks_uri'):
        if not _https(doc.get(name)):
            raise ProviderError(f'discovery_bad_{name}')
    methods = doc.get('code_challenge_methods_supported')
    if methods is not None and 'S256' not in methods:
        raise ProviderError('discovery_no_s256')
    cache.set(_key('disc'), doc, DISCOVERY_TTL)
    return doc


def _jwks(force=False):
    ck, tk = _key('jwks'), _key('jwks_at')
    if not force:
        cached = cache.get(ck)
        if cached:
            return cached
    elif time.time() - (cache.get(tk) or 0) < JWKS_REFETCH_AFTER:
        return cache.get(ck) or _jwks()  # refetched very recently: the kid really is unknown
    doc = _get_json(discovery()['jwks_uri'], 'jwks')
    cache.set(ck, doc, JWKS_TTL)
    cache.set(tk, time.time(), JWKS_TTL)
    return doc


def exchange_code(code, verifier):
    """Trade the authorization code for the raw id_token string."""
    doc = discovery()
    form = {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': config.redirect_uri(),
            'client_id': settings.OIDC_CLIENT_ID, 'code_verifier': verifier}
    supported = doc.get('token_endpoint_auth_methods_supported') or ['client_secret_basic']
    auth = None
    if 'client_secret_post' in supported:
        form['client_secret'] = settings.OIDC_CLIENT_SECRET
    else:
        auth = (settings.OIDC_CLIENT_ID, settings.OIDC_CLIENT_SECRET)
    try:
        status, body = http.fetch('post', doc['token_endpoint'], data=form, auth=auth,
                                  headers={'Accept': 'application/json'})
    except http.FetchError:
        raise ProviderError('token_unreachable')
    try:
        out = json.loads(body)
    except ValueError:
        out = None
    if status != 200 or not isinstance(out, dict) or not isinstance(out.get('id_token'), str):
        raise ProviderError('token_rejected')
    return out['id_token']


def validate_id_token(id_token, nonce, now=None):
    now = time.time() if now is None else now
    claims = dict(issuer=settings.OIDC_ISSUER, audience=settings.OIDC_CLIENT_ID, nonce=nonce, now=now, leeway=config.LEEWAY)
    try:
        return verify(id_token, _jwks(), **claims)
    except TokenError as e:
        if e.reason != 'unknown_kid':
            raise
    return verify(id_token, _jwks(force=True), **claims)  # key rotation: look once more
