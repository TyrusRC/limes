"""The browser side of the authorization-code flow with PKCE.

login    makes state, nonce and a PKCE verifier, keeps them in the session for ten minutes, and sends the browser to
         the provider.
callback takes them out of the session (so each can be used once), checks state, trades the code for an id token,
         validates it, finds or creates the user, rotates the session and logs in.
Failures show one generic message; the reason code goes to the log, never a token, code or claim."""
import base64
import hashlib
import hmac
import logging
import secrets
import time
from urllib.parse import urlencode

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login as auth_login
from django.contrib.auth.views import LoginView
from django.http import Http404, HttpResponseForbidden
from django.shortcuts import redirect
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET

from sso import accounts, config, provider
from sso.jwt import TokenError

logger = logging.getLogger(__name__)
SESSION_KEY = 'oidc_login'
FAILED = 'Single sign-on failed. Try again, or ask an administrator if it keeps happening.'
REFUSED = 'Your account is not allowed to sign in with single sign-on. Ask an administrator.'


def safe_next(request, value):
    """A same-site path or nothing: no scheme, no host, no protocol-relative or backslash tricks."""
    if (not isinstance(value, str) or not value.startswith('/') or value.startswith('//') or '\\' in value
            or any(ord(c) < 32 for c in value) or len(value) > 500):
        return ''
    return value if url_has_allowed_host_and_scheme(value, allowed_hosts=None, require_https=False) else ''


def _challenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()


def _fail(request, reason, text=FAILED):
    logger.warning('SSO sign-in refused: %s', reason)  # a code only
    messages.error(request, text)
    return redirect('login')


@never_cache
@require_GET
def sso_login(request):
    if not config.enabled():
        raise Http404
    try:
        doc = provider.discovery()
    except provider.ProviderError as e:
        return _fail(request, e.reason)
    state, nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(64)
    request.session[SESSION_KEY] = {'state': state, 'nonce': nonce, 'verifier': verifier,
                                    'next': safe_next(request, request.GET.get('next', '')),
                                    'exp': time.time() + config.STATE_TTL}
    query = urlencode({'response_type': 'code', 'client_id': settings.OIDC_CLIENT_ID,
                       'redirect_uri': config.redirect_uri(), 'scope': config.scopes(), 'state': state,
                       'nonce': nonce, 'code_challenge': _challenge(verifier), 'code_challenge_method': 'S256'})
    sep = '&' if '?' in doc['authorization_endpoint'] else '?'
    return redirect(doc['authorization_endpoint'] + sep + query)


@never_cache
@require_GET
def sso_callback(request):
    if not config.enabled():
        raise Http404
    pending = request.session.pop(SESSION_KEY, None)  # one use: a replayed callback finds nothing
    if not isinstance(pending, dict) or pending.get('exp', 0) < time.time():
        return _fail(request, 'no_pending_login')
    state, code = request.GET.get('state', ''), request.GET.get('code', '')
    if not state or not hmac.compare_digest(state.encode(), str(pending.get('state', '')).encode()):
        return _fail(request, 'state_mismatch')
    if 'error' in request.GET or not code or len(code) > 2048:
        return _fail(request, 'provider_error')
    try:
        id_token = provider.exchange_code(code, pending['verifier'])
        claims = provider.validate_id_token(id_token, pending['nonce'])
    except (provider.ProviderError, TokenError) as e:
        return _fail(request, e.reason)
    try:
        user = accounts.resolve(claims)
    except accounts.Refused as e:
        return _fail(request, e.reason, REFUSED)
    request.session.cycle_key()  # a session id seen before login is never the logged-in one
    auth_login(request, user, backend='django.contrib.auth.backends.ModelBackend')
    return redirect(pending.get('next') or settings.LOGIN_REDIRECT_URL)


class PasswordLoginView(LoginView):
    """The normal login page. With LIMES_LOCAL_LOGIN off (and SSO working) it only offers the SSO button and refuses
    password posts."""
    template_name = 'base/login.html'

    def dispatch(self, request, *args, **kwargs):
        if request.method == 'POST' and not config.local_login_allowed():
            return HttpResponseForbidden('Password sign-in is disabled. Use single sign-on.')
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx.update(sso_enabled=config.enabled(), local_login=config.local_login_allowed())
        return ctx

