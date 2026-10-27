"""SSO settings, read at call time so tests can override them. The client secret is only ever handed to the token
request; nothing here formats it into a string."""
from urllib.parse import urlsplit

from django.conf import settings
from django.urls import reverse

from memberships.models import READ_ONLY, STANDARD

LEEWAY = 60  # seconds of clock skew tolerated on exp / nbf / iat
STATE_TTL = 600  # seconds a login attempt stays valid


def _host_is_local(host):
    return host in ('localhost', '127.0.0.1', '[::1]')


def redirect_uri():
    base = (settings.OIDC_REDIRECT_BASE or '').strip().rstrip('/')
    parts = urlsplit(base)
    ok = (parts.scheme == 'https' or (parts.scheme == 'http' and _host_is_local(parts.hostname or ''))) \
        and parts.hostname and not parts.path and not parts.query and not parts.fragment and '@' not in parts.netloc
    return base + reverse('sso_callback') if ok else None


def problems():
    """What is wrong with the configuration (empty when SSO can run). Never contains a value."""
    out = []
    parts = urlsplit(settings.OIDC_ISSUER or '')
    if parts.scheme != 'https' or not parts.hostname or parts.query or parts.fragment or '@' in parts.netloc:
        out.append('LIMES_OIDC_ISSUER must be an https URL without query or fragment')
    if not settings.OIDC_CLIENT_ID:
        out.append('LIMES_OIDC_CLIENT_ID is empty')
    if not settings.OIDC_CLIENT_SECRET:
        out.append('LIMES_OIDC_CLIENT_SECRET is empty')
    if redirect_uri() is None:
        out.append('LIMES_OIDC_REDIRECT_BASE must be the https origin of this site, e.g. https://limes.example.com')
    return out


def enabled():
    return bool(settings.OIDC_ENABLED) and not problems()


def local_login_allowed():
    """Password login can be switched off only while SSO works, so a misconfiguration never locks everyone out."""
    return bool(settings.LOCAL_LOGIN) or not enabled()


def default_role():
    return settings.OIDC_DEFAULT_ROLE if settings.OIDC_DEFAULT_ROLE in (READ_ONLY, STANDARD) else READ_ONLY  # never admin


def allowed_domains():
    return {d.strip().lower().lstrip('@') for d in settings.OIDC_ALLOWED_DOMAINS if d.strip()}


def scopes():
    wanted = (settings.OIDC_SCOPES or '').split()
    return ' '.join(dict.fromkeys(['openid'] + wanted))  # always asks for openid, once
