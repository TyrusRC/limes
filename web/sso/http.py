"""The only way SSO talks to the provider: https, a public address vetted once and pinned, no redirects, bounded size
and time. Discovery, JWKS and token requests all come through fetch(); tests replace fetch() with a fake provider."""
from urllib.parse import urlsplit

import requests

from limes import safe_fetch
from limes.checks import collect

MAX_BYTES = 512 * 1024


class FetchError(Exception):
    """The provider could not be reached safely. The message never contains a URL query, a body or a secret."""


def fetch(method, url, data=None, headers=None, auth=None, resolve=collect._resolve, session_factory=requests.Session):
    """(status, body bytes). `method` is 'get' or 'post'; `data` is form-encoded for a post."""
    if method not in ('get', 'post'):
        raise FetchError('unsupported method')
    try:
        parts = urlsplit(url or '')
        host, _ = parts.hostname, parts.port
    except ValueError:
        raise FetchError('bad url')
    if parts.scheme != 'https' or not host or '@' in parts.netloc or '\\' in (url or ''):
        raise FetchError('provider urls must be https')
    ip, reason = safe_fetch.resolve_vetted(host, resolve=resolve)
    if reason:
        raise FetchError('provider host refused: not a public address')
    get = safe_fetch.pinned_get(host, ip, session_factory=session_factory, method=method)
    resp = None
    kw = {'stream': True, 'timeout': (5, 10), 'headers': dict(headers or {})}
    if method == 'post':
        kw['data'] = data
    if auth:
        kw['auth'] = auth
    try:
        resp = get(url, **kw)
        body = b''
        for chunk in resp.iter_content(65536):
            body += chunk
            if len(body) > MAX_BYTES:
                raise FetchError('provider response too large')
        return resp.status_code, body
    except requests.exceptions.RequestException as e:
        raise FetchError(f'provider request failed ({type(e).__name__})') from None
    finally:
        if resp is not None:
            resp.close()
