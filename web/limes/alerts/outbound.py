"""The one way alert rules reach a third-party endpoint (webhook, Slack, Jira): https only, the host resolved once and
vetted public (limes.safe_fetch), the connection pinned to that IP, no redirects, bounded time.
Error text never carries the URL or the exception text: the URL is often the secret."""
import requests

from limes import scope
from limes.checks import collect
from limes.safe_fetch import Deadline, pinned_get, resolve_vetted

MAX_URL = 500
TIMEOUT = 10


class OutboundError(Exception):
    """transient = worth retrying (network failure, 429, 5xx); anything else is final."""
    def __init__(self, message, transient=False):
        super().__init__(message)
        self.transient = transient


def validate_url(url):
    """None for an acceptable destination, else the reason. Syntax only: DNS is vetted at send time (request)."""
    if not isinstance(url, str) or not url or len(url) > MAX_URL or '\\' in url or any(c.isspace() for c in url):
        return 'enter a valid https URL'
    try:
        parts = requests.utils.urlparse(url)
        parts.port
    except ValueError:
        return 'enter a valid https URL'
    host = scope.target_host(url)
    if parts.scheme.lower() != 'https':
        return 'the URL must use https'
    if not host or '@' in parts.netloc:
        return 'enter a valid https URL without credentials'
    ip = scope.parse_ip(host)
    if (ip is not None and scope.is_reserved_ip(ip)) or scope.is_internal_name(host):
        return 'the URL must be a public host'
    return None


def request(method, url, resolve=collect._resolve, session_factory=requests.Session, **kw):
    """Send one request; the Response for a 2xx, else OutboundError."""
    reason = validate_url(url)
    if reason:
        raise OutboundError(reason)
    host = scope.target_host(url)
    ip, why = resolve_vetted(host, resolve=resolve)
    if why:
        raise OutboundError('the host did not resolve to a public address', transient='lookup failed' in why)
    try:
        resp = pinned_get(host, ip, session_factory=session_factory, deadline=Deadline(TIMEOUT), method=method)(
            url, timeout=TIMEOUT, **kw)
    except requests.exceptions.RequestException as exc:
        raise OutboundError('the request failed (%s)' % type(exc).__name__, transient=True)
    except TimeoutError:
        raise OutboundError('the request timed out', transient=True)
    status = resp.status_code
    if status >= 400:
        raise OutboundError('the endpoint answered HTTP %d' % status, transient=status == 429 or status >= 500)
    if status >= 300:
        raise OutboundError('the endpoint redirected (redirects are not followed)')
    return resp
