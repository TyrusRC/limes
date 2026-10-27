"""Safe contact with targets: resolve a host once, vet every answer, then connect only to the vetted IP.

Resolving again at connect time would let a DNS-rebinding name pass the vetting with a public answer and then
point the connection at 10.0.0.1, so every connection here goes to the IP that resolve_vetted returned. The
hostname still travels as the Host header and the TLS SNI, and certificates are verified against the hostname.

NOTE: connection inventory. The risk checks and the light monitor reach targets in three ways only: requests
(pinned_get), a raw ssl socket (pinned_tls_connect) and dns.resolver (DNS queries, never the target's own
address). The scan tools (subfinder, naabu, httpx, nuclei, vigil, mantis crawling) resolve on their own and
cannot be pinned from here: they stay covered only by the pre-scan root scope guard (limes.scope.may_contact /
may_attack), which checks the IPs of the latest recorded resolution and so remains open to rebinding. Upgrade
path: pin those tools to the vetted IPs (naabu -host <ip>, httpx host-to-IP pinning) or send them through an
egress proxy that vets every connection.
"""
import re
import socket
import ssl
import time
from http.cookiejar import DefaultCookiePolicy
from urllib.parse import urlsplit, urlunsplit

import dns.exception
import dns.resolver
import requests
from requests.adapters import HTTPAdapter
from requests.cookies import RequestsCookieJar
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError

from limes import scope
from limes.checks import collect

DEFAULT_PORTS = {'http': 80, 'https': 443}
# Total wall clock for one host check (every http hop, the plain probe and the TLS handshakes), whatever the
# host does: a host dripping a byte every few seconds never resets it. Each blocking step gets min(STEP, time left).
HOST_DEADLINE = 30
STEP = collect.TIMEOUT
_monotonic = time.monotonic  # module attribute so tests can inject a clock


class Deadline:
    """One host check's total time budget."""
    def __init__(self, seconds=HOST_DEADLINE, clock=None):
        self.clock = clock or _monotonic
        self.end = self.clock() + seconds

    def expired(self):
        return self.clock() >= self.end

    def timeout(self):
        """The timeout for the next blocking step; TimeoutError once the deadline has passed."""
        left = self.end - self.clock()
        if left <= 0:
            raise TimeoutError('host check deadline reached')
        return min(STEP, left)


class _DeadlineSocket:
    """Wraps the socket of a pinned HTTP connection: every send and recv is armed with the deadline's timeout.
    Keeps socket.socket's file reference counting: the real socket closes only once the wrapper and every file
    made from it are closed (http.client closes the connection before the body of a Connection: close reply)."""
    def __init__(self, sock, deadline):
        self._sock, self._deadline = sock, deadline
        self._io_refs, self._closed = 0, False

    def _arm(self):
        self._sock.settimeout(self._deadline.timeout())

    def recv(self, *a):
        self._arm()
        return self._sock.recv(*a)

    def recv_into(self, *a):
        self._arm()
        return self._sock.recv_into(*a)

    def send(self, *a):
        self._arm()
        return self._sock.send(*a)

    def sendall(self, *a):
        self._arm()
        return self._sock.sendall(*a)

    def settimeout(self, t):
        pass  # the deadline decides; urllib3 resetting a per-read timeout must not extend it

    def makefile(self, mode='r', buffering=None, **kw):
        # socket.socket.makefile builds a SocketIO over self, so the file's reads come back through recv_into
        return socket.socket.makefile(self, mode, buffering, **kw)

    def _decref_socketios(self):
        if self._io_refs > 0:
            self._io_refs -= 1
        if self._closed:
            self.close()

    def close(self):
        self._closed = True
        if self._io_refs <= 0:
            self._sock.close()

    def __getattr__(self, name):
        return getattr(self._sock, name)


def _pools(deadline):
    """urllib3 pool classes whose connections dial with the deadline's timeout and wrap their socket in it.
    CPython bounds the whole TLS handshake by the socket timeout set at connect, so the handshake is covered too."""
    def connect(conn, parent):
        try:
            conn.timeout = deadline.timeout()
        except TimeoutError:  # a timeout, never a refused connection ('nothing listening')
            raise ConnectTimeoutError(conn, 'host check deadline reached')
        parent.connect(conn)
        conn.sock = _DeadlineSocket(conn.sock, deadline)

    class Plain(HTTPConnection):
        def connect(self):
            connect(self, HTTPConnection)

    class Secure(HTTPSConnection):
        def connect(self):
            connect(self, HTTPSConnection)

    class PlainPool(HTTPConnectionPool):
        ConnectionCls = Plain

    class SecurePool(HTTPSConnectionPool):
        ConnectionCls = Secure
    return {'http': PlainPool, 'https': SecurePool}


NOT_RESOLVED = 'does not resolve'


def _address_class(value):
    ip = scope.parse_ip(value)
    if ip is None:
        return 'malformed'
    for attr, word in (('is_loopback', 'loopback'), ('is_link_local', 'link-local'), ('is_multicast', 'multicast'),
                       ('is_unspecified', 'unspecified'), ('is_private', 'private')):
        if getattr(ip, attr):
            return word
    return 'reserved'


def _answers(resolve, name, rdtype):
    """Answers, [] when the name has none, None when the lookup failed (fail closed)."""
    try:
        return list(resolve(name, rdtype))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.DNSException, OSError, ValueError):
        return None


def resolve_vetted(host, resolve=collect._resolve):
    """(ip, None) for a host whose every A and AAAA answer is public, else (None, reason).
    One A and one AAAA query (the resolver follows CNAMEs); an IP literal is vetted without any query."""
    name = (host or '').strip().rstrip('.').lower()
    if not name:
        return None, 'no host'
    ip = scope.parse_ip(name)
    if ip is not None:
        return (None, f'{ip} is a private or reserved address') if scope.is_reserved_ip(ip) else (str(ip), None)
    if scope.is_internal_name(name):
        return None, f'{name} is an internal-only name'
    found = []
    for rdtype in ('A', 'AAAA'):
        got = _answers(resolve, name, rdtype)
        if got is None:
            return None, f'DNS lookup failed for {name} ({rdtype})'
        found += got
    if not found:
        return None, f'{name} {NOT_RESOLVED}'
    bad = sorted({_address_class(a) for a in found if scope.is_reserved_ip(a)})
    if bad:  # the class only: the internal address itself is not repeated into stored reasons
        return None, f'{name} resolves to a {" / ".join(bad)} address'
    # A answers come first: IPv4 is preferred, since containers on default Docker networks often have no IPv6 route
    return str(scope.parse_ip(found[0])), None


class _PinnedAdapter(HTTPAdapter):
    """Pools bound by the host check's deadline; for https (host set) they also send SNI and verify the
    certificate for `host` while connecting to an IP URL."""
    def __init__(self, host, deadline, **kw):
        self._host, self._deadline = host, deadline  # set first: HTTPAdapter.__init__ calls init_poolmanager
        super().__init__(**kw)

    def init_poolmanager(self, *args, **kw):
        if self._host:
            kw['server_hostname'] = kw['assert_hostname'] = self._host
        super().init_poolmanager(*args, **kw)
        self.poolmanager.pool_classes_by_scheme = _pools(self._deadline)


def _netloc(ip, port):
    addr = f'[{ip}]' if ':' in ip else ip
    return f'{addr}:{port}' if port else addr


def pinned_get(host, ip, session_factory=requests.Session, deadline=None, method='get'):
    """A requests.get stand-in (any other requests verb via `method`) that only reaches URLs on `host`, always at `ip`, never following redirects.
    NOTE: one session (and its pool) per call of pinned_get, i.e. per host check; it is left to the garbage
    collector. Upgrade path: close it explicitly if host checks ever run in a long-lived loop."""
    host = host.rstrip('.').lower()
    session = session_factory()
    session.trust_env = False  # no proxies or .netrc credentials from the environment
    # cookie-free, like a fresh requests.get per call: nothing set on one hop (perhaps in answer to the project's
    # secret headers) is replayed on the next, least of all on the cleartext probe
    session.cookies = RequestsCookieJar(policy=DefaultCookiePolicy(allowed_domains=[]))
    deadline = deadline or Deadline()
    session.mount('https://', _PinnedAdapter(host, deadline))
    session.mount('http://', _PinnedAdapter(None, deadline))

    def get(url, **kw):
        bad = requests.exceptions.InvalidURL(f'refusing a URL that is not on {host}')
        if not url or '\\' in url:
            raise bad
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            raise bad
        scheme = parts.scheme.lower()
        if scheme not in DEFAULT_PORTS or '@' in parts.netloc or scope.target_host(url) != host:
            raise bad
        if deadline.expired():  # out of time: unknown ('error'), never a refused connection ('nothing listening')
            raise requests.exceptions.Timeout('host check deadline reached')
        if not kw.get('verify', True):  # False, 0, '' or None would all turn verification off
            raise ValueError('TLS verification cannot be turned off')
        if port == DEFAULT_PORTS[scheme]:
            port = None
        headers = {k: v for k, v in (kw.pop('headers', None) or {}).items() if k.lower() != 'host'}
        name = f'[{host}]' if ':' in host else host  # an IPv6 literal is bracketed in Host
        headers['Host'] = name if port is None else f'{name}:{port}'
        kw['allow_redirects'] = False  # callers follow same-host hops themselves (collect._fetch_https)
        pinned = urlunsplit((scheme, _netloc(ip, port), parts.path or '/', parts.query, ''))
        try:
            resp = getattr(session, method)(pinned, headers=headers, **kw)
        except requests.exceptions.RequestException as e:
            raise _timeout_if_expired(e, deadline)
        if hasattr(resp, 'iter_content'):  # a streamed body read later is held to the same rule
            resp.iter_content = _guarded_iter(resp.iter_content, deadline)
        return resp
    return get


def _timeout_if_expired(exc, deadline):
    """The deadline running out after the dial (on send, or mid-body) surfaces as a ConnectionError, which reads as
    'nothing listening': report it as the Timeout it is. A failure while time is left is passed through."""
    if deadline.expired() and not isinstance(exc, requests.exceptions.Timeout):
        out = requests.exceptions.Timeout('host check deadline reached')
        out.__cause__ = exc
        return out
    return exc


def _guarded_iter(iter_content, deadline):
    def guarded(*a, **kw):
        try:
            yield from iter_content(*a, **kw)
        except requests.exceptions.RequestException as e:
            raise _timeout_if_expired(e, deadline)
    return guarded


def pinned_tls_connect(ip, create_connection=socket.create_connection, context_factory=collect.tls_context, deadline=None):
    """connect(host, legacy=None) for collect.observe_tls: dials (ip, 443) with SNI and verification for host.
    Dial and handshake each get min(STEP, time left): CPython bounds the whole handshake by the socket timeout."""
    deadline = deadline or Deadline()

    def connect(host, legacy=None):
        ctx = context_factory(legacy)
        if ctx.verify_mode != ssl.CERT_REQUIRED or not ctx.check_hostname:
            raise ValueError('refusing a TLS context that does not verify the certificate and hostname')
        with create_connection((ip, 443), timeout=deadline.timeout()) as sock:
            sock.settimeout(deadline.timeout())
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return tls.getpeercert()
    return connect


class NoSuchHost(requests.exceptions.ConnectionError):
    """The name has no DNS answer at all: no such bucket, account or site."""


class Refused(requests.exceptions.RequestException):
    """The host was not contacted (DNS failed, or the answer was not public): unknown, never 'nothing there'."""


LABEL_RE = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?')


def host_allowed(host, exact=(), suffixes=()):
    """True for a host in `exact`, or one label directly under a `suffixes` entry (a.b.s3.amazonaws.com is not
    <label>.s3.amazonaws.com): a candidate name can never smuggle in another host."""
    host = (host or '').rstrip('.').lower()
    if host in exact:
        return True
    return any(host.endswith('.' + s) and LABEL_RE.fullmatch(host[:-len(s) - 1]) for s in suffixes)


def allowlisted_get(exact=(), suffixes=(), resolve=collect._resolve, session_factory=requests.Session, deadline=None):
    """A requests.get stand-in for third-party provider hosts (not scan targets): https on 443 only, and only a host
    that host_allowed() accepts. Each call resolves and vets the host, then pins that one request to the vetted IP
    (pinned_get), so redirects are never followed and a name that resolves to a private address is not contacted.
    A name that definitely does not exist raises NoSuchHost; a lookup failure or a non-public answer raises Refused."""
    def get(url, **kw):
        bad = requests.exceptions.InvalidURL('refusing a URL that is not on an allowed host')
        if not url or '\\' in url:
            raise bad
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            raise bad
        host = scope.target_host(url)
        if (parts.scheme.lower() != 'https' or '@' in parts.netloc or port not in (None, 443) or not host
                or not host_allowed(host, exact, suffixes)):
            raise bad
        ip, reason = resolve_vetted(host, resolve=resolve)
        if reason:
            raise (NoSuchHost if reason.endswith(NOT_RESOLVED) else Refused)('host refused')
        # one deadline per request unless the caller shares one: a long sweep must not run out a single host's budget
        return pinned_get(host, ip, session_factory=session_factory, deadline=deadline or Deadline())(url, **kw)
    return get
