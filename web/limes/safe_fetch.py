"""Safe contact with targets: resolve a host once, vet every answer, then connect only to the vetted IP.

Resolving again at connect time would let a DNS-rebinding name pass the vetting with a public answer and then
point the connection at 10.0.0.1, so every connection here goes to the IP that resolve_vetted returned. The
hostname still travels as the Host header and the TLS SNI, and certificates are verified against the hostname.

NOTE: connection inventory. The risk checks and the light monitor reach targets in three ways only: requests
(pinned_get), a raw ssl socket (pinned_tls_connect) and dns.resolver (DNS queries, never the target's own
address). The scan tools (subfinder, naabu, httpx, nuclei, assay, mantis crawling) resolve on their own and
cannot be pinned from here: they stay covered only by the pre-scan root scope guard (limes.scope.may_contact /
may_attack), which checks the IPs of the latest recorded resolution and so remains open to rebinding. Upgrade
path: pin those tools to the vetted IPs (naabu -host <ip>, httpx host-to-IP pinning) or send them through an
egress proxy that vets every connection.
"""
import socket
import ssl
from http.cookiejar import DefaultCookiePolicy
from urllib.parse import urlsplit, urlunsplit

import dns.exception
import dns.resolver
import requests
from requests.adapters import HTTPAdapter
from requests.cookies import RequestsCookieJar

from limes import scope
from limes.checks import collect

MAX_REASON_ADDRESSES = 5
DEFAULT_PORTS = {'http': 80, 'https': 443}


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
        return None, f'{name} does not resolve'
    bad = sorted({str(a) for a in found if scope.is_reserved_ip(a)})
    if bad:
        return None, f'{name} resolves to private/reserved ' + ', '.join(bad[:MAX_REASON_ADDRESSES])
    return str(scope.parse_ip(found[0])), None


class _PinnedAdapter(HTTPAdapter):
    """HTTPS pools that send SNI and verify the certificate for `host` while connecting to an IP URL."""
    def __init__(self, host, **kw):
        self._host = host  # set first: HTTPAdapter.__init__ calls init_poolmanager
        super().__init__(**kw)

    def init_poolmanager(self, *args, **kw):
        kw['server_hostname'] = kw['assert_hostname'] = self._host
        super().init_poolmanager(*args, **kw)


def _netloc(ip, port):
    addr = f'[{ip}]' if ':' in ip else ip
    return f'{addr}:{port}' if port else addr


def pinned_get(host, ip, session_factory=requests.Session):
    """A requests.get stand-in that only fetches URLs on `host`, always from `ip`, never following redirects.
    NOTE: one session (and its pool) per call of pinned_get, i.e. per host check; it is left to the garbage
    collector. Upgrade path: close it explicitly if host checks ever run in a long-lived loop."""
    host = host.rstrip('.').lower()
    session = session_factory()
    session.trust_env = False  # no proxies or .netrc credentials from the environment
    # cookie-free, like a fresh requests.get per call: nothing set on one hop (perhaps in answer to the project's
    # secret headers) is replayed on the next, least of all on the cleartext probe
    session.cookies = RequestsCookieJar(policy=DefaultCookiePolicy(allowed_domains=[]))
    session.mount('https://', _PinnedAdapter(host))

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
        if kw.get('verify') is False:
            raise ValueError('TLS verification cannot be turned off')
        if port == DEFAULT_PORTS[scheme]:
            port = None
        headers = {k: v for k, v in (kw.pop('headers', None) or {}).items() if k.lower() != 'host'}
        headers['Host'] = host if port is None else f'{host}:{port}'
        kw['allow_redirects'] = False  # callers follow same-host hops themselves (collect._fetch_https)
        pinned = urlunsplit((scheme, _netloc(ip, port), parts.path or '/', parts.query, ''))
        return session.get(pinned, headers=headers, **kw)
    return get


def pinned_tls_connect(ip, create_connection=socket.create_connection, context_factory=collect.tls_context):
    """connect(host, legacy=None) for collect.observe_tls: dials (ip, 443) with SNI and verification for host."""
    def connect(host, legacy=None):
        ctx = context_factory(legacy)
        if ctx.verify_mode != ssl.CERT_REQUIRED or not ctx.check_hostname:
            raise ValueError('refusing a TLS context that does not verify the certificate and hostname')
        with create_connection((ip, 443), timeout=collect.TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return tls.getpeercert()
    return connect
