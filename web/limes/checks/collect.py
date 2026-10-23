"""Observation collectors for the risk checks. All network I/O lives here, behind
injectable callables, so the evaluators stay pure. TLS verification is never disabled."""
import socket
import ssl
from datetime import datetime, timedelta, timezone as dt_timezone
from urllib.parse import urljoin, urlsplit

import dns.exception
import dns.resolver
import requests
from django.utils import timezone

from limes import scope


TIMEOUT = 5
MAX_REDIRECTS = 3
FRESH = timedelta(days=30)
# SSLError reasons that mean the server refused the legacy protocol. Anything else is unknown.
SERVER_REFUSALS = {'UNSUPPORTED_PROTOCOL', 'TLSV1_ALERT_PROTOCOL_VERSION', 'WRONG_VERSION_NUMBER',
                   'SSLV3_ALERT_HANDSHAKE_FAILURE', 'TLSV1_ALERT_INSUFFICIENT_SECURITY', 'NO_SHARED_CIPHER',
                   'TLSV1_ALERT_HANDSHAKE_FAILURE'}
LEGACY = ('TLSv1', 'TLSv1_1')


class ContextRefused(Exception):
    """The local TLS library refused to build a legacy-protocol context."""


# ---- HTTP ----

def _cookies(resp):
    try:
        return list(resp.raw.headers.getlist('Set-Cookie'))
    except AttributeError:
        c = resp.headers.get('set-cookie') or resp.headers.get('Set-Cookie')
        return [c] if c else []


def _https_obs(resp, url):
    return {'status': resp.status_code, 'url': url,
            'headers': {k.lower(): v for k, v in resp.headers.items()}, 'cookies': _cookies(resp)}


def same_host_https(url, host):
    """True only for https://<host>[:443]/... with no userinfo and no backslash. Parsers
    disagree on such authorities (urlsplit vs urllib3/WHATWG), so anything odd is refused."""
    if not url or '\\' in url:
        return False
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    return (parts.scheme.lower() == 'https' and '@' not in parts.netloc and port in (None, 443)
            and scope.target_host(url) == (host or '').rstrip('.').lower())


def _fetch_https(host, headers, get):
    """GET https://host/ following at most MAX_REDIRECTS same-host redirects."""
    url = f'https://{host}/'
    for _ in range(MAX_REDIRECTS + 1):
        resp = get(url, headers=headers, timeout=TIMEOUT, allow_redirects=False, stream=True)
        try:
            obs = _https_obs(resp, url)
        finally:
            resp.close()
        loc = obs['headers'].get('location')
        if not loc or not 300 <= obs['status'] < 400 or '\\' in loc:
            return obs
        nxt = urljoin(url, loc)
        if not same_host_https(nxt, host):
            return obs  # evaluate the 3xx we have
        url = nxt
    return obs


def _guard(fn):
    """requests outcome: dict, None (nothing listening) or 'error' (unknown, never a pass)."""
    try:
        return fn()
    except requests.exceptions.SSLError:
        return 'error'
    except requests.exceptions.Timeout:
        return 'error'
    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.RequestException:
        return 'error'


def observe_http(host, ident, get=requests.get):
    headers = {'User-Agent': ident.ua, **{h.name: h.value for h in ident.headers}}

    def plain():
        # cleartext: never send the project's custom or secret headers
        resp = get(f'http://{host}/', headers={'User-Agent': ident.ua}, timeout=TIMEOUT, allow_redirects=False, stream=True)
        try:
            return {'status': resp.status_code, 'location': resp.headers.get('Location', '')}
        finally:
            resp.close()
    return {'host': host, 'https': _guard(lambda: _fetch_https(host, headers, get)), 'http': _guard(plain)}


# ---- TLS ----

def tls_context(legacy=None, make=ssl.create_default_context):
    """A verifying client context (CERT_REQUIRED, hostname checked); legacy pins TLS 1.0/1.1."""
    ctx = make()
    if legacy:
        if not getattr(ssl, f'HAS_{legacy}', False):
            raise ContextRefused(f'{legacy} not supported by this OpenSSL')
        try:
            ctx.set_ciphers('ALL:@SECLEVEL=0')
            ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion[legacy]
        except (ssl.SSLError, ValueError) as e:
            raise ContextRefused(str(e))
    return ctx


def _tls_connect(host, legacy=None):
    """Verified handshake on 443; returns the peer cert. Resolves on its own: scan paths use safe_fetch's pinned one."""
    ctx = tls_context(legacy)
    with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert()


def _not_after(peer):
    ts = ssl.cert_time_to_seconds(peer['notAfter'])
    return datetime.fromtimestamp(ts, dt_timezone.utc)


def _cert(host, connect):
    base = {'not_after': None, 'expired': False, 'hostname_ok': True, 'trusted': True}
    try:
        return {**base, 'not_after': _not_after(connect(host))}
    except ssl.SSLCertVerificationError as e:
        code = e.verify_code
        if code == 10:
            # validity time is checked last: chain and hostname already verified
            return {**base, 'expired': True}
        # OpenSSL stops at the first error. None = never checked (the evaluator reports error):
        # expiry is checked after both of these, the hostname after chain building.
        unknown = {**base, 'verify_code': code, 'expired': None}
        if code == 62:
            return {**unknown, 'hostname_ok': False, 'trusted': None}  # signatures not yet verified
        return {**unknown, 'trusted': False, 'hostname_ok': None}  # 18/19/20/21 and anything else
    except ConnectionRefusedError:
        return None
    except (OSError, ssl.SSLError):  # includes timeouts
        return 'error'


def _legacy(host, version, connect):
    """True: protocol negotiated. False: refused by the server. None: unknown.
    Allowlist: only explicit server refusals are False, so a local-side failure is never a pass."""
    try:
        connect(host, version)
        return True
    except ssl.SSLCertVerificationError:
        return True  # got as far as certificate verification
    except ssl.SSLError as e:
        return False if getattr(e, 'reason', None) in SERVER_REFUSALS else None
    except ConnectionResetError:
        return False
    except (ContextRefused, OSError, ValueError):  # local refusal, timeouts, unreachable
        return None


def observe_tls(host, connect=_tls_connect):
    cert = _cert(host, connect)
    legacy = {v: _legacy(host, v, connect) for v in LEGACY} if isinstance(cert, dict) else {}
    return {'cert': cert, 'legacy': legacy}


# ---- DNS ----

def _resolve(name, rdtype):
    ans = dns.resolver.Resolver()
    ans.lifetime = TIMEOUT
    out = []
    for r in ans.resolve(name, rdtype):
        if rdtype == 'TXT':
            out.append(b''.join(r.strings).decode('utf-8', 'replace'))
        elif rdtype == 'MX':
            out.append(f'{r.preference} {r.exchange.to_text()}')
        else:
            out.append(r.to_text())
    return out


def _lookup(resolve, name, rdtype):
    try:
        return resolve(name, rdtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException:
        return 'error'


def _mx_hosts(records):
    if records == 'error':
        return records
    hosts = [r.split(None, 1)[-1].strip().rstrip('.') for r in records]
    return [h for h in hosts if h]  # RFC 7505 null MX ('.') means no mail


def observe_mail_dns(root, resolve=_resolve):
    mail = {'txt': _lookup(resolve, root, 'TXT'), 'dmarc': _lookup(resolve, f'_dmarc.{root}', 'TXT'),
            'mx': _mx_hosts(_lookup(resolve, root, 'MX'))}
    dns_obs = {}
    for key, rdtype in (('ds', 'DS'), ('caa', 'CAA')):
        found = _lookup(resolve, root, rdtype)
        dns_obs[key] = found if found == 'error' else bool(found)
    return mail, dns_obs


# ---- ports (database only, never probed) ----

def _fresh_internetdb(asset, now):
    idb = (asset.enrichment or {}).get('internetdb') or {}
    try:
        ts = datetime.fromisoformat(idb['fetched_at'])
    except (KeyError, TypeError, ValueError):
        return None
    if ts.tzinfo is None:
        ts = timezone.make_aware(ts, dt_timezone.utc)
    return (idb, ts) if now - ts < FRESH else None


def ports_for_ip(asset, now):
    """({port: [source, ...]}, complete). Only fresh InternetDB data is complete: naabu rows
    carry no date and default scans probe top-100, which omits most risky ports, so naabu can
    only add ports, never vouch for an absent one."""
    from startScan.models import Port
    ports = {}
    fresh = _fresh_internetdb(asset, now)
    if fresh:
        idb, ts = fresh
        for p in idb.get('ports') or []:
            ports.setdefault(int(p), []).append(f'internetdb {ts.date().isoformat()}')
    # several IpAddress rows can share an address (one per scan): union them all
    naabu = Port.objects.filter(ports__address=asset.value).values_list('number', flat=True).distinct()
    for p in naabu:
        ports.setdefault(p, []).append('naabu')
    return dict(sorted(ports.items())), bool(fresh)
