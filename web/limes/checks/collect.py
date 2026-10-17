"""Observation collectors for the risk checks. All network I/O lives here, behind
injectable callables, so the evaluators stay pure. TLS verification is never disabled."""
import socket
import ssl
from datetime import datetime, timedelta, timezone as dt_timezone
from urllib.parse import urljoin, urlparse

import dns.exception
import dns.resolver
import requests
from django.utils import timezone


TIMEOUT = 5
MAX_REDIRECTS = 3
FRESH = timedelta(days=30)
LOCAL_REFUSALS = {'NO_PROTOCOLS_AVAILABLE', 'NO_CIPHERS_AVAILABLE'}
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
        nxt = urljoin(url, loc) if loc and 300 <= obs['status'] < 400 else None
        if not nxt or (urlparse(nxt).hostname or '').lower() != host.lower() or not nxt.lower().startswith('https://'):
            return obs
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
        resp = get(f'http://{host}/', headers=headers, timeout=TIMEOUT, allow_redirects=False, stream=True)
        try:
            return {'status': resp.status_code, 'location': resp.headers.get('Location', '')}
        finally:
            resp.close()
    return {'https': _guard(lambda: _fetch_https(host, headers, get)), 'http': _guard(plain)}


# ---- TLS ----

def _tls_connect(host, legacy=None):
    """Verified handshake on 443; returns the peer cert. legacy pins TLS 1.0/1.1."""
    ctx = ssl.create_default_context()
    if legacy:
        if not getattr(ssl, f'HAS_{legacy}', False):
            raise ContextRefused(f'{legacy} not supported by this OpenSSL')
        try:
            ctx.set_ciphers('ALL:@SECLEVEL=0')
            ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion[legacy]
        except (ssl.SSLError, ValueError) as e:
            raise ContextRefused(str(e))
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
            return {**base, 'expired': True}  # trust is unknown, not "untrusted"
        if code == 62:
            return {**base, 'hostname_ok': False}
        return {**base, 'trusted': False}  # 18/19/20/21 and anything else
    except ConnectionRefusedError:
        return None
    except (OSError, ssl.SSLError):  # includes timeouts
        return 'error'


def _legacy(host, version, connect):
    """True: protocol negotiated. False: refused. None: unknown."""
    try:
        connect(host, version)
        return True
    except ContextRefused:
        return None
    except ssl.SSLCertVerificationError:
        return True  # got as far as certificate verification
    except ssl.SSLError as e:
        # the local library cannot speak this protocol: unknown, not a refusal by the server
        return None if getattr(e, 'reason', None) in LOCAL_REFUSALS else False
    except ConnectionResetError:
        return False
    except OSError:  # timeouts, unreachable
        return None
    except ValueError:
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
    """{port: [source, ...]} from fresh InternetDB data and naabu, or None when there is none."""
    from startScan.models import Port
    ports, seen = {}, False
    fresh = _fresh_internetdb(asset, now)
    if fresh:
        seen = True
        idb, ts = fresh
        for p in idb.get('ports') or []:
            ports.setdefault(int(p), []).append(f'internetdb {ts.date().isoformat()}')
    # several IpAddress rows can share an address (one per scan): union them all
    naabu = Port.objects.filter(ports__address=asset.value).values_list('number', flat=True).distinct()
    for p in naabu:
        seen = True
        ports.setdefault(p, []).append('naabu')
    return dict(sorted(ports.items())) if seen else None
