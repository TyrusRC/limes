"""TLS certificate and legacy-protocol checks from one observation. Pure: no I/O."""
from datetime import timedelta

from limes.checks.catalogue import CHECKS, Result

IDS = [i for i in CHECKS if i.startswith('tls.')]
EXPIRING_WINDOW = timedelta(days=14)


def _legacy(legacy):
    accepted = [p for p in ('TLSv1', 'TLSv1_1') if legacy.get(p) is True]
    if accepted:
        return Result('tls.legacy_protocol', 'fail', {'accepted': accepted})
    # None = the context or handshake was refused: unknown, never a pass
    if any(legacy.get(p) is None for p in ('TLSv1', 'TLSv1_1')):
        return Result('tls.legacy_protocol', 'error', {})
    return Result('tls.legacy_protocol', 'pass', {})


def evaluate(obs, now):
    cert = obs.get('cert')
    if cert is None or cert == 'error':
        st = 'error' if cert == 'error' else 'not_applicable'
        return [Result(i, st, {}) for i in IDS]
    na = cert.get('not_after')
    expired = bool(cert.get('expired')) or (na is not None and na < now)
    if na is None:
        expiring = 'not_applicable'
    else:
        expiring = 'fail' if not expired and na - now <= EXPIRING_WINDOW else 'pass'
    ev = {'not_after': na.isoformat()} if na else {}
    out = {
        'tls.cert_expired': Result('tls.cert_expired', 'fail' if expired else 'pass', ev if expired else {}),
        'tls.cert_expiring': Result('tls.cert_expiring', expiring, ev if expiring == 'fail' else {}),
        'tls.cert_hostname_mismatch': Result('tls.cert_hostname_mismatch', 'pass' if cert.get('hostname_ok') else 'fail', {}),
        'tls.cert_untrusted': Result('tls.cert_untrusted', 'pass' if cert.get('trusted') else 'fail', {}),
        'tls.legacy_protocol': _legacy(obs.get('legacy') or {}),
    }
    return [out[i] for i in IDS]
