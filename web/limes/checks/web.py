"""Website header checks from one HTTPS and one HTTP observation. Pure: no I/O."""
from limes.checks.catalogue import CHECKS, Result
from limes.checks.collect import same_host_https
from limes.scope import target_host

IDS = [i for i in CHECKS if i.startswith('web.')]
HTTPS_DEPENDENT = [i for i in IDS if i not in ('web.https_missing', 'web.http_no_redirect')]


def _cookie_name(raw):
    return raw.split(';', 1)[0].split('=', 1)[0].strip()


def _cookie_bad(raw):
    attrs = [a.strip().lower() for a in raw.split(';')[1:]]
    return not ('secure' in attrs and 'httponly' in attrs and any(a.startswith('samesite') for a in attrs))


def _no_redirect_status(http, https, host):
    """pass only for a redirect to https:// on the probed host itself (same rule as the collector)."""
    loc = (http.get('location') or '').strip()
    if not loc.lower().startswith('https://'):
        return 'fail'
    host = host or (target_host(https['url']) if isinstance(https, dict) and https.get('url') else None)
    if not host:
        return 'error'  # cannot tell whether it stays on this host
    return 'pass' if same_host_https(loc, host) else 'fail'


def _https_checks(https):
    h = https.get('headers') or {}
    csp = h.get('content-security-policy', '')
    bad_cookies = [_cookie_name(c) for c in https.get('cookies') or [] if _cookie_bad(c)]
    leaks = {k: h[k] for k in ('server', 'x-powered-by') if any(ch.isdigit() for ch in h.get(k, ''))}
    framed = 'x-frame-options' not in h and 'frame-ancestors' not in csp.lower()
    return {
        'web.hsts_missing': ('strict-transport-security' not in h, {}),
        'web.csp_missing': ('content-security-policy' not in h, {}),
        'web.frame_options_missing': (framed, {}),
        'web.content_type_options_missing': (h.get('x-content-type-options', '').strip().lower() != 'nosniff', {}),
        'web.cookie_flags_missing': (bool(bad_cookies), {'cookies': bad_cookies}),
        'web.version_disclosure': (bool(leaks), leaks),
    }


def evaluate(obs):
    https, http = obs.get('https'), obs.get('http')
    out = {}
    if isinstance(https, dict):
        out['web.https_missing'] = Result('web.https_missing', 'pass', {})
        for cid, (bad, ev) in _https_checks(https).items():
            out[cid] = Result(cid, 'fail' if bad else 'pass', ev if bad else {})
    else:
        # https is None (no answer) or 'error'
        if https == 'error':
            st = 'error'
        elif isinstance(http, dict):
            st = 'fail'
        else:
            st = 'error' if http == 'error' else 'not_applicable'
        out['web.https_missing'] = Result('web.https_missing', st, {})
        dep = 'error' if https == 'error' else 'not_applicable'
        for cid in HTTPS_DEPENDENT:
            out[cid] = Result(cid, dep, {})
    if isinstance(http, dict):
        out['web.http_no_redirect'] = Result('web.http_no_redirect', _no_redirect_status(http, https, obs.get('host')), {})
    else:
        out['web.http_no_redirect'] = Result('web.http_no_redirect', 'error' if http == 'error' else 'not_applicable', {})
    return [out[i] for i in IDS]
