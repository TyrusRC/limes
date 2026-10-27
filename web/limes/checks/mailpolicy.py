"""MTA-STS, TLS-RPT and BIMI checks for an owned mail domain. Pure: no I/O. All four are provisional (0 points).

obs = {'mx': [host, ...], 'sts': [txt] | 'error', 'policy': None | {'status': int | 'error', 'body': bytes | None,
'reason': str | None}, 'tlsrpt': [txt] | 'error', 'bimi': [txt] | 'error', 'dmarc': [txt] | 'error'}.
Evidence is shapes only: a mode word from a fixed set, a number, problem codes. Policy text, MX names and the logo URL
are never stored."""
import re

from limes.checks.catalogue import Result

MODES = ('none', 'testing', 'enforce')
MAX_AGE_CEILING = 31557600  # RFC 8461: one year
MIN_MAX_AGE = 86400
MAX_LINES = 100
PATTERN_RE = re.compile(r'(?:\*\.)?[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)+')
EXPECT_POLICY = 'mode enforce, max_age >= 86400, an mx line covering every mail server'


def first(records, prefix):
    for r in records:
        if r.strip().lower().replace(' ', '').startswith(prefix):
            return r.strip()
    return None


def tags(record):
    """tag -> value of a 'k=v; k=v' record (first occurrence wins, keys lower-cased)."""
    out = {}
    for part in record.split(';'):
        k, sep, v = part.partition('=')
        if sep:
            out.setdefault(k.strip().lower(), v.strip())
    return out


def parse_policy(body):
    """{'version', 'mode', 'max_age', 'mx': [...]} from the policy file; unknown keys are ignored."""
    out = {'mx': []}
    for line in body.decode('utf-8', 'replace').splitlines()[:MAX_LINES]:
        k, sep, v = line.partition(':')
        if not sep:
            continue
        k, v = k.strip().lower(), v.strip()
        if k == 'mx':
            out['mx'].append(v.rstrip('.').lower())
        elif k in ('version', 'mode', 'max_age'):
            out.setdefault(k, v)
    return out


def mx_covered(host, pattern):
    """RFC 8461 matching: an exact name, or '*.suffix' standing for exactly one leftmost label."""
    host = host.rstrip('.').lower()
    if pattern.startswith('*.'):
        label, _dot, rest = host.partition('.')
        return bool(label) and rest == pattern[2:]
    return host == pattern


def policy_problems(pol, mx_hosts):
    """(mode or None, max_age or None, [problem codes]) for a parsed policy."""
    problems = []
    if pol.get('version') != 'STSv1':
        problems.append('version')
    mode = pol.get('mode', '').lower()
    if mode not in MODES:
        problems.append('mode')
        mode = None
    try:
        max_age = int(pol.get('max_age', ''))
        if not 0 <= max_age <= MAX_AGE_CEILING:
            problems.append('max_age_range')
    except ValueError:
        max_age = None
        problems.append('max_age_invalid')
    if max_age is not None and mode != 'none' and max_age < MIN_MAX_AGE:
        problems.append('max_age_short')
    patterns = pol['mx']
    if mode != 'none':
        if not patterns:
            problems.append('mx_missing')
        elif not all(PATTERN_RE.fullmatch(p) for p in patterns):
            problems.append('mx_pattern_invalid')
        elif any(not any(mx_covered(h, p) for p in patterns) for h in mx_hosts):
            problems.append('mx_not_covered')
    return mode, max_age, problems


def _sts(obs):
    sts, policy = obs['sts'], obs['policy']
    if sts == 'error':
        return Result('email.mta_sts_missing', 'error', {}), Result('email.mta_sts_testing', 'error', {})
    rec = first(sts, 'v=stsv1')
    if rec is None or not tags(rec).get('id'):
        ev = {'expected': 'TXT record at _mta-sts.<domain>: v=STSv1; id=<id>',
              'actual': 'no record' if rec is None else 'record without an id'}
        return Result('email.mta_sts_missing', 'fail', ev), Result('email.mta_sts_testing', 'not_applicable', {})
    missing = Result('email.mta_sts_missing', 'pass', {})
    if not policy or policy.get('status') == 'error':
        return missing, Result('email.mta_sts_testing', 'error', {'reason': (policy or {}).get('reason') or 'policy not fetched'})
    if policy['status'] != 200 or policy.get('body') is None:
        why = policy.get('reason') or f"http_{policy['status']}"
        return missing, Result('email.mta_sts_testing', 'fail', {
            'problems': [why], 'expected': EXPECT_POLICY, 'actual': 'policy file not served'})
    mode, max_age, problems = policy_problems(parse_policy(policy['body']), obs['mx'])
    bad = mode != 'enforce' or bool(problems)
    ev = {'mode': mode or 'invalid', 'max_age': max_age, 'problems': problems, 'expected': EXPECT_POLICY,
          'actual': f"mode {mode or 'invalid'}" + (f', {len(problems)} problem(s)' if problems else '')}
    return missing, Result('email.mta_sts_testing', 'fail' if bad else 'pass', ev if bad else {})


def _tlsrpt(txt):
    if txt == 'error':
        return Result('email.tls_rpt_missing', 'error', {})
    rec = first(txt, 'v=tlsrptv1')
    if rec is not None and tags(rec).get('rua'):
        return Result('email.tls_rpt_missing', 'pass', {})
    return Result('email.tls_rpt_missing', 'fail', {
        'expected': 'TXT record at _smtp._tls.<domain>: v=TLSRPTv1; rua=<mailto: or https: address>',
        'actual': 'no record' if rec is None else 'record without rua'})


def _bimi(bimi, dmarc):
    if bimi == 'error':
        return Result('email.bimi_invalid', 'error', {})
    rec = first(bimi, 'v=bimi1')
    if rec is None:
        return Result('email.bimi_invalid', 'not_applicable', {})
    if dmarc == 'error':
        return Result('email.bimi_invalid', 'error', {})
    problems = []
    d = first(dmarc, 'v=dmarc1')
    policy = tags(d).get('p', '').lower() if d else ''
    if policy not in ('quarantine', 'reject'):
        problems.append('dmarc_not_enforced')
    logo = tags(rec).get('l', '')
    if logo and not logo.lower().startswith('https://'):
        problems.append('logo_not_https')
    if not problems:
        return Result('email.bimi_invalid', 'pass', {})
    return Result('email.bimi_invalid', 'fail', {
        'problems': problems, 'dmarc_policy': policy if policy in ('none', 'quarantine', 'reject') else 'absent',
        'expected': 'DMARC p=quarantine or p=reject, and an https logo URL', 'actual': ', '.join(problems)})


def not_applicable():
    return [Result(i, 'not_applicable', {}) for i in ('email.mta_sts_missing', 'email.mta_sts_testing',
                                                      'email.tls_rpt_missing', 'email.bimi_invalid')]


def evaluate(obs):
    """The four provisional mail results, in catalogue order, for a domain that has MX hosts."""
    missing, testing = _sts(obs)
    return [missing, testing, _tlsrpt(obs['tlsrpt']), _bimi(obs['bimi'], obs['dmarc'])]
