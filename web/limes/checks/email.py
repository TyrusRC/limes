"""SPF, DMARC and MX checks from one observation. Pure: no I/O."""
import re

from limes.checks.catalogue import CHECKS, PROVISIONAL, Result

IDS = [i for i in CHECKS if i.startswith('email.') and i not in PROVISIONAL]  # provisional ones: limes.checks.mailpolicy


def _first(records, prefix):
    for r in records:
        if r.strip().lower().startswith(prefix):
            return r.strip()
    return None


def _spf_all(spf):
    """Qualifier of the last `all` mechanism ('' means +), or None if there is none."""
    found = re.findall(r'(?:^|\s)([+\-~?]?)all(?=\s|$)', spf.lower())
    return found[-1] if found else None


def evaluate(obs):
    txt, dmarc_txt, mx = obs['txt'], obs['dmarc'], obs['mx']
    spf = None if txt == 'error' else _first(txt, 'v=spf1')
    dmarc = None if dmarc_txt == 'error' else _first(dmarc_txt, 'v=dmarc1')
    out = {}

    if txt == 'error':
        out['email.spf_missing'] = Result('email.spf_missing', 'error', {})
        out['email.spf_permissive'] = Result('email.spf_permissive', 'error', {})
    elif spf is None:
        out['email.spf_missing'] = Result('email.spf_missing', 'fail', {})
        out['email.spf_permissive'] = Result('email.spf_permissive', 'not_applicable', {})
    else:
        out['email.spf_missing'] = Result('email.spf_missing', 'pass', {})
        bad = _spf_all(spf) in ('', '+', '?')
        out['email.spf_permissive'] = Result('email.spf_permissive', 'fail' if bad else 'pass',
                                             {'spf': spf} if bad else {})

    if dmarc_txt == 'error':
        out['email.dmarc_missing'] = Result('email.dmarc_missing', 'error', {})
        out['email.dmarc_none'] = Result('email.dmarc_none', 'error', {})
    elif dmarc is None:
        out['email.dmarc_missing'] = Result('email.dmarc_missing', 'fail', {})
        out['email.dmarc_none'] = Result('email.dmarc_none', 'not_applicable', {})
    else:
        out['email.dmarc_missing'] = Result('email.dmarc_missing', 'pass', {})
        m = re.search(r'(?:^|;)\s*p\s*=\s*([a-z]+)', dmarc.lower())
        none = bool(m) and m.group(1) == 'none'
        out['email.dmarc_none'] = Result('email.dmarc_none', 'fail' if none else 'pass',
                                         {'dmarc': dmarc} if none else {})

    if mx == 'error' or txt == 'error' or dmarc_txt == 'error':
        # an unknown SPF/DMARC state can't be called a pass; a known gap still fails below
        gap = mx != 'error' and mx and (spf is None and txt != 'error' or dmarc is None and dmarc_txt != 'error')
        st = 'fail' if gap else ('pass' if mx == [] else 'error')
    elif not mx:
        st = 'pass'  # no mail is received, so nothing to protect
    else:
        st = 'fail' if spf is None or dmarc is None else 'pass'
    out['email.mx_unprotected'] = Result('email.mx_unprotected', st, {})
    return [out[i] for i in IDS]
