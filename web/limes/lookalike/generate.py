"""Candidate lookalike names for an owned root. dnstwist is a GENERATOR only: nothing here (or in dnstwist's
Fuzzer, which does no I/O) touches the network. Hostile or oversized names are dropped, never raised.

NOTE: MAX_CANDIDATES_PER_ROOT is a ceiling. Upgrade path: a per-root setting.
NOTE: dnstwist's homoglyph generator is exponential in label length (a 63-character label took minutes), so labels
over HOMOGLYPH_MAX_LABEL get no homoglyph candidates. Upgrade path: a bounded single-substitution generator of our own.
"""
import re
import socket
import threading

import idna

from limes.intel.domains import _EXTRACT, registrable

MAX_CANDIDATES_PER_ROOT = 1000
TLDS = ('com', 'net', 'org', 'co', 'io', 'info', 'xyz', 'app')
WORDS = ('login', 'secure', 'account', 'support', 'mail', 'portal', 'online', 'app')
MAX_KEYWORDS = 20
HOMOGLYPH_MAX_LABEL = 24
MAX_CT_MATCHES = 100
RANKS = ('omission', 'transposition', 'replacement', 'insertion', 'repetition', 'addition', 'vowel-swap', 'hyphenation',
         'plural', 'bitsquatting', 'homoglyph', 'cyrillic', 'tld-swap', 'dictionary', 'various', 'subdomain')
KEYWORD_RE = re.compile(r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?')
FQDN_RE = re.compile(r'(?=^.{4,253}$)(^((?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z0-9-]{2,63}$)')

_FUZZER = None
_lock = threading.Lock()


def _fuzzer_class():
    """dnstwist.Fuzzer. Importing dnstwist sets a process-wide socket default timeout (12 s), which would reach
    every later socket in the worker, so the caller's value is put back."""
    global _FUZZER
    with _lock:
        if _FUZZER is None:
            saved = socket.getdefaulttimeout()
            try:
                import dnstwist
                _FUZZER = dnstwist.Fuzzer
            finally:
                socket.setdefaulttimeout(saved)
    return _FUZZER


def valid_fqdn(name):
    return isinstance(name, str) and FQDN_RE.fullmatch(name) is not None


def distance(a, b, limit=2):
    """Levenshtein distance, or limit + 1 as soon as it is known to exceed `limit`."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > limit:
            return limit + 1
        prev = cur
    return min(prev[-1], limit + 1)


def _keywords(keywords):
    out = []
    for k in keywords or ():
        k = k.strip().lower() if isinstance(k, str) else ''
        if KEYWORD_RE.fullmatch(k) and k not in out:
            out.append(k)
        if len(out) == MAX_KEYWORDS:
            break
    return out


def _unicode(domain):
    try:
        return idna.decode(domain)[:253]
    except (UnicodeError, idna.IDNAError):
        return domain


def candidates(root, keywords=(), exclude=frozenset()):
    root = (root or '').strip().lower().rstrip('.')
    ext = _EXTRACT(root) if root else None
    if not ext or not ext.domain or not ext.suffix or ext.registered_domain != root:
        return []
    try:
        label = idna.decode(ext.domain)
    except (UnicodeError, idna.IDNAError):
        return []
    # the constructor only splits its argument; the split below is the public-suffix-aware one
    fuzzer = _fuzzer_class()('example.com', _keywords(keywords) + list(WORDS), list(TLDS))
    fuzzer.subdomain, fuzzer.domain, fuzzer.tld = '', label, ext.suffix
    names = [n for n in RANKS if n != 'homoglyph' or len(label) <= HOMOGLYPH_MAX_LABEL]
    skip = {root, *(str(e).lower() for e in exclude)}
    found = {}  # domain -> fuzzer names
    for name in names:
        fuzzer.generate([name])  # one at a time: the Fuzzer keeps a single fuzzer name per domain
        for p in fuzzer.domains:
            domain = p['domain']
            if domain in skip or not valid_fqdn(domain):
                continue
            if name != 'tld-swap' and not domain.endswith('.' + ext.suffix):
                continue  # dnstwist's 'various' also drops or moves the suffix; only tld-swap may change it
            if name == 'homoglyph':
                text = _unicode(domain)
                if distance(text[:-len(ext.suffix) - 1], label, 1) != 1:
                    continue
            found.setdefault(domain, []).append(name)
    out = [{'domain': d, 'unicode': _unicode(d), 'fuzzers': f} for d, f in found.items()]
    out.sort(key=lambda c: (RANKS.index(c['fuzzers'][0]), c['domain']))
    return out[:MAX_CANDIDATES_PER_ROOT]


def ct_matches(names, label, exclude):
    """Registrable domains of CT names that carry the brand as a whole token (split on '.' and '-') or within
    edit distance 2 of it; never a substring match. The allowed distance shrinks for very short labels."""
    label = (label or '').lower()
    limit = min(2, len(label) // 3)
    out = set()
    for name in names:
        if not isinstance(name, str) or len(name) > 253:
            continue
        name = name.lower()
        tokens = re.split(r'[.-]', name)
        if not any(distance(t, label, limit) <= limit for t in tokens if t):
            continue
        reg = registrable(name)
        if reg and reg not in exclude and valid_fqdn(reg):
            out.add(reg)
    return sorted(out)[:MAX_CT_MATCHES]
