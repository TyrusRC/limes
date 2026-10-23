"""Match certificate names to owned inventory. Pure: no ORM, no I/O. Names come from the public CT log, so every one is
hostile: they are normalised first, then matched only by exact lookup on dot-separated suffixes (never a string
`endswith`, so `evilx.com` and `x.com.evil.net` can never match `x.com`)."""
import re
from typing import NamedTuple

import validators

MAX_NAMES = 1000
STORED_NAMES = 100
SAMPLE_NAMES = 20
ISSUER_MAX_CHARS = 200

_NAME = re.compile(r'[a-z0-9.-]+')
_CONTROL = re.compile(r'[\x00-\x1f\x7f-\x9f  ]')
_DOTS = ('。', '．', '｡')  # the idna codec reads these as '.'; a CA never signs them as one


class Index(NamedTuple):
    roots: dict       # root value -> [(project_id, root_asset_id)]
    hosts: dict       # exact owned name -> [(project_id, asset_id)]
    lookalikes: dict  # lookalike domain -> [project_id]


class ProjectMatch(NamedTuple):
    owned: list       # [(name, wildcard, root_asset_id)]
    hosts: list       # [(name, asset_id)]
    lookalikes: list  # [lookalike domain]
    others: list      # [name]


def normalise(raw):
    """(name, wildcard) or None. Extends crtsh._clean: IDNA, charset, length and a single leading `*.` only."""
    if not isinstance(raw, str) or any(d in raw for d in _DOTS):
        return None
    n = raw.strip().lower()
    if n.endswith('.'):
        n = n[:-1]
    wildcard = n.startswith('*.')
    if wildcard:
        n = n[2:]
    try:
        n = n.encode('idna').decode('ascii')
    except UnicodeError:
        return None
    if len(n) > 253 or not _NAME.fullmatch(n) or validators.domain(n) is not True:
        return None
    return n, wildcard


def _suffixes(name):
    """The name, then each parent, longest first."""
    labels = name.split('.')
    for i in range(len(labels)):
        yield '.'.join(labels[i:])


def classify(raw_names, index):
    """({project_id: ProjectMatch}, dropped). Per project: longest owned root (equal or dot-suffix), else exact owned
    host, else equal/under a lookalike, else `others`. A project with no other kind of match is absent."""
    dropped = max(0, len(raw_names) - MAX_NAMES)
    seen, names = set(), []
    for raw in raw_names[:MAX_NAMES]:
        n = normalise(raw)
        if n is None:
            dropped += 1
        elif n not in seen:
            seen.add(n)
            names.append(n)
    out, hit = {}, {}  # hit: (name, wildcard) -> project ids that matched it
    for name, wild in names:
        got = hit.setdefault((name, wild), set())
        for suf in _suffixes(name):
            for pid, rid in index.roots.get(suf, ()):
                if pid not in got:
                    got.add(pid)
                    out.setdefault(pid, ProjectMatch([], [], [], [])).owned.append((name, wild, rid))
        if not wild:
            for pid, aid in index.hosts.get(name, ()):
                if pid not in got:
                    got.add(pid)
                    out.setdefault(pid, ProjectMatch([], [], [], [])).hosts.append((name, aid))
        for suf in _suffixes(name):
            for pid in index.lookalikes.get(suf, ()):
                if pid not in got:
                    got.add(pid)
                    out.setdefault(pid, ProjectMatch([], [], [], [])).lookalikes.append(suf)
    for pid, m in out.items():
        for (name, wild), got in hit.items():
            if pid not in got and name not in m.others:
                m.others.append(name)
    return out, dropped


def _split(s, sep):
    """Split on unescaped `sep`, keeping `\\x` escapes for the caller."""
    parts, cur, i = [], [], 0
    while i < len(s):
        c = s[i]
        if c == '\\' and i + 1 < len(s):
            cur.append(s[i:i + 2])
            i += 2
            continue
        if c == sep:
            parts.append(''.join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    parts.append(''.join(cur))
    return parts


def issuer_org(dn):
    """The O= value of an RFC 2253 / OpenSSL-style DN, else its CN=, else ''. Cleaned and at most 200 characters."""
    if not isinstance(dn, str):
        return ''
    dn = dn.strip()
    rdns = _split(dn, '/') if dn.startswith('/') else _split(dn, ',')
    found = {}
    for rdn in rdns:
        k, eq, v = rdn.partition('=')
        k = k.strip().upper()
        if eq and k in ('O', 'CN') and k not in found:
            found[k] = re.sub(r'\\(.)', r'\1', v)
    val = found.get('O') or found.get('CN') or ''
    return ' '.join(_CONTROL.sub(' ', val).split())[:ISSUER_MAX_CHARS]
