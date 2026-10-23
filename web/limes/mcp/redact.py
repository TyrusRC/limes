"""Scrubs secrets from scan logs before they are shown to an agent.
Order for every caller: window (tail_window) -> normalise -> redact -> length cap -> mark untrusted. Normalising first
matters: stripping control and zero-width characters AFTER redaction would rebuild a secret that they had split."""
import base64
import json
import logging
import re
import unicodedata
from urllib.parse import quote, quote_plus, unquote
from limes import commands, identity

logger = logging.getLogger(__name__)

R = '***'
_DROP = ('Cc', 'Cf', 'Cs', 'Zl', 'Zp')  # the categories results.clean strips
_ANSI = re.compile(r'\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[@-Z\\-_]')
LEARN_MAX = 50  # labelled values remembered per text, to scrub where they reappear unlabelled
LEARN_MIN = 6
QUOTED_MAX = 4096

# A name is secret-like when one of its segments (split on _ - . and camelCase) is one of these words, or ends or
# starts like one. 'author', 'bypass', 'passed', 'monkey', 'keyboard' and 'tokenizer' are not.
_EXACT = {'key', 'keys', 'secret', 'secrets', 'token', 'tokens', 'password', 'passwords', 'passwd', 'passphrase', 'pass',
          'pwd', 'pw', 'auth', 'oauth', 'authorization', 'credential', 'credentials', 'creds', 'apikey', 'sig',
          'signature'}
_SUFFIX = ('password', 'passwd', 'passphrase', 'secret', 'token', 'apikey', 'accesskey', 'secretkey', 'privatekey', 'pwd')
_PREFIX = ('password', 'passwd', 'passphrase', 'secret', 'credential', 'apikey', 'authorization')
_CAMEL = re.compile(r'[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+')
_SPLIT = re.compile(r'[_.\-]+')


def _word(w):
    return w in _EXACT or w.endswith(_SUFFIX) or w.startswith(_PREFIX)


def secret_name(name):
    for part in _SPLIT.split(name):
        if _word(part.lower()) or any(_word(s.lower()) for s in _CAMEL.findall(part)):
            return True
    return False


_QUOTED = r'"(?:[^"\\]|\\.){0,%d}"|\'(?:[^\'\\]|\\.){0,%d}\'' % (QUOTED_MAX, QUOTED_MAX)
_VALUE = re.compile(_QUOTED + r'|\S+', re.S)  # a quoted value may hold spaces, escaped quotes and line breaks
_NAME_HEAD = re.compile(
    r'(?<![A-Za-z0-9_.-])(?P<name>[A-Za-z0-9_.-]{1,60})'
    r'(?P<sep>["\']?[ \t]*(?:=>|:=|[=:])(?:[ \t]*\n[ \t]*|[ \t]*)|["\'][ \t]*,[ \t]*(?=["\']))')
_FLAG_HEAD = re.compile(r'(?<![\w-])(?P<name>--?[A-Za-z][\w-]{0,40})(?P<sep>[ \t]+)(?!-)')
_XML = re.compile(r'<(?P<tag>[A-Za-z0-9_.:-]{1,60})(?:\s[^<>]{0,200})?>(?P<v>[^<]{1,2000})</(?P=tag)>')
_PCT_NAME = re.compile(r'(?<![\w%.-])[\w.-]{0,60}(?:%[0-9A-Fa-f]{2}[\w.-]{0,60}){1,4}(?==)')
_HEADERS = r'(?:proxy-)?authorization|set-cookie|cookie|x-api-key|x-auth-token'


def normalise(text):
    """ANSI sequences out; CR and CRLF become a line break; control, format, surrogate and line-separator characters
    out (\\n and \\t stay); other space separators (NBSP...) become a plain space; fullwidth ASCII forms (U+FF01-FF5E) fold to ASCII.
    NOTE: only that block is folded, not full NFKC: NFKC would also rewrite 10 1/2, circled digits, TM and
    superscripts, i.e. change the meaning of log text the agent reads. Other confusables are not folded."""
    text = _ANSI.sub('', text).replace('\r\n', '\n').replace('\r', '\n')
    return ''.join(chr(ord(ch) - 0xFEE0) if '\uff01' <= ch <= '\uff5e' else ' ' if unicodedata.category(ch) == 'Zs' else ch
                   for ch in text if ch in '\n\t' or unicodedata.category(ch) not in _DROP)


_BREAK = re.compile(r'[\n\r]')
_SOFT = re.compile(r'[\s&,;]')


def tail_window(text, size):
    """(window, cut): the last `size` characters and whether the head was dropped. When cut, the first (possibly cut)
    line is dropped so no secret can start before the window and be shown half-redacted; CR counts as a line break.
    A window with no line break (one long line, minified JSON) drops up to the first whitespace, & , or ; instead,
    else its first 256 characters, so the newest output is still returned."""
    if len(text) <= size:
        return text, False
    win = text[-size:]
    m = _BREAK.search(win) or _SOFT.search(win)
    return (win[m.end():] if m else win[256:]), True


def domain_secrets(domain):
    """The scan target's secret header values. A value that cannot be decrypted yields no secrets, never an error."""
    try:
        return identity.redaction_secrets(identity.ScanIdentity.for_domain(domain))
    except Exception as e:
        logger.warning('MCP log redaction: could not read the scan identity (%s)', type(e).__name__)
        return []


def _forms(v):
    """The value and the encodings it is likely to reappear in: URL, JSON-escaped and base64 (three alignments)."""
    out = {v, quote(v, safe=''), quote_plus(v), json.dumps(v)[1:-1]}
    raw = v.encode('utf-8', 'replace')
    for pad, skip in ((0, 0), (1, 2), (2, 3)):
        enc = base64.b64encode(b'\0' * pad + raw).decode().rstrip('=')
        tail = {0: 0, 1: 2, 2: 1}[(pad + len(raw)) % 3]
        enc = enc[skip:len(enc) - tail]
        if len(enc) >= 8:
            out.add(enc)
    return sorted((f for f in out if f), key=len, reverse=True)


def _scrub(text, values):
    for v in values:
        for f in _forms(v):
            text = text.replace(f, R)
    return text


def _clip(v):
    v = v.strip()
    return v[1:-1] if len(v) >= 2 and v[0] in '"\'' and v[-1] == v[0] else v


class _Learn:
    """Labelled values seen in one text. NOTE: capped at LEARN_MAX so the exact-value pass stays cheap."""

    def __init__(self):
        self.values = []

    def add(self, v):
        v = v.strip()
        if v and v[0] not in '"\'' and ' ' in v:  # 'Bearer abc': the token is the secret
            v = v.split()[-1]
        v = _clip(v)
        if LEARN_MIN <= len(v) <= 200 and R not in v and v not in self.values and len(self.values) < LEARN_MAX:
            self.values.append(v)


def _pairs(text, head, is_secret, learn):
    out, pos = [], 0
    while True:
        m = head.search(text, pos)
        if not m:
            break
        end = m.end()
        v = _VALUE.match(text, end) if is_secret(m.group('name')) else None
        if v:
            out += [text[pos:end], R]
            learn.add(v.group())
            pos = v.end()
        else:
            out.append(text[pos:end])
            pos = end
    out.append(text[pos:])
    return ''.join(out)


def _sub(pattern, repl, learn_group=None):
    rx = re.compile(pattern, re.S) if isinstance(pattern, str) else pattern

    def step(text, learn):
        def fn(m):
            if learn_group:
                learn.add(m.group(learn_group))
            return m.expand(repl) if isinstance(repl, str) else repl(m)
        return rx.sub(fn, text)
    return step


def _userinfo(m):
    rest = m.group(1)
    first = rest.split('/')[0]
    if '@' in first:  # user@host, user:pass@host, and a password holding @
        cut = first.rindex('@')
    elif ':' in first and not re.fullmatch(r'[^:]+:\d+', first) and '@' in rest:  # a password holding /
        cut = rest.rindex('@')
    else:
        return m.group(0)
    return '://' + R + '@' + rest[cut + 1:]


def _flag_ok(name):
    return secret_name(name.lstrip('-'))


_STEPS = [
    # private key blocks (PEM, PGP, JSON-escaped with literal \n): whole, unterminated (cut at the end), and the
    # tail of one whose start was cut off
    _sub(r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\Z)', R),
    _sub(r'\A[A-Za-z0-9+/=\s\\]*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----', R),
    # header values to the end of the line, plus indented continuation lines
    _sub(r'(?i)\b(' + _HEADERS + r')(["\']?[ \t]*[:=][ \t]*)([^\n]*(?:\n[ \t]+[^\n]*)*)', r'\1\2' + R, 3),
    # curl -u user:pass, -uuser:pass, --user=user:pass (a value that is a URL is a target, not a credential)
    _sub(r'(?<![\w-])(-u|--user)([ \t]*=?[ \t]*)(?![A-Za-z][A-Za-z0-9+.-]*://)[^\s:]+:(\S*)', r'\1\2' + R, 3),
    lambda text, learn: _pairs(text, _FLAG_HEAD, _flag_ok, learn),  # --password x, --token x, -k x
    # -p x and -pX unless the value is a port list (mysql -p12345678 is left alone: it reads as one)
    _sub(r'(?<![\w-])(-p)(?:([ \t]+)|(?=[A-Za-z_@!#$%^*\'"]))(?![\dUTSuts:,-]+(?:\s|$))(?!-)(\S+)', r'\1\2' + R, 3),
    # URL userinfo: before the first / of the URL, or up to the last @ when the password holds a /
    _sub(r'://(\S{0,300})', _userinfo),
    _sub(r'(?i)\b(bearer|basic)(\s+)([A-Za-z0-9._~+/=-]{6,})', r'\1\2' + R, 3),
    # env, query, JSON, YAML, PHP and define() shapes, by secret-like name
    lambda text, learn: _pairs(text, _NAME_HEAD, secret_name, learn),
    _sub(_XML, lambda m: m.group(0).replace(m.group('v'), R) if secret_name(m.group('tag')) else m.group(0)),
    # Azure SAS signature and connection-string keys
    _sub(r'(?i)\b(sig|accountkey|sharedaccesskey)=([^&;\s"\']+)', r'\1=' + R, 2),
    # AWS secret access key next to an access key id, either order (a bare 40-char blob alone cannot be told from a
    # hash: ceiling documented in redact_log)
    _sub(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b[^\n]{0,80}?(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])', R),
    _sub(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])[^\n]{0,80}?\b(?:AKIA|ASIA)[0-9A-Z]{16}\b', R),
    _sub(r'\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*', R),  # JWT
    _sub(r'\blmk_[A-Za-z0-9_-]+', R),  # this instance's own MCP tokens
    _sub(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b', R),
    _sub(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})', R),
    _sub(r'\bxox[abprs]-[A-Za-z0-9-]{10,}', R),
    _sub(r'https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]+', R),
    _sub(r'\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}|\bwhsec_[A-Za-z0-9]{16,}', R),  # Stripe keys and webhook secrets
    _sub(r'\bAIza[0-9A-Za-z_-]{30,}', R),  # Google API key
    _sub(r'\bglpat-[A-Za-z0-9_-]{20,}', R),  # GitLab
    _sub(r'\bsk-[A-Za-z0-9_-]{20,}', R),  # OpenAI (sk-, sk-proj-) and Anthropic (sk-ant-)
    _sub(r'\bnpm_[A-Za-z0-9]{30,}', R),
    _sub(r'\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}', R),  # SendGrid
    _sub(r'\bSK[0-9a-fA-F]{32}\b', R),  # Twilio API key
]


def redact_log(text, secrets=()):
    """Normalise, then replace secrets with ***. Guarantees: the exact `secrets` given (and their URL, JSON and base64
    forms), the shapes in _STEPS, and any value that appeared once under a secret-like label, wherever else it shows up
    in the same text.
    NOTE: pattern-based; a secret in an unknown shape passes. A bare 40-character AWS secret key with no key id or name
    near it cannot be told from a hash, and a bare base64 blob of user:password cannot be told from any other base64.
    Upgrade path: tools redact at the source (identity.redaction_secrets already does for scan headers)."""
    if not text:
        return text or ''
    exact = [v for s in secrets if s for v in (s, normalise(s))]
    text = _PCT_NAME.sub(lambda m: unquote(m.group(0)), normalise(text))
    text = _scrub(text, exact)
    learn = _Learn()
    for step in _STEPS:
        text = step(text, learn)
    return _scrub(text, exact + learn.values)
