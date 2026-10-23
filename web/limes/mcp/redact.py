"""Scrubs secrets from scan logs before they are shown to an agent.
Order for every caller: window (tail_window) -> normalise -> redact -> length cap -> mark untrusted. Normalising first
matters: stripping control and zero-width characters AFTER redaction would rebuild a secret that they had split."""
import re
import unicodedata
from limes import commands

R = '***'
_DROP = ('Cc', 'Cf', 'Cs', 'Zl', 'Zp')  # the categories results.clean strips
_ANSI = re.compile(r'\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[@-Z\\-_]')

_SECRET_WORDS = r'(?:key|secret|token|passw|pwd|pass|auth|credential)'
_NAME = r'[A-Za-z0-9_.-]{0,40}'  # bounded: an unbounded prefix makes the scan quadratic on long runs
_QUOTED = r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\''
_VALUE = r'(?:' + _QUOTED + r'|\S+)'
_HEADERS = r'(?:proxy-)?authorization|set-cookie|cookie|x-api-key|x-auth-token'

# (pattern, replacement), applied in order
PATTERNS = [
    # private key blocks (PEM, PGP, JSON-escaped with literal \n): whole, unterminated (cut at the end), and the
    # tail of one whose start was cut off
    (re.compile(r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\Z)', re.S), R),
    (re.compile(r'\A[A-Za-z0-9+/=\s\\]*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----'), R),
    # header values to the end of the line, plus indented continuation lines
    (re.compile(r'(?i)\b(' + _HEADERS + r')(["\']?[ \t]*[:=][ \t]*)[^\n]*(?:\n[ \t]+[^\n]*)*'), r'\1\2' + R),
    # curl -u user:pass / --user (a -u whose value is a URL is a target, not a credential)
    (re.compile(r'(?<![\w-])(-u|--user)([ \t]+|=)(?![A-Za-z][A-Za-z0-9+.-]*://)[^\s:]*:\S*'), r'\1\2' + R),
    # flags: --password x, --token x ...; -p x and -pX unless the value is a port list
    (re.compile(r'(?i)(?<![\w-])(--?[\w-]*' + _SECRET_WORDS + r'[\w-]*|--?apikey)([ \t]+)(?!-)' + _VALUE), r'\1\2' + R),
    (re.compile(r'(?<![\w-])(-p)(?:([ \t]+)|(?=[A-Za-z_@!#$%^*\'"]))(?![\d,-]+(?:\s|$))(?!-)' + _VALUE), r'\1\2' + R),
    # URL userinfo up to the LAST @ of the token (passwords may hold / and @)
    (re.compile(r'(://)(?=\S{0,256}@)\S{0,256}@'), r'\1' + R + '@'),
    (re.compile(r'(?i)\b(bearer|basic)(\s+)[A-Za-z0-9._~+/=-]{6,}'), r'\1\2' + R),
    # names containing key/secret/token/password/pass/pwd/auth/credential, in env, query, JSON and YAML shapes;
    # the value may be quoted (spaces, escaped quotes), on the next indented line, or run to the next whitespace
    (re.compile(r'(?i)\b(' + _NAME + _SECRET_WORDS + _NAME + r')(["\']?[ \t]*[=:](?:[ \t]*|[ \t]*\n[ \t]+))' + _VALUE),
     r'\1\2' + R),
    # AWS secret access key next to an access key id, either order (a nameless 40-char blob alone cannot be told
    # from a hash: ceiling documented in redact_log)
    (re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b[^\n]{0,80}?(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])'), R),
    (re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])[^\n]{0,80}?\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'), R),
    (re.compile(r'\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*'), R),  # JWT
    (re.compile(r'\blmk_[A-Za-z0-9_-]+'), R),  # this instance's own MCP tokens
    (re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'), R),
    (re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})'), R),
    (re.compile(r'\bxox[abprs]-[A-Za-z0-9-]{10,}'), R),
    (re.compile(r'https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+'), R),
    (re.compile(r'\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}'), R),  # Stripe
    (re.compile(r'\bAIza[0-9A-Za-z_-]{30,}'), R),  # Google API key
]


def normalise(text):
    """ANSI sequences and control/format/surrogate/line-separator characters out (\\n and \\t stay), then NFKC so
    fullwidth and compatibility forms collapse onto the ASCII a pattern expects."""
    text = _ANSI.sub('', text)
    text = ''.join(ch for ch in text if ch in '\n\t' or unicodedata.category(ch) not in _DROP)
    return unicodedata.normalize('NFKC', text)


def tail_window(text, size):
    """The last `size` characters, without the first (possibly cut) line, so no secret can start before the window and
    be shown half-redacted. A cut window with no line break yields ''."""
    if len(text) <= size:
        return text
    win = text[-size:]
    i = win.find('\n')
    return win[i + 1:] if i >= 0 else ''


def redact_log(text, secrets=()):
    """Normalise, then replace secrets with ***. Guarantees: the exact `secrets` given, and the shapes in PATTERNS.
    NOTE: pattern-based; a secret in an unknown shape passes, and a bare 40-character AWS secret key with no key id or
    name near it cannot be told from a hash. Upgrade path: tools redact at the source (identity.redaction_secrets
    already does for scan headers)."""
    if not text:
        return text or ''
    exact = [s for v in secrets if v for s in (v, normalise(v))]
    text = commands.redact(normalise(text), exact)
    for pattern, repl in PATTERNS:
        text = pattern.sub(repl, text)
    return commands.redact(text, exact)
