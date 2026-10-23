"""Scrubs secrets from scan logs before they are shown to an agent. Runs before marking and before the length cap."""
import re
from limes import commands

R = '***'
_NAME = r'[A-Za-z0-9_.-]{0,40}'  # bounded: an unbounded prefix makes the key=value scan quadratic on long runs

# (pattern, replacement), applied in order
PATTERNS = [
    # header values, to the end of the line (also covers `-H 'Authorization: ...'` and JSON echoes)
    (re.compile(r'(?i)\b((?:proxy-)?authorization|set-cookie|cookie|x-api-key|x-auth-token)(["\']?[ \t]*[:=][ \t]*)[^\r\n]*'),
     r'\1\2' + R),
    (re.compile(r'(?i)\b(bearer[ \t]+)[A-Za-z0-9._~+/=-]+'), r'\1' + R),
    (re.compile(r'(://)[^/\s@]+@'), r'\1' + R + '@'),
    # env, query, argument and JSON shapes: any name containing key/secret/token/password
    (re.compile(r'(?i)\b(' + _NAME + r'(?:key|secret|token|password|passwd)' + _NAME + r')(["\']?[ \t]*[=:][ \t]*["\']?)[^\s&"\',;]+'),
     r'\1\2' + R),
    (re.compile(r'\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*'), R),  # JWT
    (re.compile(r'\blmk_[A-Za-z0-9_-]+'), R),  # this instance's own MCP tokens
    (re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'), R),
    (re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})'), R),
    (re.compile(r'\bxox[abprs]-[A-Za-z0-9-]{10,}'), R),
    # a whole block, an unterminated one (cut off at the end), and the tail of one whose start was cut off
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)', re.S), R),
    (re.compile(r'\A[A-Za-z0-9+/=\s]*?-----END [A-Z ]*PRIVATE KEY-----'), R),
]


def redact_log(text, secrets=()):
    """NOTE: pattern-based; a secret in an unknown shape passes. Upgrade path: tools redact at the source
    (identity.redaction_secrets already does for scan headers)."""
    if not text:
        return text or ''
    for pattern, repl in PATTERNS:
        text = pattern.sub(repl, text)
    return commands.redact(text, secrets)
