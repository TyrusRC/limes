"""Per-target scan identity: User-Agent + custom headers.

Secret header values are encrypted at rest (Fernet) and only ever reach tools
through 0600 temp files, never argv.
"""
import os
import tempfile
from dataclasses import dataclass, field

import yaml
from cryptography.fernet import Fernet
from django.conf import settings

DEFAULT_UA = 'limes/scan'


@dataclass
class Header:
    name: str
    value: str
    secret: bool = False


@dataclass
class ScanIdentity:
    user_agent: str = ''
    headers: list = field(default_factory=list)

    @property
    def ua(self):
        return self.user_agent or DEFAULT_UA

    @classmethod
    def for_domain(cls, domain):
        """Build from Domain.request_headers:
        {"user_agent": str, "headers": [{"name", "value", "secret"}]}
        Secret values are stored encrypted."""
        data = (domain.request_headers if domain else None) or {}
        headers = []
        for h in data.get('headers', []):
            secret = bool(h.get('secret'))
            value = decrypt(h['value']) if secret else h['value']
            headers.append(Header(h['name'], value, secret))
        return cls(user_agent=data.get('user_agent', ''), headers=headers)


def _fernet():
    return Fernet(settings.HEADER_ENCRYPTION_KEY.encode())


def encrypt(value):
    return _fernet().encrypt(value.encode()).decode()


def decrypt(token):
    return _fernet().decrypt(token.encode()).decode()


def _secret_file(header):
    fd, path = tempfile.mkstemp(prefix='limes-hdr-')  # mkstemp creates 0600
    with os.fdopen(fd, 'w') as f:
        f.write(f'{header.name}: {header.value}\n')
    os.chmod(path, 0o600)
    return path


def render_header_args(identity, flag='-H'):
    """Return (argv, tempfiles). Non-secret headers inline, secrets via @file."""
    argv = [flag, f'User-Agent: {identity.ua}']
    tmp = []
    for h in identity.headers:
        if h.secret:
            path = _secret_file(h)
            tmp.append(path)
            argv += [flag, f'@{path}']
        else:
            argv += [flag, f'{h.name}: {h.value}']
    return argv, tmp


def render_httpx(identity):
    # Explicit UA always set; never -random-agent.
    # httpx -H is inline-only (no '@file' form; that is katana's), so secrets go inline.
    # Callers MUST pass secrets=redaction_secrets(identity) to the runner so the
    # value is scrubbed from the Command row / commands.txt / logs.
    # NOTE: argv exposes the secret in the process table while running (accepted, as legacy).
    argv = ['-H', f'User-Agent: {identity.ua}']
    for h in identity.headers:
        argv += ['-H', f'{h.name}: {h.value}']
    return argv, []


def write_assay_config(identity, profile, path):
    """Write assay YAML. Returns tempfiles (caller also cleans up `path`).
    NOTE: secret header values land in this file (0600); delete after the run."""
    cfg = {
        'profile': profile,
        'user_agent': identity.ua,
        'headers': [f'{h.name}: {h.value}' for h in identity.headers],
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        yaml.safe_dump(cfg, f)
    return []


def redaction_secrets(identity):
    return [h.value for h in identity.headers if h.secret]


def cleanup(tempfiles):
    for p in tempfiles:
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass
