"""Personal API tokens: lmk_<8-char id>_<43-char secret>. Only sha256(full token) and the id are stored; the full
token is returned once by create_token and is never logged, stored or put in an exception message."""
import hashlib
import hmac
import logging
import re
import secrets
import string
from datetime import timedelta
from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.views.decorators.debug import sensitive_variables
from django.utils import timezone
from dashboard.models import ApiToken

PREFIX = 'lmk_'
ID_LEN = 8
ID_ALPHABET = string.ascii_lowercase + string.digits
SECRET_BYTES = 32
EXPIRY_DAYS = (30, 90, 365)
DEFAULT_DAYS = 90
SCOPES = ('read', 'read_write')
TOUCH_EVERY = timedelta(minutes=1)
SECRET_CHARS = -(-SECRET_BYTES * 4 // 3)  # token_urlsafe(32) is 43 unpadded base64url characters
_BODY = r'lmk_([a-z0-9]{%d})_([A-Za-z0-9_-]{%d})' % (ID_LEN, SECRET_CHARS)
TOKEN_RE = re.compile('^' + _BODY + '$')
TOKEN_FIND_RE = re.compile(_BODY)  # a token anywhere inside a string (used to scrub logs)
logger = logging.getLogger(__name__)


class TokenError(ValueError):
    pass


def hash_token(raw):
    return hashlib.sha256(raw.encode()).hexdigest()


@sensitive_variables('raw')
def create_token(user, name, days, scope, now=None):
    """Returns (ApiToken, full token). The full token exists only in this return value."""
    name = (name or '').strip()
    if not 1 <= len(name) <= 100:
        raise TokenError('name must be 1-100 characters')
    if days not in EXPIRY_DAYS:
        raise TokenError('expiry must be one of %s days' % ', '.join(map(str, EXPIRY_DAYS)))
    if scope not in SCOPES:
        raise TokenError('scope must be read or read_write')
    if scope == 'read_write' and not settings.MCP_WRITES_ENABLED:
        raise TokenError('write tokens are disabled on this instance')
    now = now or timezone.now()
    for _ in range(5):  # an id collision (36^8) is retried, not surfaced
        token_id = ''.join(secrets.choice(ID_ALPHABET) for _ in range(ID_LEN))
        raw = f'{PREFIX}{token_id}_{secrets.token_urlsafe(SECRET_BYTES)}'
        try:
            with transaction.atomic():
                tok = ApiToken.objects.create(user=user, name=name, token_id=token_id, token_hash=hash_token(raw),
                                              scope=scope, created_at=now, expires_at=now + timedelta(days=days))
            break
        except IntegrityError:
            continue
    else:
        raise TokenError('could not allocate a token id')
    return tok, raw


@sensitive_variables('raw')
def verify(raw, now=None):
    """The token's ApiToken, or None for any failure (malformed, unknown, wrong secret, expired, revoked, inactive user)."""
    # NOTE: an unknown id returns before hashing while a wrong secret pays sha256 + compare, so timing reveals only
    # whether a (non-secret) id exists. Upgrade path: hash a dummy value on the unknown-id branch.
    try:
        m = TOKEN_RE.match(raw) if isinstance(raw, str) else None
        if not m:
            return None
        tok = ApiToken.objects.select_related('user').filter(token_id=m.group(1)).first()
        if tok is None or not hmac.compare_digest(tok.token_hash, hash_token(raw)):
            return None
        if not tok.usable(now or timezone.now()) or not tok.user.is_active:
            return None
        return tok
    except Exception as e:  # fail closed; log the type only: the message could carry the token
        logger.warning('verify failed: %s', type(e).__name__)
        return None


def touch(token, now=None):
    """last_used_at = now, at most once per TOUCH_EVERY: one conditional UPDATE, no read."""
    now = now or timezone.now()
    ApiToken.objects.filter(Q(last_used_at__isnull=True) | Q(last_used_at__lt=now - TOUCH_EVERY), pk=token.pk) \
        .update(last_used_at=now)


def revoke(token, now=None):
    """False when it was already revoked."""
    return bool(ApiToken.objects.filter(pk=token.pk, revoked_at__isnull=True).update(revoked_at=now or timezone.now()))
