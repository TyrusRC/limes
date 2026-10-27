"""ID-token validation with `cryptography` only. Accepts RS256 and ES256 and nothing else: `none` and the HS* family
(where the public key would be used as an HMAC secret) are refused by the algorithm allowlist before any key is
touched. The key is chosen by the token's kid from the provider's JWKS, never from the token itself (jwk, jku, x5u and
crit are not honoured; crit is refused)."""
import base64
import hmac
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

ALGS = ('RS256', 'ES256')
MAX_TOKEN = 32 * 1024
MIN_RSA_BITS = 2048


class TokenError(Exception):
    """An id token that must not be trusted. `reason` is a short code, safe to log; the token itself never is."""
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _b64(part):
    try:
        return base64.urlsafe_b64decode(part + '=' * (-len(part) % 4))
    except (ValueError, TypeError):
        raise TokenError('malformed')


def _json(part):
    try:
        out = json.loads(_b64(part))
    except (ValueError, RecursionError):
        raise TokenError('malformed')
    if not isinstance(out, dict):
        raise TokenError('malformed')
    return out


def _int(value):
    if not isinstance(value, str) or not value:
        raise TokenError('bad_key')
    return int.from_bytes(_b64(value), 'big')


def _public_key(jwk, alg):
    try:
        if alg == 'RS256' and jwk.get('kty') == 'RSA':
            key = rsa.RSAPublicNumbers(_int(jwk.get('e')), _int(jwk.get('n'))).public_key()
            if key.key_size < MIN_RSA_BITS:
                raise TokenError('weak_key')
            return key
        if alg == 'ES256' and jwk.get('kty') == 'EC' and jwk.get('crv') == 'P-256':
            return ec.EllipticCurvePublicNumbers(_int(jwk.get('x')), _int(jwk.get('y')), ec.SECP256R1()).public_key()
    except (ValueError, TypeError):
        raise TokenError('bad_key')
    raise TokenError('bad_key')


def _candidates(jwks, alg, kid):
    keys = jwks.get('keys') if isinstance(jwks, dict) else None
    if not isinstance(keys, list):
        raise TokenError('no_keys')
    fits = [k for k in keys if isinstance(k, dict) and k.get('use') in (None, 'sig') and
            k.get('kty') == ('RSA' if alg == 'RS256' else 'EC') and (k.get('alg') in (None, alg))]
    if kid is not None:
        fits = [k for k in fits if k.get('kid') == kid]
    elif len(fits) != 1:
        raise TokenError('ambiguous_key')  # no kid and not exactly one usable key: do not guess
    if not fits:
        raise TokenError('unknown_kid')
    return fits


def _check_signature(alg, key, signing_input, signature):
    try:
        if alg == 'RS256':
            key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        else:
            if len(signature) != 64:
                raise TokenError('bad_signature')
            der = encode_dss_signature(int.from_bytes(signature[:32], 'big'), int.from_bytes(signature[32:], 'big'))
            key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise TokenError('bad_signature')


def header_of(token):
    """The unverified header, only to learn the kid for a JWKS refetch. Nothing from it is trusted."""
    parts = token.split('.') if isinstance(token, str) else []
    if len(parts) != 3 or len(token) > MAX_TOKEN or not token.isascii():
        raise TokenError('malformed')
    return _json(parts[0])


def verify(token, jwks, *, issuer, audience, nonce, now, leeway=60):
    """The claims of a valid id token, else TokenError. `now` is a unix time."""
    header = header_of(token)
    alg = header.get('alg')
    if alg not in ALGS or 'crit' in header:  # also catches 'none', 'HS256' and a non-string alg
        raise TokenError('bad_alg')
    kid = header.get('kid')
    if kid is not None and not isinstance(kid, str):
        raise TokenError('malformed')
    signing_input, _, sig = token.rpartition('.')
    signature = _b64(sig)
    last = None
    for jwk in _candidates(jwks, alg, kid):
        try:
            _check_signature(alg, _public_key(jwk, alg), signing_input.encode('ascii'), signature)
            last = None
            break
        except TokenError as e:
            last = e
    if last is not None:
        raise last
    claims = _json(token.split('.')[1])
    if claims.get('iss') != issuer:
        raise TokenError('bad_iss')
    aud = claims.get('aud')
    auds = aud if isinstance(aud, list) else [aud]
    if audience not in auds or not all(isinstance(a, str) for a in auds):
        raise TokenError('bad_aud')
    if len(auds) > 1 and claims.get('azp') != audience:
        raise TokenError('bad_azp')
    for name in ('exp', 'iat'):
        if isinstance(claims.get(name), bool) or not isinstance(claims.get(name), (int, float)):
            raise TokenError(f'missing_{name}')
    if claims['exp'] <= now - leeway:
        raise TokenError('expired')
    if claims['iat'] > now + leeway:
        raise TokenError('iat_in_future')
    if 'nbf' in claims:
        nbf = claims['nbf']
        if isinstance(nbf, bool) or not isinstance(nbf, (int, float)) or nbf > now + leeway:
            raise TokenError('not_yet_valid')
    sub = claims.get('sub')
    if not isinstance(sub, str) or not sub or len(sub) > 255:
        raise TokenError('bad_sub')
    got = claims.get('nonce')
    if not isinstance(got, str) or not nonce or not hmac.compare_digest(got.encode(), nonce.encode()):
        raise TokenError('bad_nonce')
    return claims
