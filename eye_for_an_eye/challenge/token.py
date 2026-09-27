"""The challenge token: short-lived, signed, stateless, scoped to one site.

Stateless is the point. A server that keeps a row for every challenged request
hands an attacker a way to exhaust it: send a million requests, force a million
rows. A signed token moves that state to the client, where the attacker is
already paying for it.

The security properties, and why each is here:

**Versioned.** A token says which schema it is, so the format can change later
without every live cookie breaking at once.

**Signed with HMAC-SHA256**, from the standard library. Nothing here implements
a hash or a MAC by hand.

**Per-site keys, derived with HKDF.** One installation can serve many sites. A
token issued for one must not validate for another, and deriving per-site keys
from one master secret is how that works without managing a key per site.

**Constant-time comparison.** Comparing a MAC with `==` leaks how many bytes
matched through timing, which is enough to forge one given patience.

**Short-lived, with a hard ceiling.** Even a configured TTL cannot exceed the
maximum this module allows, because a long-lived challenge token starts to
resemble a trust cookie, and it is not one.

The token carries no identity. No username, no account, no session, no URL, no
address in plain text. What it carries is when it was issued, when it expires,
which site it is for, and a random nonce.
"""
import base64
import hashlib
import hmac
import os
import struct
import time

CHALLENGE_TOKEN_VERSION = 1
#: The name that appears in a cookie and in documentation.
TOKEN_SCHEME = 'challenge-v1'

#: Key derivation. The label binds derived keys to this purpose, so a key for
#: challenges can never collide with a key derived elsewhere from the same
#: master secret.
HKDF_INFO_PREFIX = b'EFAE-CHALLENGE-V1|site='
MASTER_SECRET_MIN_BYTES = 32
DERIVED_KEY_BYTES = 32

#: Bounds. A token is attacker-supplied text; every one of these is a refusal.
MAX_TOKEN_CHARS = 512
MAX_SITE_CHARS = 64
NONCE_BYTES = 12
MAC_BYTES = 32

#: Lifetime. `DEFAULT_TTL_SECONDS` is a starting point, not a calibrated value.
#: `MAX_TTL_SECONDS` is a ceiling no configuration can raise: past it a challenge
#: token stops being a challenge and starts being a trust cookie.
DEFAULT_TTL_SECONDS = 900
MAX_TTL_SECONDS = 3600
MIN_TTL_SECONDS = 30
#: Clocks drift. A token issued a little in the future is accepted; one issued
#: far in the future is not, because that is a forged or replayed timestamp.
MAX_CLOCK_SKEW_SECONDS = 60

#: Payload: version, issued_at, expires_at, level, nonce. Fixed width, so parsing
#: is deterministic and cannot be steered by the client.
_PAYLOAD = struct.Struct('>BIIB')
_PAYLOAD_BYTES = _PAYLOAD.size + NONCE_BYTES

#: Verification outcomes. Every one of these is a specific, loggable reason.
VALID = 'valid'
MALFORMED = 'malformed'
UNKNOWN_VERSION = 'unknown_version'
BAD_SIGNATURE = 'bad_signature'
EXPIRED = 'expired'
NOT_YET_VALID = 'not_yet_valid'
LIFETIME_TOO_LONG = 'lifetime_too_long'
WRONG_SITE = 'wrong_site'
OUTCOMES = (VALID, MALFORMED, UNKNOWN_VERSION, BAD_SIGNATURE, EXPIRED,
            NOT_YET_VALID, LIFETIME_TOO_LONG, WRONG_SITE)


class TokenError(ValueError):
    """A token could not be issued. Never raised while verifying one."""


def _hkdf(secret, info, length=DERIVED_KEY_BYTES):
    """HKDF-SHA256 (RFC 5869), extract-then-expand.

    A standard construction, implemented from its two standard primitives rather
    than invented. The salt is empty, which RFC 5869 permits and which is correct
    here: the master secret is already high-entropy random bytes, not a password.
    """
    prk = hmac.new(b'\x00' * hashlib.sha256().digest_size, secret, hashlib.sha256).digest()
    output, block, counter = b'', b'', 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]


def site_key(master_secret, site):
    """The signing key for one site, derived from the installation's master secret.

    Two sites on one server get different keys, so a token for one never
    validates for the other — without anyone having to manage a separate secret
    per site.
    """
    if not isinstance(master_secret, bytes) or len(master_secret) < MASTER_SECRET_MIN_BYTES:
        raise TokenError(f'the challenge secret must be at least '
                         f'{MASTER_SECRET_MIN_BYTES} bytes')
    scope = normalise_site(site)
    return _hkdf(master_secret, HKDF_INFO_PREFIX + scope.encode())


def normalise_site(site):
    """A configured site identifier, bounded and predictable.

    Deliberately **not** the Host header. A client controls Host, and using it as
    a cryptographic scope would let a client choose which key signs its token.
    This is an operator-configured identifier.

    The rule itself lives in `eye_for_an_eye.sites.identity` and is shared with
    the rest of the project. Two functions deciding what a site is called would
    drift, and the day they disagreed a token would be signed under one spelling
    and verified under another — which reads as "your challenge stopped working"
    and is very hard to trace back. This wrapper adds only the challenge layer's
    own fallback: an unnamed site still needs a key, and `default` is that key.
    """
    from ..sites.identity import normalise_site_id
    return normalise_site_id(site)[:MAX_SITE_CHARS] or 'default'


def _b64encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


#: The only characters a token may contain. Everything else is refused rather
#: than ignored.
_B64URL_ALPHABET = frozenset(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_')


def _b64decode(text):
    """Decode strict, canonical, unpadded base64url. Anything else is refused.

    Python's decoder is forgiving in three ways that all matter here. It accepts
    the standard `+/` alphabet as well as base64url's `-_`; it accepts trailing
    `=` padding; and by default it silently *discards* characters outside the
    alphabet rather than objecting to them.

    Each one gives a single token more than one spelling. That is not a
    signature bypass — the MAC still has to verify — but a value with several
    spellings is one that cannot safely be used as a cache key, deduplicated,
    counted, or compared, and every one of those is a plausible thing to want to
    do with a token later. Refusing non-canonical input now costs nothing and
    closes the whole class.
    """
    if len(text) % 4 == 1 or not _B64URL_ALPHABET.issuperset(text):
        raise ValueError('a challenge token must be canonical unpadded base64url')
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def issue(master_secret, *, site='default', ttl_seconds=DEFAULT_TTL_SECONDS, level=1,
          now=None):
    """Mint a token. Cheap: one HKDF and one HMAC."""
    ttl = int(ttl_seconds)
    if not MIN_TTL_SECONDS <= ttl <= MAX_TTL_SECONDS:
        raise TokenError(f'challenge token lifetime must be between {MIN_TTL_SECONDS} '
                         f'and {MAX_TTL_SECONDS} seconds')
    if not 0 <= int(level) <= 255:
        raise TokenError('challenge level must fit in one byte')
    issued = int(now if now is not None else time.time())
    payload = _PAYLOAD.pack(CHALLENGE_TOKEN_VERSION, issued, issued + ttl,
                            int(level)) + os.urandom(NONCE_BYTES)
    mac = hmac.new(site_key(master_secret, site), payload, hashlib.sha256).digest()
    return _b64encode(payload + mac)


class Verification:
    """The result of checking a token. Always a value, never an exception."""

    __slots__ = ('outcome', 'issued_at', 'expires_at', 'level', 'key_generation')

    def __init__(self, outcome, *, issued_at=0, expires_at=0, level=0, key_generation=''):
        self.outcome = outcome
        self.issued_at = issued_at
        self.expires_at = expires_at
        self.level = level
        self.key_generation = key_generation

    @property
    def valid(self):
        return self.outcome == VALID

    def explain(self):
        return {'token_scheme': TOKEN_SCHEME, 'outcome': self.outcome,
                'valid': self.valid, 'issued_at': self.issued_at,
                'expires_at': self.expires_at, 'level': self.level,
                'key_generation': self.key_generation,
                'meaning': ('a valid token means this client completed a challenge '
                            'recently; it is not authentication and grants nothing')}

    def __repr__(self):
        return f'Verification({self.outcome!r})'


def verify(token, master_secret, *, site='default', now=None,
           max_ttl_seconds=MAX_TTL_SECONDS, skew_seconds=MAX_CLOCK_SKEW_SECONDS,
           previous_secret=None, generation='current'):
    """Check a token. Never raises, whatever the client sent.

    Order matters. Cheap structural checks come first so that garbage costs
    almost nothing, and the signature is checked before any field inside the
    payload is believed — an unsigned timestamp is not a timestamp, it is a
    number an attacker chose.
    """
    if not token or not isinstance(token, str) or len(token) > MAX_TOKEN_CHARS:
        return Verification(MALFORMED)
    try:
        raw = _b64decode(token)
    except (ValueError, TypeError):
        return Verification(MALFORMED)
    if len(raw) != _PAYLOAD_BYTES + MAC_BYTES:
        return Verification(MALFORMED)

    payload, mac = raw[:_PAYLOAD_BYTES], raw[_PAYLOAD_BYTES:]
    version = payload[0]
    if version != CHALLENGE_TOKEN_VERSION:
        return Verification(UNKNOWN_VERSION)

    # Constant-time, and against the current key first. `compare_digest` is used
    # rather than `==` because a byte-by-byte comparison leaks how much of a
    # forged MAC was correct.
    matched = ''
    for name, secret in (('current', master_secret), ('previous', previous_secret)):
        if secret is None:
            continue
        try:
            expected = hmac.new(site_key(secret, site), payload, hashlib.sha256).digest()
        except TokenError:
            continue
        if hmac.compare_digest(mac, expected):
            matched = name
            break
    if not matched:
        # Indistinguishable from a token minted for another site: both are simply
        # a signature that does not verify under this site's key, which is the
        # property that makes scopes hold.
        return Verification(BAD_SIGNATURE)

    _, issued, expires, level = _PAYLOAD.unpack(payload[:_PAYLOAD.size])
    try:
        moment = int(now) if now is not None else int(time.time())
    except (ValueError, OverflowError, TypeError):
        # An unusable clock cannot decide whether a token is in date, and this
        # function promises never to raise. Refusing is the safe reading.
        return Verification(MALFORMED, issued_at=issued, expires_at=expires)

    if expires <= issued:
        return Verification(MALFORMED, issued_at=issued, expires_at=expires)
    if expires - issued > max_ttl_seconds:
        # A token that claims a longer life than this build allows, even with a
        # good signature. That means the issuing configuration changed, or the
        # secret leaked and somebody minted a long-lived one.
        return Verification(LIFETIME_TOO_LONG, issued_at=issued, expires_at=expires)
    if issued > moment + skew_seconds:
        return Verification(NOT_YET_VALID, issued_at=issued, expires_at=expires)
    if moment >= expires:
        return Verification(EXPIRED, issued_at=issued, expires_at=expires)

    return Verification(VALID, issued_at=issued, expires_at=expires, level=level,
                        key_generation=matched)


def remaining(verification, now=None):
    """Seconds left on a valid token, or zero."""
    if not verification.valid:
        return 0
    try:
        moment = int(now) if now is not None else int(time.time())
    except (ValueError, OverflowError, TypeError):
        return 0
    return max(0, verification.expires_at - moment)


def redact(text):
    """Remove anything that looks like a challenge token from a string.

    Used by the logging path. A token is not a credential, but it is the one
    thing in the flow that must not appear in a log file that gets shipped
    somewhere: a token plus a short TTL is a short-lived bypass of the challenge.
    """
    if not text:
        return text
    import re
    return re.sub(r'(?i)(' + COOKIE_NAME + r'|challenge_token|token)=[A-Za-z0-9_\-]{8,}',
                  r'\1=[redacted]', str(text))


#: The cookie name. Project-specific and stable, so it cannot collide with an
#: application's own `session` or `token` cookie.
COOKIE_NAME = '__efae_challenge'
