"""What authentication actually happened, as distinct from what was carried.

### The bug this module exists to fix

Until P15.4 the system had one authentication signal, `credentials_60s`, and it
counted this:

    lower.startswith((b'user ', b'pass ', b'auth ', b'login '))
    or b'authorization:' in lower or b'cookie:' in lower ...

That is **credential presence**. It fires on `USER alice` from a backup script
and on `USER admin` from a brute-forcer, identically. It fires on every request
of every authenticated API client, because such a client sends an
`Authorization:` header every single time. It carried weight 3.0 — the
joint-largest term in `MathRisk` — and on the P15.3 locked benchmark it blocked
**21 of 22 sources** of a legitimate authenticated batch client, at a median
contribution of 3.000, which is the maximum the term can produce. The same
family scored *higher* than a malicious credential-automation family.

The defect was never the weight. It was the sentence the weight encoded:

    many credential-bearing requests → authentication attack

That sentence is false. A client that authenticates on every request is the
normal case for machine-to-machine traffic, and reducing the weight would only
have made the system wrong more quietly.

### What replaces it

Authentication *outcome*, which is a different observation and a much better
one. A brute-forcer and a backup script both present credentials; only one of
them keeps **failing**.

    request carries a credential   →  says almost nothing
    request carries a credential
      and the server answered 530  →  says something
      and it happened 40 times
      across 15 principals         →  says a great deal

### What this sensor can honestly see

Eye for an Eye watches traffic arriving at one host, and the responses that host
sends back. For a cleartext protocol the outcome is right there in the reply:
`530 Login incorrect`, `HTTP/1.1 401`, `SSH ... authentication failed`. For
anything inside TLS it is invisible.

So the answer has five states and `UNKNOWN` is a first-class one (§4, §7). It is
not a synonym for failure, and it is never quietly upgraded to success. A
deployment that terminates TLS at a reverse proxy, or integrates at the
application, can supply a real answer; a passive sensor watching an encrypted
session cannot, and says so.

### What is never stored

No password. No `Authorization` header value. No raw token, cookie, secret or
credential body — not in a feature, not in a digest, not in a decision record
(§3, §10). A principal identifier is kept only as a keyed pseudonym derived with
a process-local key that is never written to disk, and only from the plainly
non-secret identifier half of a cleartext protocol command (`USER <name>`). The
secret half is not read, not hashed and not counted.

That last restriction is deliberate and costs something: it means HTTP requests
contribute failure *counts* but never principal *diversity*. Hashing an
`Authorization:` header would give better diversity evidence and would also mean
storing a value derived from a live secret, which is a trade this project does
not make.
"""
from dataclasses import dataclass
import hashlib
import hmac
import re
import secrets

AUTH_SCHEMA_VERSION = 1

#: §4. Five explicit states. `UNKNOWN` means the sensor could not observe the
#: outcome and is never treated as a failure; `NOT_APPLICABLE` means no
#: authentication was attempted at all, which is most traffic.
SUCCESS = 'SUCCESS'
FAILURE = 'FAILURE'
DENIED = 'DENIED'
UNKNOWN = 'UNKNOWN'
NOT_APPLICABLE = 'NOT_APPLICABLE'
RESULTS = (SUCCESS, FAILURE, DENIED, UNKNOWN, NOT_APPLICABLE)

#: Outcomes that are evidence of abuse when they accumulate. `DENIED` is an
#: authorisation refusal rather than a bad credential — a valid principal
#: reaching for something it may not have — and it is counted separately because
#: the two mean different things even though both are refusals.
ABUSIVE_RESULTS = (FAILURE, DENIED)

#: §14. Configured route classes. Context, never ground truth: a request to an
#: ADMIN route is not malicious for being there, and a request to a PUBLIC route
#: is not innocent for the same reason.
PUBLIC = 'PUBLIC'
AUTH_ROUTE = 'AUTH'
API = 'API'
ADMIN = 'ADMIN'
WEBHOOK = 'WEBHOOK'
STATIC = 'STATIC'
ROUTE_CLASSES = (PUBLIC, AUTH_ROUTE, API, ADMIN, WEBHOOK, STATIC)

#: Coarse mechanism categories. Deliberately coarse: the point is to tell a
#: browser login from a machine token, not to inventory a site's auth stack.
PASSWORD = 'PASSWORD'
BEARER = 'BEARER'
BASIC = 'BASIC'
SIGNATURE = 'SIGNATURE'
MECHANISM_UNKNOWN = 'UNKNOWN'
MECHANISMS = (PASSWORD, BEARER, BASIC, SIGNATURE, MECHANISM_UNKNOWN)

#: How many observed refusals a *derived* statistic about refusals needs before
#: it is a measurement rather than an arithmetic accident.
#:
#: Two quantities depend on this and both were wrong without it. A failure
#: **ratio** over three attempts reads 0.67 for somebody mistyping a password
#: twice; that is not a two-thirds failure rate, it is a Monday. A failure
#: **span** over two refusals reads "300 seconds of sustained failure" for a
#: service token that expired twice during a ten-minute run, and on the P15.4
#: development families that single term alone carried a legitimate service
#: account to 0.580.
#:
#: Both are the P15.3 defect in miniature: a number that is arithmetically
#: correct and does not mean what its name says. The fix is not a smaller weight
#: (§2) — it is refusing to compute the statistic until its denominator exists.
#:
#: Six is where a count stops being explainable by ordinary human error: three
#: wrong passwords is common, six in a row from one source is not, and the
#: argument is the same whether the statistic derived from them is a fraction or
#: a duration. It is deliberately one constant rather than two, so there is a
#: single number to disagree with.
MIN_FAILURES_FOR_A_DERIVED_STATISTIC = 6

#: §11. Bounds on everything that could grow with attacker input.
MAX_PRINCIPALS_PER_SOURCE = 64
PRINCIPAL_PSEUDONYM_BYTES = 8
MAX_IDENTIFIER_BYTES = 64
AUTH_STATE_TTL_SECONDS = 900

#: The identifier half of a cleartext protocol command. The command word is
#: matched, the rest of the line is the identifier, and anything that looks like
#: a secret-bearing command is excluded below.
_IDENTIFIER_COMMAND = re.compile(rb'^(user|login|account)[ \t]+([^\r\n]{1,64})', re.IGNORECASE)

#: Commands whose argument IS the secret. Their arguments are never read, hashed
#: or counted — only the fact that an authentication step occurred.
_SECRET_COMMANDS = (b'pass ', b'password ', b'auth ')

_FAILURE_PATTERNS = (
    # FTP and SMTP-style numeric replies for a rejected login.
    (rb'^(530|430|535|534)\b', FAILURE),
    (rb'^(550|532)\b', DENIED),
    # HTTP status lines.
    (rb'^http/[\d.]+ 401\b', FAILURE),
    (rb'^http/[\d.]+ 403\b', DENIED),
    # Common textual refusals from line protocols.
    (rb'authentication fail', FAILURE),
    (rb'login incorrect', FAILURE),
    (rb'invalid (?:user|password|credential)', FAILURE),
    (rb'permission denied', FAILURE),
    (rb'-err (?:auth|invalid)', FAILURE),
    (rb'access denied', DENIED),
    (rb'not authorized', DENIED),
)

_SUCCESS_PATTERNS = (
    (rb'^(230|235|250)\b', SUCCESS),
    (rb'^http/[\d.]+ 2\d\d\b', SUCCESS),
    (rb'login successful', SUCCESS),
    (rb'authentication succ', SUCCESS),
    (rb'user logged in', SUCCESS),
)


@dataclass(frozen=True, slots=True)
class AuthenticationEvent:
    """One authentication step, normalised. §3.

    Every field is either observed or explicitly absent. Nothing here is
    inferred from another field — in particular `result` is never derived from
    `credential_present`, which is the inference that produced the P15.3 false
    blocks.
    """

    timestamp: float
    source_group: str = ''
    site_id: str = ''
    route_class: str = PUBLIC
    auth_attempted: bool = False
    result: str = NOT_APPLICABLE
    mechanism: str = MECHANISM_UNKNOWN
    credential_present: bool = False
    #: Keyed pseudonym, or empty when no identifier was safely available.
    principal: str = ''

    def __post_init__(self):
        if self.result not in RESULTS:
            raise ValueError(f'unknown authentication result {self.result!r}')
        if self.route_class not in ROUTE_CLASSES:
            raise ValueError(f'unknown route class {self.route_class!r}')
        if self.mechanism not in MECHANISMS:
            raise ValueError(f'unknown authentication mechanism {self.mechanism!r}')
        if len(self.principal) > 2 * PRINCIPAL_PSEUDONYM_BYTES:
            raise ValueError('principal pseudonym exceeds its bound')
        if not self.auth_attempted and self.result in (SUCCESS, FAILURE, DENIED):
            raise ValueError('an outcome without an attempt is not an observation')

    @property
    def abusive(self):
        """A refusal that counts toward abuse evidence. Never `UNKNOWN`."""
        return self.result in ABUSIVE_RESULTS

    def explain(self):
        return {'auth_schema_version': AUTH_SCHEMA_VERSION,
                'route_class': self.route_class, 'auth_attempted': self.auth_attempted,
                'result': self.result, 'mechanism': self.mechanism,
                'credential_present': self.credential_present,
                'principal_pseudonymous': bool(self.principal)}


def principal_pseudonym(key, identifier):
    """A keyed, truncated, non-reversible stand-in for an account name. §10.

    The key is process-local and never persisted, exactly like the probe digest
    key. Truncation is deliberate: the value only ever needs to answer "is this
    the same principal as that one", and a shorter value is a smaller thing to
    leak.
    """
    if not identifier:
        return ''
    if isinstance(identifier, str):
        identifier = identifier.encode('utf-8', 'replace')
    if len(identifier) > MAX_IDENTIFIER_BYTES:
        identifier = identifier[:MAX_IDENTIFIER_BYTES]
    digest = hmac.new(key, identifier.strip().lower(), hashlib.sha256).digest()
    return digest[:PRINCIPAL_PSEUDONYM_BYTES].hex()


def new_key():
    """A fresh process-local key. Never written anywhere."""
    return secrets.token_bytes(32)


def identifier_of(payload):
    """The non-secret identifier in a cleartext command, or `b''`.

    `USER alice` yields `alice`. `PASS hunter2` yields nothing at all, because
    the argument of a secret-bearing command is not read.
    """
    if not isinstance(payload, bytes) or not payload:
        return b''
    head = payload[:256].lstrip()
    if head[:16].lower().startswith(_SECRET_COMMANDS):
        return b''
    match = _IDENTIFIER_COMMAND.match(head)
    return match.group(2).strip() if match else b''


def attempted(payload):
    """Whether this request is an authentication step at all.

    Broader than `identifier_of`: a `PASS` line is an authentication step whose
    argument is never read, and a request carrying an `Authorization` header is
    one whose value is never read either.
    """
    if not isinstance(payload, bytes) or not payload:
        return False
    head = payload[:4096]
    lower = head.lower()
    return bool(identifier_of(payload)
                or lower.lstrip()[:16].startswith(_SECRET_COMMANDS)
                or b'authorization:' in lower
                or b'proxy-authorization:' in lower)


def mechanism_of(payload):
    """A coarse category, from the shape of the request only. Values are not read."""
    if not isinstance(payload, bytes) or not payload:
        return MECHANISM_UNKNOWN
    lower = payload[:4096].lower()
    if b'authorization: bearer' in lower:
        return BEARER
    if b'authorization: basic' in lower:
        return BASIC
    if b'authorization: ' in lower and (b'signature' in lower or b'hmac' in lower):
        return SIGNATURE
    if lower.lstrip()[:16].startswith(_SECRET_COMMANDS) or identifier_of(payload):
        return PASSWORD
    return MECHANISM_UNKNOWN


def classify_response(payload):
    """The outcome the server reported, or `UNKNOWN`. §4, §7.

    `UNKNOWN` is returned whenever the reply is absent, encrypted, truncated or
    simply not recognised. It is the honest answer and the common one, and
    nothing downstream may treat it as a failure.
    """
    if not isinstance(payload, bytes) or not payload:
        return UNKNOWN
    head = payload[:512].lstrip().lower()
    for pattern, result in _FAILURE_PATTERNS:
        if re.search(pattern, head):
            return result
    for pattern, result in _SUCCESS_PATTERNS:
        if re.search(pattern, head):
            return result
    return UNKNOWN


def observe_request(payload, *, key, timestamp=0.0, site_id='', route_class=PUBLIC,
                    source_group='', credential_present=False):
    """Build the request half of an `AuthenticationEvent`.

    The result is deliberately left `UNKNOWN` when an attempt was made: the
    outcome belongs to the server's reply, and inventing it here is precisely
    the inference §4 forbids.
    """
    is_attempt = attempted(payload)
    return AuthenticationEvent(
        timestamp=float(timestamp), source_group=str(source_group), site_id=str(site_id),
        route_class=route_class if route_class in ROUTE_CLASSES else PUBLIC,
        auth_attempted=is_attempt,
        result=UNKNOWN if is_attempt else NOT_APPLICABLE,
        mechanism=mechanism_of(payload) if is_attempt else MECHANISM_UNKNOWN,
        credential_present=bool(credential_present) or is_attempt,
        principal=principal_pseudonym(key, identifier_of(payload)))


def resolve(event, response_payload):
    """Attach an observed outcome to an attempt. Returns a new event.

    Only an attempt can acquire an outcome, and only a recognised reply changes
    anything: an unrecognised or missing reply leaves the event `UNKNOWN`.
    """
    if not event.auth_attempted:
        return event
    outcome = classify_response(response_payload)
    if outcome == UNKNOWN:
        return event
    return AuthenticationEvent(
        timestamp=event.timestamp, source_group=event.source_group, site_id=event.site_id,
        route_class=event.route_class, auth_attempted=True, result=outcome,
        mechanism=event.mechanism, credential_present=event.credential_present,
        principal=event.principal)
