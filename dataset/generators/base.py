"""Behaviour plans: what one client does, when, and against which local address.

A plan is pure data. Rendering it into packets or events happens elsewhere, so the same
described behaviour can be replayed through the production packet parser or the production
correlation engine without restating the behaviour twice.

Payloads are tiny synthetic strings. No credential, secret, token, cookie or command line
from any real system exists in this package, and nothing here is sent anywhere.
"""
from dataclasses import dataclass, field
import random
from ..safety import Budget, SafetyLimits, validate_synthetic_address

SHAPES = ('syn_only', 'syn_reset', 'handshake', 'request', 'exchange', 'session',
          'retry_then_request', 'connect_only')

#: §3, §15. What the *server* says back when this contact carries an
#: authentication step. Empty means the ordinary banner, which is what every
#: pre-P15.4 contact gets and why those corpora still render byte for byte.
#:
#: A behaviour plan has to be able to state this, because until P15.4 the corpus
#: could only express credential *presence* — the quantity P15.3 proved says
#: nothing, and the one that blocked 21 of 22 legitimate batch-API sources. A
#: corpus that cannot express "the server said 530" could not have found that
#: defect and cannot demonstrate the fix. It is an outcome, not a label: the
#: scenario states what the server did, and the engine has to read it back out
#: of the rendered reply like any other observation.
AUTH_OUTCOMES = ('', 'success', 'failure', 'denied')

# Both label classes draw destinations and ports from these shared pools, so neither the
# address nor the port can act as a shortcut for the label.
SENSOR_ADDRESSES = tuple(f'198.51.100.{index}' for index in range(1, 9))
SERVICE_PORTS = (21, 22, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9090, 9100)

# Small bounded request bodies. `USER`/`AUTH` shapes trip the deterministic credential-like
# detector without containing anything that resembles a real secret; no password is written.
REQUESTS = {
    'http_get': b'GET /index.html HTTP/1.1\r\nHost: lab\r\nUser-Agent: lab-client\r\n\r\n',
    'http_head': b'HEAD /healthz HTTP/1.1\r\nHost: lab\r\n\r\n',
    'http_status': b'GET /status HTTP/1.1\r\nHost: lab\r\n\r\n',
    'http_metrics': b'GET /metrics HTTP/1.1\r\nHost: lab\r\n\r\n',
    'http_api': b'POST /api/v1/items HTTP/1.1\r\nHost: lab\r\nContent-Length: 2\r\n\r\n{}',
    'http_broken': b'GET /\n',
    'http_binary': b'GET \x00\x01\x02\x03 HTTP/9\r\n',
    'ssh_banner': b'SSH-2.0-lab-client\r\n',
    'ftp_feat': b'FEAT\r\n',
    'ftp_user': b'USER lab\r\n',
    'auth_probe': b'AUTH lab\r\n',
    'login_probe': b'LOGIN lab\r\n',
    'redis_probe': b'*1\r\n$4\r\nPING\r\n',
    'binary_probe': b'\x16\x03\x01\x00\x2c\x01\x00\x00\x28\x03\x03',
    'generic_probe': b'\x00\x00\x00\x18lab-probe\n',
    'empty': b'',
    # P15.4. Authenticated HTTP, because the behaviour P15.3 got wrong is
    # exactly this one: a machine client that presents a credential on every
    # single request and is completely legitimate. The header values below are
    # fixed literals that say what they are; nothing here is derived from a real
    # token, and no component ever reads the value — `decision/auth.py` reads
    # the scheme word and stops.
    'http_api_bearer': (b'POST /api/v1/items HTTP/1.1\r\nHost: lab\r\n'
                        b'Authorization: Bearer lab-placeholder-not-a-token\r\n'
                        b'Content-Length: 2\r\n\r\n{}'),
    'http_admin_basic': (b'GET /admin/status HTTP/1.1\r\nHost: lab\r\n'
                         b'Authorization: Basic bGFiOnBsYWNlaG9sZGVy\r\n\r\n'),
    'http_webhook_signature': (b'POST /hooks/payment HTTP/1.1\r\nHost: lab\r\n'
                               b'Authorization: Signature keyId="lab",signature="placeholder"\r\n'
                               b'Content-Length: 2\r\n\r\n{}'),
    'http_asset': b'GET /static/app.css HTTP/1.1\r\nHost: lab\r\nUser-Agent: lab-client\r\n\r\n',
}

#: Synthetic account names. Deliberately meaningless words with a `lab-` prefix:
#: principal *diversity* is the observation that matters, and it can be
#: exercised without any name that could belong to a person.
LAB_PRINCIPALS = ('alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf', 'hotel',
                  'india', 'juliet', 'kilo', 'lima', 'mike', 'november', 'oscar', 'papa',
                  'quebec', 'romeo', 'sierra', 'tango', 'uniform', 'victor', 'whiskey', 'xray')


def user_command(name):
    """A cleartext `USER` line for a synthetic principal.

    This is the only request shape that can produce principal diversity, and it
    is deliberate: `decision/auth.py` derives a pseudonym from the plainly
    non-secret identifier half of a cleartext command and refuses to derive one
    from an `Authorization` header, because that value is a live secret. So an
    HTTP family in this package contributes failure *counts* and no diversity,
    and a line-protocol family contributes both. The corpus has to be able to
    show that difference, or nothing downstream can be tested against it.
    """
    safe = ''.join(character for character in str(name) if character.isalnum() or character == '-')
    if not safe:
        raise ValueError('principal name is empty after sanitisation')
    return b'USER lab-' + safe[:32].encode('ascii') + b'\r\n'


@dataclass(frozen=True, slots=True)
class Contact:
    """One client-initiated conversation at a scenario-relative time."""
    time: float
    destination: str
    port: int
    shape: str = 'request'
    request: bytes = b''
    follow_ups: int = 0
    transport: str = 'tcp'
    # Event-mode only: what the decoy session observed. Ignored by the packet renderer.
    command: str = ''
    credential: bool = False
    anomaly: bool = False
    family: str = ''
    #: §3. The outcome the server reported for this contact's authentication
    #: step, one of `AUTH_OUTCOMES`. Rendered as a real reply line, never as a
    #: side-channel annotation: the parser reads it exactly as it would read a
    #: live `530 Login incorrect`.
    auth: str = ''

    def __post_init__(self):
        if self.shape not in SHAPES:
            raise ValueError('unknown contact shape')
        if self.auth not in AUTH_OUTCOMES:
            raise ValueError('unknown authentication outcome')
        if not 0 <= self.time <= 86400 or not 0 <= self.port <= 65535:
            raise ValueError('contact time or port out of range')
        if len(self.request) > 512 or not 0 <= self.follow_ups <= 16:
            raise ValueError('contact payload or follow-up count exceeds the bound')
        validate_synthetic_address(self.destination)


@dataclass(slots=True)
class Plan:
    """A named, seeded, bounded behaviour for one logical client."""
    scenario_id: str
    scenario_group: str
    label: str
    label_source: str
    label_confidence: str
    seed: str
    source: str
    contacts: list = field(default_factory=list)
    parameters: dict = field(default_factory=dict)
    limits: SafetyLimits = field(default_factory=SafetyLimits)
    kind: str = 'benign'
    ingestion: str = 'pcap'
    #: §41, §42. Which site this traffic belongs to, and what kind of site that
    #: is. Evaluation metadata and *only* that: both are listed in
    #: `dataset.schema.NEVER_MODEL_INPUT`, neither has a feature column, and a
    #: test asserts they cannot reach a model. They exist because P15.3 could
    #: not report a single per-profile number — `site_group` was `None` on every
    #: row of every corpus — and "the worst site" is precisely the number a
    #: false-block rate ought to be read against.
    site_group: str = ''
    profile_type: str = ''

    def __post_init__(self):
        validate_synthetic_address(self.source)
        budget = Budget(self.limits)
        for contact in self.contacts:
            budget.connection(contact.destination)
            budget.advance(contact.time)
            budget.packet(len(contact.request))
        self.parameters = dict(self.parameters, budget=budget.snapshot())

    @property
    def duration(self):
        return max((contact.time for contact in self.contacts), default=0.0)


def rng(seed):
    """One deterministic stream per (scenario, run). Same seed, same behaviour."""
    return random.Random(f'dataset-v1:{seed}')


def jitter(stream, base, spread=0.35):
    """Timing jitter on both classes, so no generator has a recognisable fixed spacing."""
    return max(0.001, base * stream.uniform(1 - spread, 1 + spread))


def pick_destination(stream, count=1):
    return stream.sample(SENSOR_ADDRESSES, k=min(count, len(SENSOR_ADDRESSES)))


def source_address(stream):
    """Documentation-range source. Never routable, never a real host."""
    return f'192.0.2.{stream.randrange(2, 250)}'
