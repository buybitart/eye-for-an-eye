"""Feature schema 2: one deterministic train/inference transformation.

### What schema 2 adds, and what it deliberately does not touch

P15.4 adds five authentication columns and changes **no existing column** — not
its name, ceiling, transform or meaning. `credentials_60s` still counts exactly
what it always counted. That restraint is load-bearing: the shipped ONNX
classifier was fitted on the schema-1 columns, and `project()` below hands it
those columns unchanged. Redefining one in place would leave a trained model
computing a plausible number from a quantity that no longer means what it saw in
training, which is the worst kind of silent failure available here.

So `credentials_60s` keeps its meaning and loses its authority. It measured
*credential presence*: it fires identically on a backup script's `USER alice`
and a brute-forcer's `USER admin`, and on every request of every authenticated
API client. At weight 3.0 that blocked 21 of 22 sources of a legitimate batch
client on the P15.3 benchmark. The fix was never a smaller weight — it was
measuring the right thing. From P15.4 it is descriptive telemetry and cannot
create `AUTH_BEHAVIOR` evidence on its own (§8).

### Reading data written before schema 2

`upgrade()` lifts a schema-1 vector by appending `None` for each new column.
That is not a convenience, it is the accurate value: a corpus captured before
the sensor watched authentication outcomes contains no observation of them, and
the availability half of the tensor says so. Filling zeros would assert that
nothing failed, which is a claim nobody made.
"""
from dataclasses import dataclass
import hashlib
import math
import struct
from ..correlation.engine import aggregate

SCHEMA_VERSION = 2
#: The schema the shipped classifier was fitted against. `project()` is the only
#: supported way to feed it, so adding a feature can never silently change what
#: a trained model is shown.
CLASSIFIER_SCHEMA_VERSION = 1
# name, raw ceiling, transform, units, window seconds
SPEC = (
    ('connections_10s', 512, 'log', 'observations', 10),
    ('connections_60s', 512, 'log', 'observations', 60),
    ('connections_900s', 512, 'log', 'observations', 900),
    ('ports_60s', 64, 'linear', 'ports', 60),
    ('ports_900s', 128, 'linear', 'ports', 900),
    ('destinations_60s', 32, 'linear', 'addresses counted, never identities', 60),
    ('families_60s', 4, 'linear', 'protocol families', 60),
    ('repetition_60s', 1, 'linear', 'fraction', 60),
    ('sequential_60s', 1, 'linear', 'fraction', 60),
    ('anomaly_60s', 1, 'linear', 'fraction', 60),
    ('credentials_60s', 20, 'linear', 'observations', 60),
    ('continuation_60s', 1, 'linear', 'fraction', 60),
    ('persistence_900s', 300, 'linear', 'seconds', 900),
    ('burst_10s', 1, 'linear', 'fraction of 60s attempts', 60),
    ('interarrival_mean_60s', 60, 'log', 'seconds', 60),
    ('interarrival_cv_60s', 4, 'linear', 'coefficient of variation', 60),
    ('deception_60s', 64, 'linear', 'observations', 60),
    ('previous_risk', 1, 'linear', 'decayed score', 0),
    # --- schema 2, P15.4. Authentication outcome, not credential presence. ---
    # Every one of these is `None` when the sensor could not observe the outcome
    # — an encrypted session, a truncated capture, an unrecognised protocol. A
    # source that never authenticated has no failure ratio; it does not have a
    # ratio of zero, and the availability flag is what carries the difference.
    ('auth_failures_60s', 20, 'linear', 'observed refusals', 60),
    ('auth_successes_60s', 64, 'log', 'observed successes', 60),
    ('auth_failure_ratio', 1, 'linear', 'fraction of observed attempts', 900),
    ('auth_principals_900s', 32, 'linear', 'distinct pseudonymous principals refused', 900),
    ('auth_failure_span_900s', 300, 'linear', 'seconds between first and last refusal', 900),
)
NAMES = tuple(item[0] for item in SPEC)
INPUT_ORDER = NAMES + tuple('available_' + name for name in NAMES)

#: The schema-1 column names, in their original order. Frozen as a literal
#: rather than sliced from `SPEC`, so a future reordering of `SPEC` cannot
#: silently change what the classifier is fed.
SCHEMA_1_NAMES = (
    'connections_10s', 'connections_60s', 'connections_900s', 'ports_60s',
    'ports_900s', 'destinations_60s', 'families_60s', 'repetition_60s',
    'sequential_60s', 'anomaly_60s', 'credentials_60s', 'continuation_60s',
    'persistence_900s', 'burst_10s', 'interarrival_mean_60s',
    'interarrival_cv_60s', 'deception_60s', 'previous_risk',
)
SCHEMA_1_INPUT_ORDER = SCHEMA_1_NAMES + tuple('available_' + n for n in SCHEMA_1_NAMES)
#: Columns added after schema 1, in schema order.
SCHEMA_2_ADDITIONS = tuple(name for name in NAMES if name not in SCHEMA_1_NAMES)

#: Groups of features that are *conditionally applicable*: absent as a block
#: when the behaviour they describe never occurred.
#:
#: This distinction exists because data-quality completeness counts what the
#: sensor failed to observe, and there is a difference between evidence that is
#: missing and evidence that does not apply. A source that never attempted to
#: authenticate has no authentication outcome to be missing — the five columns
#: are silent because there was nothing to say, not because the sensor dropped
#: something. Counting them as gaps would lower the data quality of every
#: ordinary visitor on the web, tightening a safety gate by accident and for no
#: reason anybody chose.
#:
#: The rule is all-or-nothing per group, which is what makes it honest in the
#: harder direction too: once *any* authentication has been observed, all five
#: count, so a session that authenticated behind TLS and left its outcome
#: unreadable is recorded as incomplete rather than quietly excused.
CONDITIONAL_GROUPS = {'authentication': SCHEMA_2_ADDITIONS}

#: True while the authentication columns are conditional as a block, which is
#: what makes "the ledger said nothing" and "nobody passed the ledger" produce
#: identical vectors. That is correct for data quality and it is why
#: `tests/test_p15_5_contracts.py` guards the call sites structurally instead of
#: behaviourally: there is no downstream observation that could tell them apart.
AUTH_COLUMNS_ARE_CONDITIONAL = 'authentication' in CONDITIONAL_GROUPS

#: Feature schemas this build can serve, and the exact input order each means.
#: An artifact is validated against the schema *it* declares rather than
#: whichever one the code has: a model fitted on schema 1 is still exactly
#: correct for the columns it knows, and `FeatureTransformer.project` is what
#: hands them over. A schema absent from this table is refused outright, so the
#: failure is "this build cannot serve that model" rather than a tensor of the
#: wrong width reaching inference.
MODEL_SCHEMAS = {1: SCHEMA_1_INPUT_ORDER, SCHEMA_VERSION: INPUT_ORDER}


def applicable_names(values):
    """Feature names whose absence would be a genuine gap, for this observation."""
    index = {name: position for position, name in enumerate(NAMES)}
    skip = set()
    for group in CONDITIONAL_GROUPS.values():
        if all(values[index[name]] is None for name in group):
            skip.update(group)
    return tuple(name for name in NAMES if name not in skip)


def completeness(values):
    """The fraction of applicable features actually observed. Never divides by zero."""
    index = {name: position for position, name in enumerate(NAMES)}
    names = applicable_names(values)
    if not names:
        return 0.0
    return sum(values[index[name]] is not None for name in names) / len(names)


@dataclass(frozen=True, slots=True)
class FeatureVector:
    values: tuple[float | None, ...]
    observation_seconds: float
    sample_count: int
    capped: bool = False
    loss_fraction: float | None = None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        if type(self.schema_version) is not int or self.schema_version != SCHEMA_VERSION or len(self.values) != len(SPEC):
            raise ValueError('feature schema/count mismatch')
        if type(self.values) is not tuple or type(self.capped) is not bool:
            raise ValueError('immutable feature tuple and boolean cap required')
        for value in (*self.values, self.observation_seconds, self.loss_fraction):
            if value is not None and (type(value) not in (int, float) or not math.isfinite(value) or value < 0):
                raise ValueError('features must be finite nonnegative numbers or explicit missing values')
        if type(self.sample_count) is not int or not 0 <= self.sample_count <= 512 or self.observation_seconds > 900:
            raise ValueError('feature evidence bounds')
        if self.loss_fraction is not None and self.loss_fraction > 1:
            raise ValueError('invalid loss fraction')


def upgrade(values):
    """Lift a schema-1 value tuple to schema 2 by appending explicit unknowns.

    Every corpus and fixture written before P15.4 predates the sensor watching
    authentication outcomes, so it contains no observation of them. `None` is
    the accurate value and the availability flag carries it into the model.
    Zeros would assert that nothing failed, which is a claim no capture made.
    """
    values = tuple(values)
    if len(values) == len(SPEC):
        return values
    if len(values) != len(SCHEMA_1_NAMES):
        raise ValueError(f'cannot upgrade a vector of {len(values)} values')
    return values + (None,) * len(SCHEMA_2_ADDITIONS)


class FeatureTransformer:
    @staticmethod
    def transform(vector):
        if not isinstance(vector, FeatureVector):
            raise ValueError('FeatureVector required')
        output = []
        for value, (_, ceiling, transform, _, _) in zip(vector.values, SPEC, strict=True):
            bounded = min(value, ceiling) if value is not None else 0.0
            output.append(math.log1p(bounded) / math.log1p(ceiling) if transform == 'log' else bounded / ceiling)
        # Round once to the actual float32 contract, without requiring numpy.
        values = output + [float(value is not None) for value in vector.values]
        return struct.unpack('<' + 'f' * len(values), struct.pack('<' + 'f' * len(values), *values))

    @staticmethod
    def fingerprint(vector):
        tensor = FeatureTransformer.transform(vector)
        return hashlib.sha256(struct.pack('<I' + 'f' * len(tensor), SCHEMA_VERSION, *tensor)).hexdigest()

    @staticmethod
    def project(vector, schema=CLASSIFIER_SCHEMA_VERSION):
        """The tensor a model fitted on an older schema expects. §32, §56.

        A model sees the columns it was trained on, in the order it was trained
        on them, and nothing else. This is what lets the feature schema grow
        without invalidating an exported artifact — and, more importantly, what
        stops a grown schema from quietly feeding a trained model a tensor of a
        different width or a column of a different meaning.

        It is only sound because schema 2 added columns and redefined none. A
        future schema that changes what an existing column *means* may not use
        this path: it must retrain, because the projection would then be a lie
        with the right number of floats in it.

        **The target order is resolved from `MODEL_SCHEMAS`, never from a
        literal.** This read `if schema != 1: raise` until P15.5, which was true
        while schema 1 was the only older one and would have become the P15.4
        defect again at schema 3: every model fitted on schema 2 abruptly
        unservable, the classifier silently absent, and the deterministic path
        carrying on with no symptom at all. Selecting columns by name from the
        declared order means a schema added to the table is projectable the
        moment it is added, with no edit here (§3, §35).
        """
        if schema == SCHEMA_VERSION:
            return FeatureTransformer.transform(vector)
        order = MODEL_SCHEMAS.get(schema)
        if order is None:
            raise ValueError(f'no projection to feature schema {schema}')
        full = FeatureTransformer.transform(vector)
        index = {name: position for position, name in enumerate(INPUT_ORDER)}
        missing = [name for name in order if name not in index]
        if missing:
            # A column the older schema declares and this build does not compute.
            # Refusing is the only honest answer: the alternative is a zero in a
            # slot the model was told means something, which is the failure this
            # method exists to prevent rather than a milder form of it.
            raise ValueError(f'feature schema {schema} names columns this build '
                             f'does not compute: {sorted(missing)[:4]}')
        return tuple(full[index[name]] for name in order)


def from_samples(samples, *, now, horizon=900, previous_risk=0.0, capped=False,
                 loss_fraction=None, auth=None):
    """Reuse bounded P2 Sample objects. Counts are retained observations, not true flows.

    `auth` is the source's authentication history from
    `correlation.auth_state.AuthLedger.features`, or `None` when the caller has
    no ledger. `None` and "no attempts" produce the same thing here — unknown,
    not zero — because in both cases nothing was observed.
    """
    active = sorted((s for s in samples if now - min(900, horizon) <= s.time <= now), key=lambda s: (s.time, s.event_id))
    if not active:
        raise ValueError('no current samples')
    recent = [s for s in active if s.time >= now - 60]
    if not recent:
        raise ValueError('no recent samples')
    long, short = aggregate(active, 900), aggregate(recent, 60)
    ten = sum(s.attempt for s in recent if s.time >= now - 10)
    payload = [s for s in recent if s.payload_known]
    count = len(recent)
    vals = (ten, short['connection_attempts'], long['connection_attempts'] if horizon >= 900 else None,
        short['unique_destination_ports'], long['unique_destination_ports'] if horizon >= 900 else None,
        short['unique_destinations'], short['probe_family_diversity'] if payload else None,
        short['max_probe_repetition'] / count if payload else None,
        short['sequential_port_fraction'] if short['connection_attempts'] >= 2 else None,
        short['protocol_anomalies'] / count if payload else None,
        short['credential_attempts'] if payload else None,
        short['response_continuations'] / count if payload else None,
        long['observed_span_seconds'] if horizon >= 900 else None,
        ten / short['connection_attempts'] if short['connection_attempts'] else None,
        short['inter_arrival_mean_seconds'], short['inter_arrival_cv'],
        sum(s.deception for s in recent), previous_risk,
        # Schema 2. A ledger that saw no attempt yields `None` throughout, which
        # is the honest answer: nothing was observed, so nothing is asserted.
        *_auth_values(auth))
    return FeatureVector(tuple(vals), long['observed_span_seconds'], len(active), capped, loss_fraction)


def _auth_values(auth):
    """The five schema-2 columns, in schema order."""
    if not auth:
        return (None, None, None, None, None)
    return (auth.get('auth_failures'), auth.get('auth_successes'),
            auth.get('auth_failure_ratio'), auth.get('failed_principals'),
            auth.get('auth_failure_span_seconds'))
