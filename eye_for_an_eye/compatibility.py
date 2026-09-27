"""One place that answers "can this build serve that version". P15.5 §2, §3.

### Why this module exists

P15.4's locked benchmark blocked nothing because of this line:

    registry.record('feature_schema_compatible', inputs.feature_schema_version == 1, ...)

The feature schema had been 2 since earlier in the same cycle. Every window of
every source failed the assumption, `ASSUMPTION_FAILED` refused every block, and
a defender that agreed on every other gate could not act at all.

What makes it a design problem rather than a typo is that it was the **second**
occurrence. `decision.policy.usable_ml` carried the identical literal, was found
when schema 2 landed, and was fixed in place — and its twin in
`autonomy/authority.py` was missed, because there was no list of the places that
had to change together. A repository where "is this version acceptable" is
answered by whatever expression each call site happened to write will keep
producing that bug, and `tests/test_p15_4_schema_pins.py` can only catch the
spellings it knows to grep for.

So the rule this module establishes is narrow and mechanical: **a version is
never compared to a number at a call site.** A consumer asks a contract, and the
contract is the only thing that knows the answer.

### What a contract is, and what it is not

A `SchemaContract` answers one question — *may this build handle a value that
declares version N* — and carries the reason in the same object, because the
answer without the reason is how the previous pin survived review. It is
deliberately not a migration framework: it does not convert anything, it does
not decide what to do on a mismatch, and it holds no state. It says yes or no and
explains which.

Contracts resolve their versions lazily, by importing the module that owns the
constant at first use. That is not an optimisation. It is what keeps this module
free of transcribed numbers: the contract for the feature schema *is*
`decision.features.MODEL_SCHEMAS`, read from the code in force, so the contract
and the system cannot disagree. A registry of literals maintained beside the real
constants would be one more thing to forget to update — which is the failure this
module was written to end, not to reproduce in a new location.

### The three shapes, and why they are named

`REFUSE`, `PROJECT` and `MIGRATE` say what a *correct* consumer does with an
older value it is allowed to handle. They are recorded because "supported"
without them is ambiguous in the dangerous direction: a build that can *read* a
schema-1 model and a build that can *feed* one are different claims, and the
second is what `FeatureTransformer.project` provides. A contract marked `REFUSE`
that quietly accepted an old version would be the P15.3 defect's cousin —
plausible numbers computed from the wrong columns.
"""
from dataclasses import dataclass, field
from typing import Callable

#: An older version is not accepted at all. The value is rejected, and whatever
#: depends on it degrades rather than guesses.
REFUSE = 'refuse'
#: An older version is accepted and the value is transformed to what it declared
#: — the feature tensor being the case that matters, where `project` hands a
#: model exactly the columns it was fitted on.
PROJECT = 'project'
#: An older version is accepted and upgraded in place, once, on read.
MIGRATE = 'migrate'

SHAPES = (REFUSE, PROJECT, MIGRATE)


class IncompatibleSchema(ValueError):
    """A version this build must not act on. Raised instead of guessing.

    A distinct type because the recovery differs from an ordinary bad value: a
    caller that catches this knows the input was well formed and simply newer or
    older than it can serve, which is a degrade-and-report condition rather than
    a parse failure.
    """

    def __init__(self, contract, version, detail=''):
        self.contract = contract
        self.version = version
        super().__init__(
            f'{contract}: version {version!r} is not one this build can serve'
            + (f' ({detail})' if detail else ''))


@dataclass(frozen=True, slots=True)
class SchemaContract:
    """Which versions of one boundary this build may handle, and why.

    `current` is what this build *produces*. `servable` is what it may *accept*,
    which is a superset whenever older values remain readable. Keeping the two
    apart is the whole point: the P15.4 pin conflated them, and every consumer
    that asked "is it the current one" instead of "is it one I can serve" was
    wrong the moment a column was appended.
    """

    name: str
    #: What crosses this boundary, in one line. Present so that `explain()` is
    #: usable in a decision record without a reader consulting the source.
    carries: str
    shape: str
    #: Imports and returns `(current, servable_tuple)`. Called once, cached.
    resolver: Callable[[], tuple] = field(repr=False)

    def __post_init__(self):
        if self.shape not in SHAPES:
            raise ValueError(f'{self.name}: shape must be one of {SHAPES}')

    def _resolved(self):
        cached = _CACHE.get(self.name)
        if cached is None:
            current, servable = self.resolver()
            servable = tuple(sorted(set(servable) | {current}))
            if current not in servable:
                raise ValueError(f'{self.name}: current version is not servable')
            cached = _CACHE[self.name] = (current, servable)
        return cached

    @property
    def current(self):
        """The version this build writes."""
        return self._resolved()[0]

    @property
    def servable(self):
        """Every version this build may accept, current included."""
        return self._resolved()[1]

    def supports(self, version):
        """May this build act on a value declaring `version`?

        Typed strictly on purpose. `True` is an `int` in Python, and a contract
        that answered yes to `supports(True)` would be a compatibility check that
        accepts a boolean as version 1.
        """
        return type(version) is int and version in self.servable

    def require(self, version, *, detail=''):
        """`version` if it is servable, otherwise `IncompatibleSchema`.

        For the call sites where the alternative to acting is refusing, rather
        than the ones that choose a degraded path from a boolean.
        """
        if not self.supports(version):
            raise IncompatibleSchema(self.name, version, detail)
        return version

    def explain(self):
        current, servable = self._resolved()
        return {'schema': self.name, 'carries': self.carries, 'shape': self.shape,
                'current': current, 'servable': list(servable)}


#: Contract name -> the `(current, servable)` pair its resolver produced, cached
#: because a resolver imports a module to read one constant. Annotated to the
#: same precision as `SchemaContract.resolver` above and no further: the value is
#: provably a 2-tuple, and the resolver's own annotation does not establish what
#: is inside it, so stating element types here would assert more than the code
#: does.
_CACHE: dict[str, tuple] = {}


def _feature_schema():
    from .decision.features import MODEL_SCHEMAS, SCHEMA_VERSION
    return SCHEMA_VERSION, tuple(MODEL_SCHEMAS)


def _event_schema():
    from .events import SCHEMA_VERSION
    # Versions 1 and 2 are migrated on read by `events.from_record`; the branches
    # are there, so the contract says so rather than leaving it to the reader.
    return SCHEMA_VERSION, (1, 2, SCHEMA_VERSION)


def _auth_event_schema():
    from .decision.auth import AUTH_SCHEMA_VERSION
    return AUTH_SCHEMA_VERSION, (AUTH_SCHEMA_VERSION,)


def _auth_state_schema():
    from .correlation.auth_state import AUTH_STATE_SCHEMA_VERSION
    return AUTH_STATE_SCHEMA_VERSION, (AUTH_STATE_SCHEMA_VERSION,)


def _maturity_schema():
    from .autonomy.maturity import MATURITY_SCHEMA_VERSION
    return MATURITY_SCHEMA_VERSION, (MATURITY_SCHEMA_VERSION,)


def _decision_record_schema():
    from .autonomy.record import DECISION_RECORD_VERSION
    return DECISION_RECORD_VERSION, (DECISION_RECORD_VERSION,)


def _site_profile_schema():
    from .sites.profile import SITE_PROFILE_SCHEMA_VERSION
    return SITE_PROFILE_SCHEMA_VERSION, (SITE_PROFILE_SCHEMA_VERSION,)


def _enforcement_request_schema():
    from .security.enforcement import ENFORCEMENT_REQUEST_VERSION
    return ENFORCEMENT_REQUEST_VERSION, (ENFORCEMENT_REQUEST_VERSION,)


def _calibration_schema():
    from .decision.calibration import CALIBRATION_SCHEMA_VERSION
    return CALIBRATION_SCHEMA_VERSION, (CALIBRATION_SCHEMA_VERSION,)


def _score_contract():
    from .decision.scores import SCORE_CONTRACT_VERSION
    return SCORE_CONTRACT_VERSION, (SCORE_CONTRACT_VERSION,)


def _deception_catalogue():
    from .deception.profiles import CATALOGUE_VERSION
    return CATALOGUE_VERSION, (CATALOGUE_VERSION,)


def _model_manifest():
    from .decision.onnx_model import MANIFEST_VERSION
    return MANIFEST_VERSION, (MANIFEST_VERSION,)


#: The feature tensor. The one where a silent mismatch would be worst, because a
#: model fed the wrong columns runs and returns a plausible number.
FEATURE_SCHEMA = SchemaContract(
    'feature_schema',
    'the feature tensor a risk model is fitted on and fed',
    PROJECT, _feature_schema)

#: `NetworkEvent` as stored in SQLite.
EVENT_SCHEMA = SchemaContract(
    'event_schema', 'a stored NetworkEvent', MIGRATE, _event_schema)

#: A normalised authentication outcome. Its five result states are a closed
#: vocabulary; adding one is a shape change, which is why nothing older is
#: servable.
AUTH_EVENT_SCHEMA = SchemaContract(
    'auth_event_schema', 'a normalised AuthenticationEvent', REFUSE, _auth_event_schema)

#: The bounded per-source authentication history behind the schema-2 columns.
AUTH_STATE_SCHEMA = SchemaContract(
    'auth_state_schema', 'the per-source AuthLedger summary', REFUSE, _auth_state_schema)

#: Which paths to maturity exist and what each requires. "Was there enough
#: evidence to act" is the question every block is defended by, so a record
#: naming an unknown version is refused rather than read against today's rules.
MATURITY_SCHEMA = SchemaContract(
    'maturity_schema', 'an evidence-maturity policy', REFUSE, _maturity_schema)

#: The answer to "why was this source blocked".
DECISION_RECORD_SCHEMA = SchemaContract(
    'decision_record_schema', 'an AutonomousDecisionRecord', REFUSE, _decision_record_schema)

SITE_PROFILE_SCHEMA = SchemaContract(
    'site_profile_schema', 'a site profile', REFUSE, _site_profile_schema)

#: The value that crosses the privilege boundary. The privileged helper parses
#: this and nothing else.
ENFORCEMENT_REQUEST_SCHEMA = SchemaContract(
    'enforcement_request_schema', 'a validated EnforcementRequest', REFUSE,
    _enforcement_request_schema)

#: The calibrator artifact: method, model binding, knots, conservative knots.
CALIBRATION_SCHEMA = SchemaContract(
    'calibration_schema', 'a calibrator artifact on disk', REFUSE, _calibration_schema)

#: Which numbers on the decision path are probabilities and which are not.
SCORE_CONTRACT = SchemaContract(
    'score_contract', 'the units of every score on the decision path', REFUSE, _score_contract)

#: Which deception profile maps to which port. Changing it changes what the
#: machine looks like from outside, deliberately.
DECEPTION_CATALOGUE = SchemaContract(
    'deception_catalogue', 'the port-to-deception-profile map', REFUSE, _deception_catalogue)

#: The manifest beside an exported model.
MODEL_MANIFEST = SchemaContract(
    'model_manifest', 'the manifest beside an exported model artifact', REFUSE, _model_manifest)

#: Every contract, by name. `tests/test_p15_5_compatibility.py` walks this, so a
#: contract added without a test is not possible.
CONTRACTS = {contract.name: contract for contract in (
    FEATURE_SCHEMA, EVENT_SCHEMA, AUTH_EVENT_SCHEMA, AUTH_STATE_SCHEMA,
    MATURITY_SCHEMA, DECISION_RECORD_SCHEMA, SITE_PROFILE_SCHEMA,
    ENFORCEMENT_REQUEST_SCHEMA, CALIBRATION_SCHEMA, SCORE_CONTRACT,
    DECEPTION_CATALOGUE, MODEL_MANIFEST)}


def explain():
    """Every boundary this build has, and what it will accept at each."""
    return {'contracts': [CONTRACTS[name].explain() for name in sorted(CONTRACTS)]}
