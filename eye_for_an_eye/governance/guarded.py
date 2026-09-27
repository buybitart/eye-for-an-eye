"""Guarded activation: a promoted model earns its authority instead of being given it.

Offline evaluation and shadow observation between them cover a great deal and
cannot cover everything. Production has clients nobody simulated, traffic shapes
nobody generated, and the specific people who visit this specific site. A model
that looked correct on every corpus available can still be wrong about them.

Guarded activation is the answer to that, and it is cheap: the newly promoted
model starts contributing to decisions immediately — so it is really being
tested — but with a ceiling on what it may cause **on its own**. In the first
stage that ceiling is WATCH, which means a model that has just arrived cannot
challenge, slow down or block anybody no matter how confident it is.

Two distinctions do the work here.

**A ceiling applies to the model's own contribution, not to the system.** §38:
deterministic multi-signal policy is unchanged. If the mathematical engine and
the existing evidence already justify a block, that block still happens. What the
ceiling prevents is the *new model alone* creating an action it has not yet
earned the right to create.

**Stages advance on observations, never on the clock.** §41: twenty-four hours on
a site that saw eleven requests is not evidence. A stage that advanced on time
alone would hand full authority to a model fastest on exactly the quiet sites
where a regression is hardest to see, and where the few affected visitors are
least likely to be able to report it.
"""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile

from .policy import ACTION_LADDER

GUARDED_STATE_SCHEMA_VERSION = 1

#: What `evaluate_advance` recommends.
ADVANCE = 'ADVANCE'
CONTINUE = 'CONTINUE_GUARDED_OBSERVATION'
COMPLETE = 'COMPLETE_ACTIVATION'
HOLD = 'HOLD_AND_REVIEW'

MAX_BYTES = 262_144


class GuardedError(ValueError):
    """The guarded state cannot be read or is not consistent."""


def _now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def clamp(action, ceiling):
    """The weaker of `action` and `ceiling`. Unknown actions clamp to the ceiling.

    Deliberately total: an action name this build does not recognise resolves to
    the ceiling rather than raising, because the caller is a live decision path
    and an exception there would be an outage caused by a safety mechanism.
    """
    if ceiling not in ACTION_LADDER:
        return action
    if action not in ACTION_LADDER:
        return ceiling
    return action if ACTION_LADDER.index(action) <= ACTION_LADDER.index(ceiling) else ceiling


@dataclass
class GuardedObservation:
    """What has been seen since this model was promoted.

    Counters only, bounded by construction: nothing here grows with traffic.
    """

    feature_vectors: int = 0
    source_groups: int = 0
    trusted_outcomes: int = 0
    inference_failures: int = 0
    large_disagreements: int = 0
    scored_by_both: int = 0
    #: Would-be actions of the guarded model and of the previous one, on the
    #: same feature vectors (§42, §53).
    guarded_actions: dict = field(default_factory=dict)
    reference_actions: dict = field(default_factory=dict)
    #: Actions the ceiling actually prevented. An operator wants to know how
    #: often the guard is doing something, not only that it exists.
    ceiling_applied: int = 0
    reviewed_false_blocks: int = 0

    @property
    def disagreement_ratio(self):
        if not self.scored_by_both:
            return None
        return self.large_disagreements / self.scored_by_both

    def record(self, *, guarded_action=None, reference_action=None,
               disagreement=False, ceiling_applied=False, failure=False):
        self.feature_vectors += 1
        if guarded_action:
            self.guarded_actions[guarded_action] = self.guarded_actions.get(guarded_action, 0) + 1
        if reference_action:
            self.reference_actions[reference_action] = self.reference_actions.get(reference_action, 0) + 1
        if guarded_action and reference_action:
            self.scored_by_both += 1
        if disagreement:
            self.large_disagreements += 1
        if ceiling_applied:
            self.ceiling_applied += 1
        if failure:
            self.inference_failures += 1

    def explain(self):
        body = asdict(self)
        body['disagreement_ratio'] = self.disagreement_ratio
        return body


@dataclass
class GuardedState:
    """Which model is guarded, at what stage, and what it has seen.

    Durable, because a restart must not lose it and must not be read as progress
    (§66, §137). Written by atomic rename, like the journal.
    """

    scope: str = ''
    version: str = ''
    previous_version: str = ''
    stage: str = ''
    #: Wall-clock, for the record and for reporting.
    entered_at: str = ''
    #: Monotonic seconds accumulated in this stage. Kept separately from the
    #: wall clock so that a system clock jump cannot complete a stage (§67,
    #: §138); a restart contributes nothing, which is correct.
    observed_seconds: float = 0.0
    observation: GuardedObservation = field(default_factory=GuardedObservation)
    frozen: bool = False
    freeze_reason: str = ''

    @property
    def active(self):
        return bool(self.version and self.stage)

    def explain(self):
        return {'guarded_state_schema_version': GUARDED_STATE_SCHEMA_VERSION,
                'scope': self.scope, 'version': self.version,
                'previous_version': self.previous_version, 'stage': self.stage,
                'entered_at': self.entered_at,
                'observed_seconds': self.observed_seconds,
                'frozen': self.frozen, 'freeze_reason': self.freeze_reason,
                'observation': self.observation.explain()}


def ceiling_for(state, policy):
    """The strongest action the guarded model may cause on its own.

    A model that is not guarded has no extra ceiling — it is subject to whatever
    PolicyGuard allows, like any other model. The most restrictive answer is
    returned for an unrecognised stage, because an unknown stage is a bug and a
    bug in this function should fail towards doing less.
    """
    if state is None or not state.active:
        return None
    stage = policy.stage(state.stage)
    if stage is None:
        return ACTION_LADDER[0]
    return stage.action_ceiling


def evaluate_advance(state, policy, *, now_seconds=None):
    """Whether this guarded model has earned the next rung. Returns (verdict, reasons).

    The verdict is advisory in the same sense the assessment is: it is computed
    here and acted on elsewhere, so that the rule and the effect can be reviewed
    separately.
    """
    if state is None or not state.active:
        return CONTINUE, ('there is no guarded model',)
    if state.frozen:
        return HOLD, (state.freeze_reason or 'guarded advancement is frozen',)

    stage = policy.stage(state.stage)
    if stage is None:
        return HOLD, (f'{state.stage!r} is not a stage in the current policy; the '
                      'policy changed under a guarded model and a person should '
                      'decide what that means',)

    observation = state.observation
    elapsed = state.observed_seconds if now_seconds is None else now_seconds
    reasons, blocked = [], False

    if observation.inference_failures > stage.maximum_inference_failures:
        return HOLD, (f'{observation.inference_failures} inference failures during '
                      f'{stage.name}; this is a technical problem, not a slow start',)

    ratio = observation.disagreement_ratio
    if ratio is not None and ratio > stage.maximum_disagreement_ratio:
        return HOLD, (f'the guarded model disagrees materially with the previous one '
                      f'on {ratio:.1%} of scored windows, above the {stage.maximum_disagreement_ratio:.0%} '
                      'this stage allows; a person should look before it gets more '
                      'authority',)

    for name, seen, needed in (
            ('observation time', elapsed, stage.minimum_seconds),
            ('feature vectors', observation.feature_vectors, stage.minimum_feature_vectors),
            ('source groups', observation.source_groups, stage.minimum_source_groups),
            ('trusted reviewed outcomes', observation.trusted_outcomes,
             stage.minimum_trusted_outcomes)):
        if seen < needed:
            blocked = True
            reasons.append(f'{seen:g} of {needed:g} {name}')

    if blocked:
        return CONTINUE, tuple(reasons)

    return (ADVANCE if policy.stage_after(stage.name) else COMPLETE,
            (f'{stage.name} requirements met on observations, not on elapsed time '
             'alone',))


class GuardedStore:
    """Per-scope guarded state on disk. One small file, atomic writes."""

    def __init__(self, root):
        self.root = Path(root)

    def _path(self, scope):
        safe = scope.replace(':', '__').replace('/', '_').replace('\\', '_')
        return self.root / f'guarded-{safe}.json'

    def load(self, scope):
        path = self._path(scope)
        if not path.is_file():
            return None
        try:
            if path.stat().st_size > MAX_BYTES:
                raise GuardedError('guarded state file is larger than its bound')
            body = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError) as exc:
            raise GuardedError(f'guarded state is unreadable: {exc}') from exc
        if body.get('guarded_state_schema_version') != GUARDED_STATE_SCHEMA_VERSION:
            raise GuardedError('unsupported guarded state version')
        observation = GuardedObservation(
            **{key: value for key, value in (body.get('observation') or {}).items()
               if key in GuardedObservation.__dataclass_fields__})
        return GuardedState(
            scope=body.get('scope', scope), version=body.get('version', ''),
            previous_version=body.get('previous_version', ''),
            stage=body.get('stage', ''), entered_at=body.get('entered_at', ''),
            observed_seconds=float(body.get('observed_seconds', 0.0)),
            observation=observation, frozen=bool(body.get('frozen', False)),
            freeze_reason=body.get('freeze_reason', ''))

    def save(self, state):
        path = self._path(state.scope)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(state.explain(), indent=2).encode('utf-8')
        handle, temporary = tempfile.mkstemp(dir=str(path.parent), prefix='.guarded-')
        try:
            with os.fdopen(handle, 'wb') as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
        return state

    def clear(self, scope):
        self._path(scope).unlink(missing_ok=True)

    def enter(self, *, scope, version, previous_version, stage, now=None):
        """Begin the first guarded stage for a newly activated model."""
        state = GuardedState(scope=scope, version=version,
                             previous_version=previous_version, stage=stage,
                             entered_at=now or _now())
        return self.save(state)

    def advance_to(self, state, stage):
        """Move to the next rung, resetting the per-stage observation counters.

        The counters reset because each rung asks for its own evidence: carrying
        stage 1's observations into stage 2 would let a model buy the second rung
        with the traffic it already used to buy the first.
        """
        state.stage = stage
        state.entered_at = _now()
        state.observed_seconds = 0.0
        state.observation = GuardedObservation()
        return self.save(state)
