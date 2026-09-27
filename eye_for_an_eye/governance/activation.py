"""The promotion transaction: ten steps, any of which may be the last one.

Activation is the only part of this package that changes anything, so it is
written on the assumption that the process will die at the worst possible moment.
Every step either changes nothing or is recorded before it is attempted, and the
order is chosen so that the irreversible step happens as late as possible and
after everything that could have refused has already refused.

    1. lock the scope                    one transition per scope
    2. verify the assessment             eligible, and not stale
    3. verify the candidate              on disk, hashed, scoped, loadable
    4. verify the rollback target        no way back, no way forward
    5. open the journal                  intent, before anything is touched
    6. load and warm up the candidate    in a separate process
    7. switch the pointer atomically     the one irreversible step
    8. verify inference after the switch
    9. enter the first guarded stage
    10. close the journal and release the lock

Step 6 before step 7 is the whole design (§148). Switching the pointer and then
discovering the model does not load is how a promotion becomes an outage; loading
first costs a few seconds and removes that case entirely.

If any step before 7 fails, nothing has changed and the journal entry is
discarded. If step 8 or 9 fails, the pointer is put back and the candidate is
quarantined — a model that activated and then could not answer is not a model to
try again unchanged.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import errno
import os
from pathlib import Path

from . import journal as journal_module
from .assessment import ELIGIBLE
from .guarded import GuardedStore
from .journal import ACTIVATING, COMMITTED, GUARDED, JournalError, STAGED

ACTIVATION_SCHEMA_VERSION = 1


class ActivationError(RuntimeError):
    """A promotion that must not proceed. Nothing has been left half-done."""


class ScopeLocked(ActivationError):
    """Another transition for this scope is already in progress."""


def _now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


class ScopeLock:
    """An exclusive lock file for one scope, held for one transition.

    `O_CREAT | O_EXCL` is the whole mechanism: the filesystem decides who wins,
    and a process that crashes leaves a stale file that `force_release` can clear
    once an operator has looked. A lock that expired on its own would defeat the
    purpose — the case it protects against is precisely the one where something
    went wrong and nobody knows what yet.
    """

    def __init__(self, root, scope):
        safe = str(scope).replace(':', '__').replace('/', '_').replace('\\', '_')
        self.path = Path(root) / f'.promoting-{safe}.lock'
        self.held = False

    def acquire(self, *, owner=''):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            handle = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                raise ScopeLocked(
                    f'another promotion holds {self.path.name}; one transition per '
                    'scope at a time. If no promotion is running, an earlier one '
                    'was interrupted and an operator should clear it') from exc
            raise
        with os.fdopen(handle, 'w') as stream:
            stream.write(f'{os.getpid()} {owner} {_now()}\n')
        self.held = True
        return self

    def release(self):
        if self.held:
            self.path.unlink(missing_ok=True)
            self.held = False

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *_):
        self.release()
        return False


@dataclass
class ActivationResult:
    """What happened, in enough detail to explain it afterwards."""

    scope: str
    candidate_version: str
    activated: bool
    stage: str = ''
    rollback_target: str = ''
    reasons: tuple = field(default_factory=tuple)
    quarantined: bool = False

    def explain(self):
        return {'activation_schema_version': ACTIVATION_SCHEMA_VERSION,
                'scope': self.scope, 'candidate': self.candidate_version,
                'activated': self.activated, 'guarded_stage': self.stage,
                'rollback_target': self.rollback_target,
                'quarantined': self.quarantined, 'reasons': list(self.reasons)}


class PromotionActivator:
    """Performs the transaction. Accepts only an ELIGIBLE, current assessment.

    The activator does not judge. It re-checks the things that could have changed
    since the assessment was taken — the artifact is still there, the rollback
    target is still there, the policy has not moved — and otherwise takes the
    record's word for the verdict, because the verdict is the governance engine's
    job and doing it twice in two places is how the two come to disagree.
    """

    def __init__(self, *, root, policy, journal=None, guarded=None):
        self.root = Path(root)
        self.policy = policy
        self.journal = journal or journal_module.PromotionJournal(
            self.root / 'promotion-journal.json')
        self.guarded = guarded or GuardedStore(self.root)

    # --- the transaction --------------------------------------------------

    def promote(self, *, assessment, registry, warmup, scope=None, reason=''):
        """Activate an eligible candidate into its first guarded stage.

        `warmup` is a callable taking the resolved model paths and returning True
        when the model loaded and answered a synthetic feature vector. It is
        injected rather than imported so that this module stays free of the
        inference machinery, and so a test can exercise every failure path
        without an ONNX file.
        """
        scope = scope or assessment.scope
        reasons = []

        # 2. The verdict, and whether it still means anything.
        if assessment.decision != ELIGIBLE:
            raise ActivationError(
                f'{assessment.candidate_version} is {assessment.decision}, not '
                f'{ELIGIBLE}; activation accepts only an eligible assessment')
        if assessment.is_stale_under(self.policy):
            raise ActivationError(
                'the assessment was reached under a different governance policy; '
                'a policy change never retroactively authorises a promotion. '
                'Re-assess the candidate under the current policy')
        if assessment.scope != scope:
            raise ActivationError(
                f'the assessment is for {assessment.scope} and activation was asked '
                f'for {scope}; a promotion never has ambiguous scope')

        version = assessment.candidate_version

        # 1. The lock. Taken after the cheap refusals so that a bad request does
        #    not leave a lock file behind for an operator to clear.
        lock = ScopeLock(self.root, scope).acquire(owner=version)
        try:
            # 3. The candidate, as it is on disk right now.
            resolved = registry.resolve('CANDIDATE')
            if not resolved or resolved.get('version') != version:
                raise ActivationError(
                    f'{version} is no longer the registered candidate for {scope}')

            # 4. The way back. §58.
            state = registry.state
            rollback_target = state.active or ''
            if not rollback_target:
                raise ActivationError(
                    'there is no active model to fall back to, so this promotion '
                    'would not be reversible; automatic promotion requires a '
                    'rollback target')
            if not (Path(registry.version_path(rollback_target)) / 'classifier.onnx').is_file():
                raise ActivationError(
                    f'the rollback target {rollback_target} is not on disk; a '
                    'promotion whose fallback is missing is not reversible')

            # 5. Intent, before anything is touched.
            self.journal.open(scope=scope, candidate_version=version,
                              rollback_target=rollback_target,
                              assessment_id=assessment.assessment_id,
                              policy_digest=assessment.policy_digest,
                              reason=reason)
            self.journal.advance(scope, STAGED)

            # 6. Load and warm up before the pointer moves. §148, §149.
            try:
                warm = bool(warmup(resolved))
            except Exception as exc:
                warm = False
                reasons.append(f'warmup raised {type(exc).__name__}')
            if not warm:
                self.journal.advance(scope, journal_module.ROLLED_BACK,
                                     reason='warmup failed before activation')
                reasons.append('the candidate did not load and answer a synthetic '
                               'feature vector; the active model was never changed')
                return ActivationResult(scope=scope, candidate_version=version,
                                        activated=False,
                                        rollback_target=rollback_target,
                                        reasons=tuple(reasons), quarantined=True)

            # 7. The one irreversible step.
            self.journal.advance(scope, ACTIVATING)
            registry.promote(version, gate_passed=True,
                             reason=f'auto-promotion {assessment.assessment_id}')

            # 8. It answered before the switch; confirm it answers after it.
            try:
                still_warm = bool(warmup(registry.resolve('ACTIVE')))
            except Exception as exc:
                still_warm = False
                reasons.append(f'post-activation inference raised {type(exc).__name__}')
            if not still_warm:
                self.journal.advance(scope, journal_module.ROLLING_BACK,
                                     reason='post-activation inference failed')
                registry.rollback(reason='post-activation inference failed')
                self.journal.advance(scope, journal_module.ROLLED_BACK)
                reasons.append('the model answered before activation and not after; '
                               'the previous model has been restored')
                return ActivationResult(scope=scope, candidate_version=version,
                                        activated=False,
                                        rollback_target=rollback_target,
                                        reasons=tuple(reasons), quarantined=True)

            # 9. Guarded, not active. §35, §36.
            stage = self.policy.first_stage
            self.guarded.enter(scope=scope, version=version,
                               previous_version=rollback_target, stage=stage.name)
            self.journal.advance(scope, GUARDED, guarded_stage=stage.name)
            reasons.append(f'{version} is {stage.name} with a maximum model-driven '
                           f'action of {stage.action_ceiling}')
            return ActivationResult(scope=scope, candidate_version=version,
                                    activated=True, stage=stage.name,
                                    rollback_target=rollback_target,
                                    reasons=tuple(reasons))
        finally:
            # 10. Always, including on the paths that raised.
            lock.release()

    # --- completion and withdrawal ---------------------------------------

    def complete(self, *, scope, registry=None):
        """Give a guarded model full authority. The end of the staircase."""
        state = self.guarded.load(scope)
        if state is None or not state.active:
            raise ActivationError(f'there is no guarded model for {scope}')
        self.guarded.clear(scope)
        entry = self.journal.in_flight(scope)
        if entry is not None:
            self.journal.advance(scope, COMMITTED,
                                 reason='guarded observation completed')
        return {'scope': scope, 'version': state.version, 'stage': 'ACTIVE',
                'note': 'the model now has the authority PolicyGuard gives any model'}

    def roll_back(self, *, scope, registry, reason):
        """Withdraw a guarded or active model and restore its predecessor.

        Rollback never deletes anything (§118, §119): the withdrawn artifact stays
        on disk, the datasets and reviews are untouched, and the only thing that
        changes is which model answers.
        """
        state = self.guarded.load(scope)
        entry = self.journal.in_flight(scope)
        if entry is not None:
            self.journal.advance(scope, journal_module.ROLLING_BACK, reason=reason)
        registry.rollback(reason=reason)
        if state is not None:
            self.guarded.clear(scope)
        if entry is not None:
            self.journal.advance(scope, journal_module.ROLLED_BACK, reason=reason)
        restored = registry.state.active
        return {'scope': scope,
                'from': getattr(state, 'version', '') or (entry.candidate_version if entry else ''),
                'to': restored, 'reason': reason,
                'firewall_state': 'unchanged',
                'dataset': 'unchanged',
                'note': 'the withdrawn model stays on disk; only the pointer moved'}

    # --- recovery ---------------------------------------------------------

    def recover(self, *, scope, registry):
        """Resolve an interrupted promotion after a restart. Never guesses.

        Returns `(action, message)`. `AMBIGUOUS` means exactly that, and the
        caller's correct response is to freeze and report rather than to pick the
        more likely answer (§115).
        """
        try:
            active = registry.state.active
        except Exception as exc:
            return journal_module.AMBIGUOUS, (
                f'the registry could not be read ({type(exc).__name__}); promotion '
                'is frozen until it can be')
        try:
            action, message, entry = self.journal.recover(scope, registry_active=active)
        except JournalError as exc:
            return journal_module.AMBIGUOUS, (
                f'{exc}; promotion is frozen and the active model is left alone')

        if action == journal_module.DISCARD and entry is not None:
            self.journal.advance(scope, journal_module.ROLLED_BACK,
                                 reason='interrupted before any change')
        elif action == journal_module.ROLL_BACK and entry is not None:
            registry.rollback(reason='completing an interrupted rollback')
            self.journal.advance(scope, journal_module.ROLLED_BACK)
            self.guarded.clear(scope)
        elif action == journal_module.COMPLETE_ROLLBACK and entry is not None:
            self.journal.advance(scope, journal_module.ROLLED_BACK)
            self.guarded.clear(scope)
        elif action == journal_module.RESUME_GUARDED and entry is not None:
            # §66. A restart is not progress: whatever stage it was in, it is
            # still in, and it still owes the same observations.
            if self.guarded.load(scope) is None:
                self.guarded.enter(scope=scope, version=entry.candidate_version,
                                   previous_version=entry.rollback_target,
                                   stage=entry.guarded_stage or self.policy.first_stage.name)
            if entry.phase != GUARDED:
                self.journal.advance(scope, GUARDED,
                                     guarded_stage=entry.guarded_stage
                                     or self.policy.first_stage.name)
        return action, message

    def explain(self, scope):
        state = self.guarded.load(scope)
        entry = self.journal.latest(scope)
        return {'activation_schema_version': ACTIVATION_SCHEMA_VERSION,
                'scope': scope,
                'guarded': state.explain() if state else None,
                'journal': entry.explain() if entry else None}
