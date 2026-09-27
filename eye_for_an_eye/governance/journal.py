"""The promotion journal: what was happening when the power went out.

A promotion touches several things — staged files, a registry pointer, a guarded
state record — and a process can die between any two of them. Without a durable
note of intent, the state afterwards is a guess: is this model active because it
was promoted, or because a half-finished promotion left the pointer moved and
nothing else?

So every promotion writes its intent down before doing anything, and updates the
note at each step that cannot be undone by simply forgetting. On restart,
`recover()` reads the note and the registry and returns one unambiguous answer.

    PREPARE      intent recorded; nothing has been touched
    STAGED       artifacts verified and staged; the pointer is untouched
    ACTIVATING   the pointer write has been attempted
    GUARDED      the new model is live under a reduced ceiling
    COMMITTED    the new model has full authority
    ROLLING_BACK a withdrawal has been attempted
    ROLLED_BACK  the previous model is live again

This is deliberately not a consensus protocol. It is one file on one machine,
written by atomic rename, and that is enough: there is exactly one writer, the
thing being protected is a single pointer, and adding a distributed algorithm
here would add failure modes rather than remove them (§63).

The recovery rule that matters most is the one for `GUARDED`. A restart must
**not** be read as a successful observation period. A model that was halfway
through earning its authority when the machine rebooted has not earned any more
of it than it had, and the clock does not restart in its favour either (§66).
"""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile

JOURNAL_SCHEMA_VERSION = 1

PREPARE = 'PREPARE'
STAGED = 'STAGED'
ACTIVATING = 'ACTIVATING'
GUARDED = 'GUARDED'
COMMITTED = 'COMMITTED'
ROLLING_BACK = 'ROLLING_BACK'
ROLLED_BACK = 'ROLLED_BACK'

PHASES = (PREPARE, STAGED, ACTIVATING, GUARDED, COMMITTED, ROLLING_BACK, ROLLED_BACK)

#: Phases where nothing outside the journal has changed yet, so abandoning the
#: entry is a complete and correct recovery.
UNTOUCHED = (PREPARE, STAGED)
#: Phases that are an end state.
SETTLED = (COMMITTED, ROLLED_BACK)

#: What `recover()` tells the caller to do.
NOTHING_TO_DO = 'NOTHING_TO_DO'
DISCARD = 'DISCARD'
RESUME_GUARDED = 'RESUME_GUARDED'
COMPLETE_ROLLBACK = 'COMPLETE_ROLLBACK'
ROLL_BACK = 'ROLL_BACK'
AMBIGUOUS = 'AMBIGUOUS'

#: Entries kept per scope. Bounded, because this runs unattended.
MAX_ENTRIES = 64
MAX_BYTES = 262_144


class JournalError(ValueError):
    """The journal cannot be read, and nothing may be guessed from that."""


def _now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


@dataclass(frozen=True, slots=True)
class JournalEntry:
    """One promotion attempt, and how far it got."""

    scope: str
    candidate_version: str
    phase: str
    rollback_target: str = ''
    assessment_id: str = ''
    policy_digest: str = ''
    guarded_stage: str = ''
    started_at: str = ''
    updated_at: str = ''
    reason: str = ''

    def __post_init__(self):
        if self.phase not in PHASES:
            raise JournalError(f'{self.phase!r} is not a promotion phase')

    @property
    def settled(self):
        return self.phase in SETTLED

    def explain(self):
        return asdict(self)


@dataclass
class PromotionJournal:
    """A small durable record, one file, atomic writes, bounded length.

    Not a log of everything that happened — that is the history file. This is
    only ever asked one question: *what was in progress?*
    """

    path: Path
    entries: list = field(default_factory=list)

    def __init__(self, path):
        self.path = Path(path)
        self.entries = []
        self._load()

    # --- durability -------------------------------------------------------

    def _load(self):
        if not self.path.is_file():
            self.entries = []
            return
        try:
            if self.path.stat().st_size > MAX_BYTES:
                raise JournalError('promotion journal is larger than its bound')
            body = json.loads(self.path.read_text(encoding='utf-8'))
        except (OSError, ValueError) as exc:
            # §115: an unreadable journal freezes promotion. It never resolves
            # to "nothing was happening", because that is the one reading that
            # could silently leave a half-finished promotion in place.
            raise JournalError(f'promotion journal is unreadable: {exc}') from exc
        if body.get('journal_schema_version') != JOURNAL_SCHEMA_VERSION:
            raise JournalError('unsupported promotion journal version')
        self.entries = [JournalEntry(**entry) for entry in body.get('entries', [])]

    def _save(self):
        self.entries = self.entries[-MAX_ENTRIES:]
        payload = json.dumps(
            {'journal_schema_version': JOURNAL_SCHEMA_VERSION,
             'entries': [entry.explain() for entry in self.entries]},
            indent=2, sort_keys=False).encode('utf-8')
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Written to a temporary file in the same directory, flushed, then
        # renamed. A rename within one directory is atomic, so a reader sees
        # either the old file or the new one and never a partial write.
        handle, temporary = tempfile.mkstemp(dir=str(self.path.parent),
                                             prefix='.journal-')
        try:
            with os.fdopen(handle, 'wb') as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
        try:
            directory = os.open(str(self.path.parent), os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(directory)
        except OSError:
            # Some filesystems refuse directory fsync. The rename is still
            # atomic; only the moment it becomes durable is less certain.
            pass
        finally:
            os.close(directory)

    # --- writing ----------------------------------------------------------

    def open(self, *, scope, candidate_version, rollback_target, assessment_id='',
             policy_digest='', reason=''):
        """Record the intent to promote, before anything is touched."""
        if self.in_flight(scope):
            raise JournalError(
                f'a promotion for {scope} is already in flight; one scope changes '
                'at a time')
        entry = JournalEntry(
            scope=scope, candidate_version=candidate_version, phase=PREPARE,
            rollback_target=rollback_target, assessment_id=assessment_id,
            policy_digest=policy_digest, started_at=_now(), updated_at=_now(),
            reason=reason[:200])
        self.entries.append(entry)
        self._save()
        return entry

    def advance(self, scope, phase, *, guarded_stage=None, reason=None):
        """Move the in-flight entry for `scope` to a later phase."""
        index = self._index(scope)
        if index is None:
            raise JournalError(f'no promotion is in flight for {scope}')
        current = self.entries[index]
        if phase not in PHASES:
            raise JournalError(f'{phase!r} is not a promotion phase')
        updated = JournalEntry(
            scope=current.scope, candidate_version=current.candidate_version,
            phase=phase, rollback_target=current.rollback_target,
            assessment_id=current.assessment_id, policy_digest=current.policy_digest,
            guarded_stage=(current.guarded_stage if guarded_stage is None
                           else guarded_stage),
            started_at=current.started_at, updated_at=_now(),
            reason=current.reason if reason is None else str(reason)[:200])
        self.entries[index] = updated
        self._save()
        return updated

    # --- reading ----------------------------------------------------------

    def _index(self, scope):
        for position in range(len(self.entries) - 1, -1, -1):
            if self.entries[position].scope == scope and not self.entries[position].settled:
                return position
        return None

    def in_flight(self, scope=None):
        """The unsettled entry for a scope, or any unsettled entry."""
        if scope is None:
            unsettled = [entry for entry in self.entries if not entry.settled]
            return unsettled[-1] if unsettled else None
        index = self._index(scope)
        return self.entries[index] if index is not None else None

    def in_flight_count(self):
        return sum(1 for entry in self.entries if not entry.settled)

    def latest(self, scope):
        for entry in reversed(self.entries):
            if entry.scope == scope:
                return entry
        return None

    def history(self, scope=None, limit=20):
        found = [entry for entry in self.entries
                 if scope is None or entry.scope == scope]
        return found[-limit:]

    # --- recovery ---------------------------------------------------------

    def recover(self, scope, *, registry_active):
        """What to do about `scope` after a restart. Never guesses.

        `registry_active` is what the registry pointer actually says now, which
        is the other half of the answer: the journal records intent, the pointer
        records what happened, and only the two together are unambiguous.
        """
        entry = self.in_flight(scope)
        if entry is None:
            return NOTHING_TO_DO, '', None

        if entry.phase in UNTOUCHED:
            # Intent was recorded and nothing outside the journal changed.
            return DISCARD, (f'a promotion of {entry.candidate_version} was '
                             f'interrupted at {entry.phase}; nothing had been '
                             'changed, so there is nothing to undo'), entry

        if entry.phase == ACTIVATING:
            # The dangerous one. The pointer write either happened or did not.
            if registry_active == entry.candidate_version:
                return RESUME_GUARDED, (
                    f'{entry.candidate_version} was activated before the '
                    'interruption; it resumes under its guarded ceiling rather '
                    'than as a full active model'), entry
            if registry_active == entry.rollback_target:
                return DISCARD, (
                    f'the pointer still names {entry.rollback_target}; the '
                    'promotion did not take effect'), entry
            return AMBIGUOUS, (
                f'the journal expected {entry.candidate_version} or '
                f'{entry.rollback_target} to be active, and the registry names '
                f'{registry_active!r}; this is not safe to resolve automatically'), entry

        if entry.phase == GUARDED:
            if registry_active != entry.candidate_version:
                return AMBIGUOUS, (
                    f'{entry.candidate_version} was guarded-active but the registry '
                    f'now names {registry_active!r}'), entry
            # §66: a restart is not an observation period. The stage is carried
            # forward exactly as it was, and the evidence it still owes is
            # unchanged.
            return RESUME_GUARDED, (
                f'{entry.candidate_version} continues in {entry.guarded_stage}; a '
                'restart earns it no authority and resets no requirement'), entry

        if entry.phase == ROLLING_BACK:
            if registry_active == entry.rollback_target:
                return COMPLETE_ROLLBACK, (
                    f'the rollback to {entry.rollback_target} had already taken '
                    'effect; the journal is being closed'), entry
            return ROLL_BACK, (
                f'a rollback to {entry.rollback_target} was interrupted and must '
                'be completed'), entry

        return AMBIGUOUS, f'unexpected phase {entry.phase}', entry

    def explain(self):
        return {'journal_schema_version': JOURNAL_SCHEMA_VERSION,
                'path': str(self.path),
                'in_flight': self.in_flight_count(),
                'entries': [entry.explain() for entry in self.entries[-10:]]}
