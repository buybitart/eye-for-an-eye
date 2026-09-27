"""Durable governance state: history, the audit log, and the freeze switch.

Three small files, all bounded, all written by atomic rename. None of them is a
database, and none of them needs to be: the whole point of local-first is that an
operator can read these with `cat` when something has gone wrong and the program
will not start.

**History** (§101) is the record of what happened to which model. Bounded, and it
never contains a dataset, a feature vector or anything about a visitor.

**The audit log** (§102) is the record of security-relevant decisions: who turned
automatic promotion on, when a candidate became eligible, when something was
promoted, advanced, withdrawn, frozen or released. It exists to answer "why is
this model running" months later, so entries are appended and never rewritten.

**The freeze switch** (§54) is one flag and a reason. It is separate from the
configuration on purpose: an operator freezing promotion during an incident
should not have to edit a config file and restart anything, and the system
setting it automatically after repeated failures (§55) must not be editing the
operator's configuration behind their back.
"""
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile

GOVERNANCE_STORE_SCHEMA_VERSION = 1

MAX_HISTORY = 200
MAX_AUDIT = 500
MAX_BYTES = 1_048_576

#: Audit event names. A closed set, so the log can be read by a machine and so
#: that adding one is a deliberate act rather than a string typed at a call site.
AUTO_PROMOTION_ENABLED = 'auto_promotion_enabled'
AUTO_PROMOTION_DISABLED = 'auto_promotion_disabled'
CANDIDATE_ASSESSED = 'candidate_assessed'
PROMOTION_STARTED = 'promotion_started'
PROMOTION_GUARDED = 'promotion_guarded'
STAGE_ADVANCED = 'stage_advanced'
PROMOTION_COMMITTED = 'promotion_committed'
ROLLED_BACK = 'rolled_back'
QUARANTINED = 'quarantined'
RELEASED_FROM_QUARANTINE = 'released_from_quarantine'
FROZEN = 'frozen'
UNFROZEN = 'unfrozen'
SAFE_MODE_ENTERED = 'safe_mode_entered'
MANUAL_OVERRIDE = 'manual_override'

AUDIT_EVENTS = (AUTO_PROMOTION_ENABLED, AUTO_PROMOTION_DISABLED, CANDIDATE_ASSESSED,
                PROMOTION_STARTED, PROMOTION_GUARDED, STAGE_ADVANCED,
                PROMOTION_COMMITTED, ROLLED_BACK, QUARANTINED,
                RELEASED_FROM_QUARANTINE, FROZEN, UNFROZEN, SAFE_MODE_ENTERED,
                MANUAL_OVERRIDE)


class StoreError(ValueError):
    """Governance state cannot be read, and nothing is guessed from that."""


def _now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def _write_atomic(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=str(path.parent), prefix='.gov-')
    try:
        with os.fdopen(handle, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _read_json(path, *, what):
    if not path.is_file():
        return None
    try:
        if path.stat().st_size > MAX_BYTES:
            raise StoreError(f'{what} is larger than its bound')
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise StoreError(f'{what} is unreadable: {exc}') from exc


@dataclass(frozen=True, slots=True)
class HistoryEntry:
    """One thing that happened to one model, for one scope."""

    at: str
    scope: str
    event: str
    version: str = ''
    previous_version: str = ''
    assessment_id: str = ''
    policy_digest: str = ''
    stage: str = ''
    decision: str = ''
    reason: str = ''

    def explain(self):
        return asdict(self)


@dataclass(frozen=True, slots=True)
class FreezeState:
    """Whether anything may be promoted or advanced right now."""

    frozen: bool = False
    reason: str = ''
    at: str = ''
    by: str = ''
    automatic: bool = False
    consecutive_failures: int = 0
    safe_mode: bool = False

    def explain(self):
        return asdict(self)


class GovernanceStore:
    """History, audit and freeze for one installation.

    Per-scope history (§71) is kept in one file and filtered on read rather than
    split across files: the whole thing is bounded at a few hundred entries, and
    one file an operator can open beats a directory they have to assemble.
    """

    def __init__(self, root):
        self.root = Path(root)

    # --- paths ------------------------------------------------------------

    @property
    def history_path(self):
        return self.root / 'promotion-history.json'

    @property
    def audit_path(self):
        return self.root / 'governance-audit.jsonl'

    @property
    def freeze_path(self):
        return self.root / 'governance-freeze.json'

    # --- history ----------------------------------------------------------

    def history(self, scope=None, limit=50):
        body = _read_json(self.history_path, what='promotion history') or {}
        if body and body.get('governance_store_schema_version') != GOVERNANCE_STORE_SCHEMA_VERSION:
            raise StoreError('unsupported promotion history version')
        entries = [HistoryEntry(**entry) for entry in body.get('entries', [])]
        if scope is not None:
            entries = [entry for entry in entries if entry.scope == scope]
        return entries[-limit:]

    def record(self, *, scope, event, **fields):
        """Append one history entry. Bounded, and never rewritten."""
        body = _read_json(self.history_path, what='promotion history') or {}
        entries = list(body.get('entries', []))
        entry = HistoryEntry(at=_now(), scope=scope, event=event,
                             **{key: str(value)[:200] for key, value in fields.items()
                                if key in HistoryEntry.__dataclass_fields__})
        entries.append(entry.explain())
        _write_atomic(self.history_path, json.dumps(
            {'governance_store_schema_version': GOVERNANCE_STORE_SCHEMA_VERSION,
             'entries': entries[-MAX_HISTORY:]}, indent=2).encode('utf-8'))
        return entry

    # --- audit ------------------------------------------------------------

    def audit(self, event, *, scope='', actor='system', detail=''):
        """Append one security-relevant event. JSONL, so it survives a partial write.

        An unknown event name is refused rather than written. A log whose
        vocabulary anybody can extend at a call site stops being readable by
        anything but a person, and the point of this file is that a machine can
        check it too.
        """
        if event not in AUDIT_EVENTS:
            raise StoreError(f'{event!r} is not a governance audit event')
        line = json.dumps({'at': _now(), 'event': event, 'scope': scope,
                           'actor': str(actor)[:64], 'detail': str(detail)[:300]},
                          separators=(',', ':'))
        self.root.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open('a', encoding='utf-8') as stream:
            stream.write(line + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        self._trim_audit()
        return line

    def _trim_audit(self):
        try:
            if self.audit_path.stat().st_size <= MAX_BYTES:
                return
            lines = self.audit_path.read_text(encoding='utf-8').splitlines()
        except (OSError, ValueError):
            return
        _write_atomic(self.audit_path,
                      ('\n'.join(lines[-MAX_AUDIT:]) + '\n').encode('utf-8'))

    def audit_entries(self, limit=50):
        if not self.audit_path.is_file():
            return []
        try:
            lines = self.audit_path.read_text(encoding='utf-8').splitlines()
        except OSError as exc:
            raise StoreError(f'the audit log is unreadable: {exc}') from exc
        found = []
        for line in lines[-limit:]:
            try:
                found.append(json.loads(line))
            except ValueError:
                # One torn line at the end of an append-only file is expected
                # after a crash and is not a reason to refuse the whole log.
                continue
        return found

    # --- freeze -----------------------------------------------------------

    def freeze_state(self):
        body = _read_json(self.freeze_path, what='the governance freeze state')
        if body is None:
            return FreezeState()
        if body.get('governance_store_schema_version') != GOVERNANCE_STORE_SCHEMA_VERSION:
            raise StoreError('unsupported governance freeze version')
        return FreezeState(**{key: value for key, value in body.items()
                              if key in FreezeState.__dataclass_fields__})

    def freeze(self, *, reason, by='operator', automatic=False, safe_mode=False):
        """Stop all promotion and all stage advancement."""
        current = self.freeze_state()
        state = FreezeState(frozen=True, reason=str(reason)[:200], at=_now(), by=by,
                            automatic=automatic,
                            consecutive_failures=current.consecutive_failures,
                            safe_mode=safe_mode or current.safe_mode)
        self._save_freeze(state)
        self.audit(SAFE_MODE_ENTERED if safe_mode else FROZEN, actor=by, detail=reason)
        return state

    def unfreeze(self, *, by='operator', reason=''):
        """Resume. Deliberately clears the failure count as well.

        An operator releasing a freeze has looked at why it happened; carrying
        the old count forward would freeze them again almost immediately and
        teach them to stop using the command.
        """
        state = FreezeState(frozen=False, reason='', at=_now(), by=by,
                            automatic=False, consecutive_failures=0, safe_mode=False)
        self._save_freeze(state)
        self.audit(UNFROZEN, actor=by, detail=reason)
        return state

    def record_failure(self, *, policy, reason=''):
        """Count a failed promotion, and freeze once there have been enough (§55)."""
        current = self.freeze_state()
        count = current.consecutive_failures + 1
        limit = policy.promotion.failures_before_freeze
        if count >= limit and not current.frozen:
            return self.freeze(
                reason=(f'{count} promotions failed in a row, at the limit of {limit}; '
                        'repeated failure means something another attempt will not '
                        'fix'),
                by='system', automatic=True)
        state = FreezeState(frozen=current.frozen, reason=current.reason,
                            at=current.at, by=current.by, automatic=current.automatic,
                            consecutive_failures=count, safe_mode=current.safe_mode)
        self._save_freeze(state)
        return state

    def clear_failures(self):
        current = self.freeze_state()
        state = FreezeState(frozen=current.frozen, reason=current.reason,
                            at=current.at, by=current.by, automatic=current.automatic,
                            consecutive_failures=0, safe_mode=current.safe_mode)
        self._save_freeze(state)
        return state

    def enter_safe_mode(self, *, reason, by='system'):
        """§57, §116. The state after a rollback itself fails.

        Safe mode is a stronger thing than a freeze: promotion stops, candidate
        authority stops, and the system runs on a known-good model with the
        mathematical engine and PolicyGuard, which never depended on any of this.
        """
        return self.freeze(reason=reason, by=by, automatic=True, safe_mode=True)

    def _save_freeze(self, state):
        body = {'governance_store_schema_version': GOVERNANCE_STORE_SCHEMA_VERSION}
        body.update(state.explain())
        _write_atomic(self.freeze_path, json.dumps(body, indent=2).encode('utf-8'))

    # --- reporting --------------------------------------------------------

    def explain(self):
        try:
            freeze = self.freeze_state().explain()
        except StoreError as exc:
            freeze = {'error': str(exc)}
        try:
            history = len(self.history(limit=MAX_HISTORY))
        except StoreError as exc:
            history = f'unreadable: {exc}'
        return {'governance_store_schema_version': GOVERNANCE_STORE_SCHEMA_VERSION,
                'root': str(self.root), 'freeze': freeze,
                'history_entries': history}
