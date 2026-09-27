"""The canonical decision record, on disk, bounded. P15.5R §1-§7.

### Why this exists, and why it did not

`autonomy.decision_journal_path` has been a configuration setting since P15. It
is documented as "where decision records are written". Nothing wrote them.

That was survivable while the authority itself was never constructed by a
running sensor. It stopped being survivable the moment it was, because the
operational log turned out not to be able to carry a decision: `serialize_event`
refuses any log record over 4096 bytes and replaces its observations with
`{'record_truncated': True}` — the whole record, not the verbose parts of it. A
full `AutonomousDecisionRecord` is several times that. So the richest decisions,
the ones with the most families and the most reason codes, were exactly the ones
that lost everything.

Raising the log limit would have been the wrong repair. A log line is a line: it
is read by people and by tools that assume lines are small, and making it large
enough for the largest decision would make it large enough for anything. The two
jobs are different and now have different homes:

    operational log   a compact summary, one line, always bounded
    decision journal  the complete record, JSONL, rotated, retained, local

### What "bounded" means here

Everything: one record's serialised size, one file's size, how many files are
kept, and the total bytes on disk. A forensic log with no ceiling is a way to
fill a disk, and filling the disk of a machine this software is defending would
be a self-inflicted outage.

### What happens when the journal cannot be written

Nothing that could hurt. A failure here never blocks anybody, never unblocks
anybody, never touches the firewall and never stops the sensor. It degrades the
journal's health and counts the failure, and the compact summary in the
operational log still carries the decision id, the action, the profile, the
probability, the bound and the reason codes — so a block remains explainable
even when its full record did not land.

Whether a journal failure should additionally *suppress* an otherwise-valid
block is an operator's judgement rather than this module's. Nothing in this
project's existing policy makes durable auditability a precondition for acting,
and inventing one silently is what §6 forbids in the other direction too. So the
choice is explicit: `autonomy.journal_required_for_action`, default false,
because the accountable minimum survives in the log either way. An operator who
needs the stronger property sets it and gets it.
"""
from .bounded_jsonl import (BoundedJsonlWriter, DEGRADED, FILE_MODE, HEALTHY,
                            MAX_ENTRY_BYTES, NOT_CONFIGURED, UNAVAILABLE,
                            WriterLimits)
from ..security.redaction import sensitive_key

import time

JOURNAL_SCHEMA_VERSION = 1

#: The journal's ceilings are the shared writer's. Named here so a caller can
#: keep saying `JournalLimits` and so the journal's own default patience — it is
#: allowed to be slower than the shadow export, per §25's priority order — is
#: stated in one place.
JournalLimits = WriterLimits

#: §25. The journal sits above the shadow export and below the decision path, so
#: it is given a longer write budget than the export and a shorter one than
#: anything the sensor needs to keep doing.
JOURNAL_SLOW_WRITE_SECONDS = 0.25

#: Keys whose *presence* would mean something upstream changed in a way this
#: module must refuse rather than serialise. `security/redaction.REDACT_KEYS` is
#: the same vocabulary the event logger and the API already use, so a field that
#: would be redacted there cannot be written in full here.
#:
#: The record has no such field today — it holds derived values, bounded reason
#: codes and no free text from a request. This is the guard against the day
#: somebody adds one.
FORBIDDEN_MARKER = '[refused: sensitive field name]'


def sanitise(document, *, include_source=False, _depth=0):
    """Walk a decision document and refuse anything that must not be persisted.

    Two rules, both applied to every key at every depth:

    * a key whose name is in the project's redaction vocabulary — password,
      authorization, cookie, token, credential, secret, session, payload, raw —
      is replaced by a marker rather than written;
    * `source`, the operational address, is dropped unless the operator asked
      for it. `source_pseudonym` is always kept, which is what correlates one
      source's records without the journal becoming a list of who visited.

    The first rule finds nothing in today's record. It is here because "the
    record contains no secrets" is a property of this version of the record, and
    a journal is exactly the place where that stops being true quietly.
    """
    if _depth >= 8:
        return '[depth limit]'
    if isinstance(document, dict):
        out = {}
        for key, value in document.items():
            name = str(key)
            if sensitive_key(name):
                out[name] = FORBIDDEN_MARKER
                continue
            if name == 'source' and not include_source:
                continue
            out[name] = sanitise(value, include_source=include_source,
                                 _depth=_depth + 1)
        return out
    if isinstance(document, (list, tuple)):
        return [sanitise(item, include_source=include_source, _depth=_depth + 1)
                for item in document]
    return document




class DecisionJournal:
    """The canonical full record, written through the shared bounded writer.

    This class owns two things and delegates everything else: what a journal
    line contains, and whether a decision that could not be written may still
    be acted on. Rotation, retention, permissions, the entry ceiling and the
    write deadline all belong to `BoundedJsonlWriter`, which the shadow export
    uses as well — because two implementations of one job is how they quietly
    diverge, which is the lesson this whole cycle is about.
    """

    schema_version = JOURNAL_SCHEMA_VERSION

    def __init__(self, path, *, limits=None, include_source=False,
                 required_for_action=False, clock=time.time):
        self.writer = BoundedJsonlWriter(
            path,
            limits=limits or WriterLimits(
                slow_write_seconds=JOURNAL_SLOW_WRITE_SECONDS),
            clock=clock)
        self.include_source = bool(include_source)
        self.required_for_action = bool(required_for_action)
        self.clock = clock

    # -- the parts of the old surface callers still use ----------------------

    @property
    def path(self):
        return self.writer.path

    @property
    def limits(self):
        return self.writer.limits

    @property
    def counters(self):
        return self.writer.counters

    @property
    def last_error(self):
        return self.writer.last_error

    @property
    def records(self):
        return self.writer.records

    # -- writing -------------------------------------------------------------

    def write(self, outcome):
        """Persist one decision. Returns whether it landed. Never raises.

        The return value is the only thing a caller may act on, and the only
        caller that acts on it is the one honouring
        `journal_required_for_action`.
        """
        return self.writer.write(self.entry(outcome))

    def entry(self, outcome):
        """One journal line, before serialisation. Separated so a test can read
        what would be written without writing it."""
        return {
            'journal_schema_version': JOURNAL_SCHEMA_VERSION,
            'written_at': round(self.clock(), 3),
            'entry': sanitise(outcome.explain(), include_source=self.include_source),
        }

    # -- state ---------------------------------------------------------------

    def status(self):
        body = self.writer.status()
        body.update({
            'journal_schema_version': JOURNAL_SCHEMA_VERSION,
            'include_source': self.include_source,
            'required_for_action': self.required_for_action,
            'note': ('the canonical full decision record. The operational log '
                     'carries a bounded summary of the same decision'),
        })
        return body

    def metrics(self):
        return {'decision_journal_records_total': self.counters['written'],
                'decision_journal_failures_total': self.counters['failed'],
                'decision_journal_rotations_total': self.counters['rotated'],
                'decision_journal_bytes': self.writer.total_bytes}

    def close(self):
        self.writer.close()


def from_config(config, *, clock=time.time):
    """The journal this configuration asks for, or `None`.

    `None` is the default and a supported state: a decision journal is useful
    and it is also a file of behaviour, so an operator opts in. `status()` on a
    runtime without one reports NOT_CONFIGURED rather than a fault.
    """
    settings = getattr(config, 'autonomy', None)
    path = str(getattr(settings, 'decision_journal_path', '') or '') if settings else ''
    if not path:
        return None
    return DecisionJournal(
        path,
        limits=WriterLimits(
            max_file_bytes=int(getattr(settings, 'journal_max_file_bytes',
                                       WriterLimits.max_file_bytes)),
            max_files=int(getattr(settings, 'journal_max_files',
                                  WriterLimits.max_files)),
            max_total_bytes=int(getattr(settings, 'journal_max_total_bytes',
                                        WriterLimits.max_total_bytes)),
            max_records=int(getattr(settings, 'decision_journal_max_entries',
                                    WriterLimits.max_records)),
            slow_write_seconds=JOURNAL_SLOW_WRITE_SECONDS),
        include_source=bool(getattr(settings, 'journal_include_source', False)),
        required_for_action=bool(
            getattr(settings, 'journal_required_for_action', False)),
        clock=clock)
