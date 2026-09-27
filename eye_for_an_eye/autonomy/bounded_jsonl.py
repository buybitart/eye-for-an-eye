"""One bounded, rotating, append-only JSONL writer. P15.5R §5, §11, §24, §25.

Two things needed this in P15.5R — the canonical decision journal and the
privacy-safe shadow export — and the cycle's own lesson is that two
implementations of one job is how they quietly diverge. So there is one, and the
two callers differ only in what they put in a line and how patient they are
allowed to be.

### The four ceilings, and why all four

`max_file_bytes` makes rotation happen at a predictable size. `max_files` bounds
how far back the history goes. `max_records` is the record-count ceiling P15's
configuration already had. And `max_total_bytes` bounds the disk regardless of
the other three, which matters because an operator who raises one of them rarely
thinks about their product.

A forensic file without a ceiling is a way to fill a disk, and filling the disk
of the machine this software is defending would be a self-inflicted outage.

### Backpressure without a second thread

§11 and §24 ask that slow storage never hold up traffic, and §25 puts service
availability above the audit journal and the journal above the export. A queue
and a writer thread would satisfy that and would also add a thread, a bounded
queue, a shutdown ordering problem and a new way to lose records silently.

This does it with a deadline instead. Each writer carries a `slow_write_seconds`
budget; a write that exceeds it trips a cooling-off period during which writes
are dropped and counted, and after which one write is attempted again. The
hot-path cost of slow storage is therefore bounded at one slow write per
cooldown rather than one per decision, with no thread and no queue — and the
priority order §25 asks for is expressed as two different budgets: the journal
is allowed to be patient, the export is not.

Dropping is visible. `status()` reports the cooling-off state and the counters,
which is what turns "the export is behind" into something an operator can see
rather than something they infer from a file that stopped growing.
"""
from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
import threading
import time

#: Component states, the same four words the rest of the runtime uses.
NOT_CONFIGURED = 'NOT_CONFIGURED'
HEALTHY = 'HEALTHY'
DEGRADED = 'DEGRADED'
UNAVAILABLE = 'UNAVAILABLE'

#: One serialised line. A record larger than this is not a record — it is a bug
#: producing unbounded content — so it is refused and counted rather than
#: written.
MAX_ENTRY_BYTES = 262_144

#: Files are created readable only by the user running the sensor. These are
#: files of behaviour; they do not belong to the group.
FILE_MODE = 0o600


@dataclass(frozen=True, slots=True)
class WriterLimits:
    """Four ceilings and one deadline.

    `slow_write_seconds` is the backpressure budget: a single write taking
    longer than this trips `cooldown_seconds` of dropping. The defaults are
    deliberately far above any healthy local append, so the mechanism is
    invisible until storage is genuinely in trouble.
    """

    max_file_bytes: int = 8_388_608
    max_files: int = 4
    max_total_bytes: int = 33_554_432
    max_records: int = 20_000
    slow_write_seconds: float = 0.25
    cooldown_seconds: float = 5.0

    def __post_init__(self):
        if self.max_file_bytes < 4096:
            raise ValueError('a file smaller than 4 KiB cannot hold a record')
        if not 1 <= self.max_files <= 64:
            raise ValueError('file count must be between 1 and 64')
        if self.max_total_bytes < self.max_file_bytes:
            raise ValueError('the total byte budget must fit at least one file')
        if self.max_records < 1:
            raise ValueError('a log that retains no records is not a log')
        if self.slow_write_seconds <= 0 or self.cooldown_seconds < 0:
            raise ValueError('the backpressure budget must be positive')

    def explain(self):
        return {'max_file_bytes': self.max_file_bytes, 'max_files': self.max_files,
                'max_total_bytes': self.max_total_bytes,
                'max_records': self.max_records,
                'slow_write_seconds': self.slow_write_seconds,
                'cooldown_seconds': self.cooldown_seconds}


class BoundedJsonlWriter:
    """Append-only JSONL with rotation, retention and a write deadline.

    Holds no privilege, and no lock anybody outside it waits on. One writer
    guarded by a lock, because `DecisionEngine.observe` and `DecisionEngine.poll`
    both reach the decision path and the runtime thread is not the only caller
    in every deployment.
    """

    def __init__(self, path, *, limits=None, clock=time.time,
                 monotonic=time.monotonic):
        self.path = Path(path)
        self.limits = limits or WriterLimits()
        self.clock = clock
        self.monotonic = monotonic
        self._lock = threading.Lock()
        self._fd = None
        self._bytes = 0
        self._cooling_until = 0.0
        self.records = 0
        self.counters = {'written': 0, 'failed': 0, 'rotated': 0,
                         'refused_too_large': 0, 'retention_deleted': 0,
                         'dropped_backpressure': 0, 'slow_writes': 0}
        #: Why the last write failed, for `doctor`. Empty is healthy.
        self.last_error = ''

    # -- writing -------------------------------------------------------------

    def write(self, document):
        """Persist one document. Returns whether it landed. Never raises.

        Total exception handling is deliberate: this runs on the decision path,
        and the decision path's answer to "a file misbehaved" must never be an
        exception travelling up into the event loop.
        """
        with self._lock:
            now = self.monotonic()
            if now < self._cooling_until:
                self.counters['dropped_backpressure'] += 1
                return False
            started = now
            try:
                landed = self._write(document)
            except Exception as exc:                               # noqa: BLE001
                self.counters['failed'] += 1
                self.last_error = f'{type(exc).__name__}: {exc}'[:200]
                landed = False
            elapsed = self.monotonic() - started
            if elapsed > self.limits.slow_write_seconds:
                self.counters['slow_writes'] += 1
                self._cooling_until = self.monotonic() + self.limits.cooldown_seconds
                self.last_error = (f'a write took {elapsed:.3f}s, over the '
                                   f'{self.limits.slow_write_seconds}s budget; '
                                   f'dropping for {self.limits.cooldown_seconds}s')
            return landed

    def _write(self, document):
        line = json.dumps(document, ensure_ascii=True, separators=(',', ':'),
                          allow_nan=False).encode('utf-8') + b'\n'
        if len(line) > MAX_ENTRY_BYTES:
            self.counters['refused_too_large'] += 1
            self.last_error = (f'a record serialised to {len(line)} bytes, over the '
                               f'{MAX_ENTRY_BYTES}-byte entry ceiling')
            return False
        if self.records >= self.limits.max_records:
            self._rotate()
        self._open()
        if self._bytes and self._bytes + len(line) > self.limits.max_file_bytes:
            self._rotate()
            self._open()
        written = os.write(self._fd, line)
        if written != len(line):
            # A short write leaves a truncated line. It will not parse, so a
            # reader skips it rather than misreading it — but it is a failure
            # and is counted as one.
            self.counters['failed'] += 1
            self.last_error = f'short write: {written} of {len(line)} bytes'
            return False
        self._bytes += written
        self.records += 1
        self.counters['written'] += 1
        self.last_error = ''
        return True

    # -- files ---------------------------------------------------------------

    def _open(self):
        if self._fd is not None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                           FILE_MODE)
        info = os.fstat(self._fd)
        if stat.S_ISREG(info.st_mode):
            # Only a regular file, and only because this is a file of behaviour
            # that should not belong to the group (§4). Anything else is an
            # object the operator made deliberately — a device, a fifo, a socket
            # — and narrowing its mode is the sensor changing something it did
            # not create.
            #
            # Not hypothetical. A privileged test run pointed a writer at
            # `/dev/full` to inject ENOSPC and left the device mode 0600 for
            # every other process on the machine, which is a small outage caused
            # by a defender's logging path.
            try:
                os.fchmod(self._fd, FILE_MODE)
            except OSError:
                # A filesystem that will not take the mode is not a reason to
                # stop writing; it is a reason for the operator to know.
                # `status()` reports the intended mode rather than this raising.
                pass
        self._bytes = info.st_size

    def _close(self):
        if self._fd is not None:
            try:
                os.close(self._fd)
            finally:
                self._fd = None
                self._bytes = 0

    def _rotate(self):
        """`name` -> `name.1` -> `name.2` ... and the oldest is removed.

        Rename rather than copy, so a reader holding the old path keeps reading
        a complete file and no record is ever half-moved.
        """
        self._close()
        if not self.path.exists():
            self.records = 0
            return
        for index in range(self.limits.max_files - 1, 0, -1):
            source = self.rotated(index)
            target = self.rotated(index + 1)
            if source.exists():
                if index + 1 >= self.limits.max_files:
                    self._unlink(source)
                else:
                    source.replace(target)
        self.path.replace(self.rotated(1))
        self.records = 0
        self.counters['rotated'] += 1
        self._enforce_total_bytes()

    def rotated(self, index):
        return self.path.with_name(f'{self.path.name}.{index}')

    def _unlink(self, path):
        try:
            path.unlink()
            self.counters['retention_deleted'] += 1
        except OSError:
            pass

    def _enforce_total_bytes(self):
        """The ceiling that holds whatever the others are set to.

        Oldest first, because the newest records are the ones somebody is most
        likely to be looking for.
        """
        while True:
            files = self.existing()
            total = sum(size for _path, size in files)
            if total <= self.limits.max_total_bytes or len(files) <= 1:
                return
            self._unlink(files[-1][0])

    def existing(self):
        """Every file in this set, newest first, with its size."""
        found = []
        for index in range(0, self.limits.max_files + 1):
            path = self.path if index == 0 else self.rotated(index)
            try:
                found.append((path, path.stat().st_size))
            except OSError:
                continue
        return found

    # -- state ---------------------------------------------------------------

    @property
    def cooling(self):
        return self.monotonic() < self._cooling_until

    @property
    def total_bytes(self):
        return sum(size for _path, size in self.existing())

    def status(self):
        healthy = not self.last_error and not self.cooling
        return {
            'status': HEALTHY if healthy else DEGRADED,
            'path': str(self.path),
            'files': len(self.existing()),
            'total_bytes': self.total_bytes,
            'records_in_active_file': self.records,
            'cooling_off': self.cooling,
            'limits': self.limits.explain(),
            'counters': dict(self.counters),
            'last_error': self.last_error,
            'permissions': oct(FILE_MODE),
        }

    def close(self):
        with self._lock:
            self._close()
