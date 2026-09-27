"""Reading web requests from a local Nginx JSON access log.

Nginx has already parsed the HTTP request — correctly, and for years. Writing a
second HTTP parser here would add an attack surface to gain nothing, so this
module does not parse HTTP. It reads structured lines the web server produced.

Everything in a line is still attacker-controlled: a User-Agent can contain a
newline, a path can contain a JSON-breaking string, a Host can be a megabyte
long. So the reader treats every line as hostile text — bounded, decoded once,
and dropped rather than trusted when it does not make sense.

The other half of this module is unglamorous and matters more in practice than
anything above: **log rotation**. A reader that holds one file descriptor
forever stops seeing traffic the first time logrotate runs, and does so silently.
This one notices, reopens, and says so.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path

from .event import build

NGINX_READER_VERSION = 1

#: A single log line longer than this is dropped. Nginx will not produce one;
#: something writing into the log might.
MAX_LINE_BYTES = 16384
#: How many lines one poll may take. Keeps a burst from starving the sensor.
MAX_LINES_PER_POLL = 2000

#: The field names this reader understands, and the ones a deployment must not
#: log. The second list is enforced: a line carrying a credential field is
#: dropped whole rather than partially read, because a log that contains one is
#: a problem the operator needs to fix, not something to quietly work around.
FIELDS = ('time', 'remote_addr', 'forwarded_for', 'real_ip', 'method', 'uri', 'args',
          'status', 'bytes_sent', 'request_length', 'request_time', 'protocol',
          'host', 'user_agent', 'referer', 'auth_outcome', 'service')
FORBIDDEN_FIELDS = ('authorization', 'cookie', 'set_cookie', 'password', 'request_body',
                    'http_authorization', 'http_cookie', 'body', 'post_data')

#: The log_format an operator installs. Kept minimal: every field here is used,
#: and nothing that could carry a secret is requested.
LOG_FORMAT = '''log_format eye_for_an_eye escape=json
    '{'
    '"time":"$time_iso8601",'
    '"remote_addr":"$remote_addr",'
    '"forwarded_for":"$http_x_forwarded_for",'
    '"method":"$request_method",'
    '"uri":"$uri",'
    '"args":"$args",'
    '"status":$status,'
    '"bytes_sent":$bytes_sent,'
    '"request_length":$request_length,'
    '"request_time":$request_time,'
    '"protocol":"$server_protocol",'
    '"host":"$host",'
    '"user_agent":"$http_user_agent",'
    '"referer":"$http_referer"'
    '}';'''


class NginxReaderError(Exception):
    """The reader could not be set up. Never raised while reading a line."""


@dataclass
class ReaderStats:
    """What the reader has done. Every number here is a bounded counter."""

    lines_read: int = 0
    events: int = 0
    parse_errors: int = 0
    rejected_fields: int = 0
    oversized: int = 0
    rotations: int = 0
    reopen_failures: int = 0
    last_error: str = ''

    def explain(self):
        return {'nginx_reader_version': NGINX_READER_VERSION,
                'lines_read': self.lines_read, 'events': self.events,
                'parse_errors': self.parse_errors,
                'rejected_fields': self.rejected_fields,
                'oversized_lines': self.oversized, 'rotations': self.rotations,
                'reopen_failures': self.reopen_failures,
                'last_error': self.last_error}


def parse_time(value):
    """`$time_iso8601`, or now. A bad timestamp is never a reason to lose an event."""
    if not value:
        return datetime.now(timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value)[:40].replace('Z', '+00:00'))
    except ValueError:
        return datetime.now(timezone.utc)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def parse_line(line, resolver, *, secret=None, store_path=False, stats=None):
    """One JSON log line into a `WebEvent`, or None.

    Returns None for anything that is not a usable request record. A dropped line
    is counted, never guessed at: a half-understood request would produce
    half-true features.
    """
    stats = stats or ReaderStats()
    if not line:
        return None
    raw = line if isinstance(line, bytes) else line.encode('utf-8', 'replace')
    if len(raw) > MAX_LINE_BYTES:
        stats.oversized += 1
        return None
    try:
        record = json.loads(raw.decode('utf-8', 'replace'))
    except (ValueError, UnicodeDecodeError):
        stats.parse_errors += 1
        return None
    if not isinstance(record, dict):
        stats.parse_errors += 1
        return None

    lowered = {str(key).lower() for key in record}
    if lowered & set(FORBIDDEN_FIELDS):
        # The log format is logging something it must not. Drop the line and say
        # so; silently stripping it would hide a misconfiguration that is
        # currently writing credentials to disk.
        stats.rejected_fields += 1
        stats.last_error = ('the access log contains a credential field; remove it from '
                            'log_format')
        return None

    identity = resolver.resolve(record.get('remote_addr'),
                               forwarded=record.get('forwarded_for'),
                               real_ip=record.get('real_ip'))
    if not identity.address:
        stats.parse_errors += 1
        return None

    duration = record.get('request_time')
    try:
        duration_ms = float(duration) * 1000.0 if duration not in (None, '', '-') else None
    except (TypeError, ValueError):
        duration_ms = None

    event = build(
        timestamp=parse_time(record.get('time')), identity=identity,
        method=record.get('method', ''), path=record.get('uri', '/'),
        query=record.get('args', ''), status=_int(record.get('status')),
        host=record.get('host', ''), protocol=record.get('protocol', ''),
        request_bytes=_int(record.get('request_length')),
        response_bytes=_int(record.get('bytes_sent')), duration_ms=duration_ms,
        referer=record.get('referer', ''), user_agent=record.get('user_agent', ''),
        auth_outcome=str(record.get('auth_outcome', ''))[:16],
        service=str(record.get('service', ''))[:64],
        secret=secret, store_path=store_path)
    stats.events += 1
    return event


def _int(value):
    try:
        number = int(float(value))
    except (TypeError, ValueError):
        return 0
    return number if 0 <= number <= 2 ** 40 else 0


@dataclass
class LogTailer:
    """Follows a log file across rotation, without ever blocking the caller.

    Rotation is detected by inode, not by name, because logrotate's default is to
    rename the file the descriptor still points at. A reader that watches only the
    path keeps happily reading a file nobody writes to any more.

    Truncation (`copytruncate`) is detected separately: the same inode, but the
    file is now shorter than where we were reading.
    """

    path: str
    stats: ReaderStats = field(default_factory=ReaderStats)
    _handle: object = None
    _inode: int = 0
    _offset: int = 0

    def open(self, *, from_end=True):
        """Open the log. Starting at the end by default, so a first run does not
        replay a month of history as if it had just happened."""
        target = Path(self.path)
        try:
            handle = target.open('rb')
            info = os.fstat(handle.fileno())
        except OSError as exc:
            self.stats.reopen_failures += 1
            self.stats.last_error = f'cannot open {self.path}: {exc.strerror or exc}'
            return False
        self.close()
        self._handle = handle
        self._inode = info.st_ino
        self._offset = info.st_size if from_end else 0
        handle.seek(self._offset)
        return True

    def close(self):
        if self._handle is not None:
            try:
                self._handle.close()
            except OSError:
                pass
        self._handle = None

    @property
    def ready(self):
        return self._handle is not None

    def _rotated(self):
        """Has the file we are reading stopped being the file at this path?"""
        try:
            current = os.stat(self.path)
        except OSError:
            return False
        if current.st_ino != self._inode:
            return True
        return current.st_size < self._offset

    def read(self, *, max_lines=MAX_LINES_PER_POLL):
        """Return up to `max_lines` complete lines. Never blocks, never raises."""
        if self._handle is None and not self.open(from_end=False):
            return []
        if self._rotated():
            self.stats.rotations += 1
            # Drain what is left of the old file first, then follow the new one.
            remainder = self._drain(max_lines)
            self.open(from_end=False)
            return remainder + self._drain(max(0, max_lines - len(remainder)))
        return self._drain(max_lines)

    def _drain(self, max_lines):
        lines = []
        if self._handle is None or max_lines <= 0:
            return lines
        try:
            while len(lines) < max_lines:
                raw = self._handle.readline()
                if not raw:
                    break
                if not raw.endswith(b'\n'):
                    # A partially written line. Rewind so it is read whole next time.
                    self._handle.seek(-len(raw), os.SEEK_CUR)
                    break
                self._offset += len(raw)
                self.stats.lines_read += 1
                lines.append(raw)
        except OSError as exc:
            self.stats.last_error = f'read failed: {exc.strerror or exc}'
            self.close()
        return lines


class NginxSource:
    """A local Nginx access log as a source of `WebEvent`s.

    Bounded on every axis: line length, lines per poll, and what a line may
    contain. It reads; it does not write, reload, or touch the web server.
    """

    def __init__(self, path, resolver, *, secret=None, store_path=False,
                 max_lines_per_poll=MAX_LINES_PER_POLL):
        if not path:
            raise NginxReaderError('a web log path is required')
        self.tailer = LogTailer(path=str(path))
        self.resolver = resolver
        self.secret = secret
        self.store_path = bool(store_path)
        self.max_lines_per_poll = max(1, int(max_lines_per_poll))

    @property
    def stats(self):
        return self.tailer.stats

    def start(self, *, from_end=True):
        return self.tailer.open(from_end=from_end)

    def close(self):
        self.tailer.close()

    def poll(self):
        """Whatever has been written since the last call, as events."""
        events = []
        for line in self.tailer.read(max_lines=self.max_lines_per_poll):
            event = parse_line(line, self.resolver, secret=self.secret,
                               store_path=self.store_path, stats=self.stats)
            if event is not None:
                events.append(event)
        return events

    def health(self):
        document = dict(self.stats.explain())
        document['path'] = self.tailer.path
        document['open'] = self.tailer.ready
        document['trusted_proxies_configured'] = self.resolver.configured
        return document
