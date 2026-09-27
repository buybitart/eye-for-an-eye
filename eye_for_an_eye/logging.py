"""Bounded asynchronous JSONL telemetry. Slow output cannot grow the input queue."""
from collections import Counter
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import queue
from pathlib import Path
import shutil
import sys
import threading
import time
from .enrichment.cache import TTLCache
from .limits import TokenBucket
from .event_types import EventType
from .security.redaction import bounded_value


class _ReportingFileHandler(RotatingFileHandler):
    def handleError(self, record):
        # RotatingFileHandler normally prints and swallows write/rotation failures.
        # Let the bounded writer record failure instead of falsely counting success.
        raise


def safe_value(value, depth=0):
    return bounded_value(value, depth)


def serialize_event(event):
    record = json.loads(event.to_json())
    warning = event.event_type in (EventType.PARSE_ERROR, EventType.STORAGE_ERROR, EventType.RUNTIME_WARNING)
    record.update(level='WARNING' if warning else 'INFO', component='sensor', event=str(event.event_type))
    line = json.dumps(record, ensure_ascii=True, separators=(',', ':'))
    if len(line) > 4096:
        record.update(observations={'record_truncated': True}, hypotheses={}, deception={},
                      classification=None, confidence='UNKNOWN', enrichment={}, limitations=['log_record_limit'])
        line = json.dumps(record, ensure_ascii=True, separators=(',', ':'))
    return line


class EventLogger:
    def __init__(self, config, *, writer=None):
        self.config = config
        self.queue = queue.Queue(config.queue_size)
        self.writer = writer
        self.handler = None
        self.cancel = threading.Event()
        self.thread = None
        self.lock = threading.Lock()
        self.rate = TokenBucket(config.events_per_second)
        self.sources = TTLCache(10000, 60, max_bytes=4_194_304)
        self.metrics = Counter()
        self.types = {item: TokenBucket(config.per_event_type_per_second) for item in EventType}
        self.repeated = TTLCache(1024, config.repeated_window, max_bytes=1_048_576)

    def start(self):
        if self.thread is not None:
            return
        if self.writer is None:
            if self.config.file:
                self.handler = _ReportingFileHandler(self.config.file, maxBytes=self.config.max_bytes,
                                                  backupCount=self.config.backups, encoding='utf-8')
                self.handler.setFormatter(logging.Formatter('%(message)s'))
                self.writer = lambda line: self.handler.emit(logging.LogRecord('eye', logging.INFO, '', 0, line.rstrip('\n'), (), None))
            else:
                self.writer = sys.stdout.write
        # A permanently stalled OS output cannot prevent termination of listeners.
        self.thread = threading.Thread(target=self._run, name='event-writer', daemon=True)
        self.thread.start()

    def emit(self, event):
        if self.cancel.is_set():
            return False
        with self.lock:
            if event.event_type not in self.types:
                self.metrics['invalid_event_type'] += 1
                return False
            if event.event_type in (EventType.PARSE_ERROR, EventType.RUNTIME_WARNING, EventType.STORAGE_ERROR):
                signature = (str(event.event_type), event.src_ip, hashlib.sha256(
                    json.dumps(bounded_value(event.observations), sort_keys=True).encode()).digest())
                if self.repeated.get(signature):
                    self.metrics['suppressed_count'] += 1
                    return False
                self.repeated.set(signature, True)
            now = time.monotonic()
            burst = max(1.0, self.config.per_source_per_second)
            tokens, updated = self.sources.get(event.src_ip, (burst, now))
            tokens = min(burst, tokens + (now - updated) * self.config.per_source_per_second)
            if tokens < 1 or not self.rate.allow() or not self.types[event.event_type].allow():
                self.metrics['sampled'] += 1
                return False
            self.sources.set(event.src_ip, (tokens - 1, now))
            try:
                self.queue.put_nowait(serialize_event(event))
                self.metrics['queued'] += 1
                return True
            except queue.Full:
                self.metrics['dropped'] += 1
                return False

    def _run(self):
        while not self.cancel.is_set() or not self.queue.empty():
            try:
                line = self.queue.get(timeout=.05)
            except queue.Empty:
                continue
            try:
                if self.config.file and shutil.disk_usage(Path(self.config.file).parent).free < self.config.min_free_bytes:
                    self.metrics['disk_pressure_drops'] += 1
                    continue
                self.writer(line + '\n')
                self.metrics['written'] += 1
            except (OSError, ValueError):
                self.metrics['write_errors'] += 1
            finally:
                self.queue.task_done()
        if self.handler:
            self.handler.close()

    def close(self, timeout=2):
        self.cancel.set()
        if self.thread:
            self.thread.join(timeout)
        stalled = self.thread is not None and self.thread.is_alive()
        self.metrics['writer_stalled'] = int(stalled)
        return not stalled
