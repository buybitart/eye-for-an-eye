"""SQLite WAL with migrations, retention and a conservative DB/WAL disk envelope."""
from collections import Counter
import sqlite3
import json
import os
from pathlib import Path
import threading
import time
from .locking import WriterLease
from ..events import NetworkEvent

APPLICATION_ID = 0x45344559
SCHEMA_VERSION = 2


class SQLiteStore:
    def __init__(self, config, *, clock=time.time):
        self.config, self.clock = config, clock
        self.connection = None
        self.owner = None
        self.metrics = Counter()
        self.status = 'unavailable'
        self.error = None
        self.page_limit = (config.max_bytes - 65536) // (3 * 4096)
        self.lease = WriterLease(config.path + '.lock')
        self.pressure = 'NORMAL'
        self.next_cleanup = 0.0

    def open(self, *, before_migration=None, maintenance=True):
        if self.connection is not None:
            raise RuntimeError('storage is already open')
        self.owner = threading.get_ident()
        self.lease.acquire()
        try:
            try:
                descriptor = os.open(self.config.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass  # Never chmod an existing operator-owned database.
            else:
                os.close(descriptor)
            connection = sqlite3.connect(self.config.path, timeout=self.config.busy_timeout, isolation_level=None)
        except (sqlite3.Error, OSError):
            self.lease.close()
            raise
        self.connection = connection
        try:
            version = connection.execute('PRAGMA user_version').fetchone()[0]
            app_id = connection.execute('PRAGMA application_id').fetchone()[0]
            tables = connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            if version > SCHEMA_VERSION or (tables and app_id != APPLICATION_ID):
                raise ValueError('unsupported or foreign database; storage was not migrated')
            connection.execute('PRAGMA page_size=4096')
            page_size = connection.execute('PRAGMA page_size').fetchone()[0]
            if page_size != 4096:
                raise ValueError('storage requires 4096-byte pages')
            actual = connection.execute(f'PRAGMA max_page_count={self.page_limit}').fetchone()[0]
            if actual > self.page_limit:
                raise ValueError('existing database exceeds the main-file budget')
            connection.execute('PRAGMA auto_vacuum=INCREMENTAL')
            if connection.execute('PRAGMA journal_mode=WAL').fetchone()[0] != 'wal':
                raise ValueError('WAL could not be enabled')
            connection.execute('PRAGMA synchronous=FULL')
            # Keep dirty pages until commit so the WAL reserve covers one write per page.
            connection.execute('PRAGMA cache_spill=OFF')
            connection.execute('PRAGMA wal_autocheckpoint=16')
            connection.execute('PRAGMA journal_size_limit=65536')
            if version == 0:
                connection.executescript(f'''
                    BEGIN IMMEDIATE;
                    CREATE TABLE events (
                        seq INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE,
                        ingested_at REAL NOT NULL, sensor_id TEXT NOT NULL,
                        event_type TEXT NOT NULL, event_json TEXT NOT NULL CHECK(length(event_json)<=4096));
                    CREATE INDEX event_age ON events(ingested_at);
                    CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at REAL NOT NULL);
                    INSERT INTO schema_migrations VALUES(1, CAST(strftime('%s','now') AS REAL));
                    PRAGMA application_id={APPLICATION_ID};
                    PRAGMA user_version=1;
                    COMMIT;
                ''')
            if version < 2:
                if version == 1 and before_migration is not None:
                    # Writer lease is already held; backup and migration cannot race another cooperating writer.
                    before_migration(connection)
                self._migrate_v2()
            self.status = 'healthy'
            if maintenance:
                self.maintenance()
        except Exception:
            connection.close()
            self.connection = None
            self.lease.close()
            raise

    def _migrate_v2(self):
        connection = self.connection
        deadline = time.monotonic() + 10
        connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        try:
            connection.execute('BEGIN IMMEDIATE')
            for name, kind in (('observed_at', 'REAL'), ('src_ip', 'TEXT'), ('src_port', 'INTEGER'),
                               ('dst_ip', 'TEXT'), ('dst_port', 'INTEGER'), ('transport', 'TEXT'),
                               ('classification', 'TEXT'), ('confidence', 'TEXT')):
                connection.execute(f'ALTER TABLE events ADD COLUMN {name} {kind}')
            sequence = 0
            while True:
                rows = connection.execute('SELECT seq,event_json FROM events WHERE seq>? ORDER BY seq LIMIT 256', (sequence,)).fetchall()
                if not rows:
                    break
                for sequence, encoded in rows:
                    event = NetworkEvent.from_json(encoded)
                    connection.execute('UPDATE events SET observed_at=?,src_ip=?,src_port=?,dst_ip=?,dst_port=?,'
                        'transport=?,classification=?,confidence=? WHERE seq=?', (*self._columns(event), sequence))
            for name, fields in (('event_time', 'observed_at,seq'), ('event_kind', 'event_type,observed_at,seq'),
                                  ('event_source', 'src_ip,observed_at,seq'), ('event_class', 'classification,observed_at,seq'),
                                  ('event_port', 'dst_port,observed_at,seq')):
                connection.execute(f'CREATE INDEX {name} ON events({fields})')
            connection.execute('INSERT INTO schema_migrations VALUES(2,?)', (self.clock(),))
            connection.execute('PRAGMA user_version=2')
            connection.execute('COMMIT')
        except (sqlite3.Error, ValueError):
            connection.set_progress_handler(None, 0)
            if connection.in_transaction:
                connection.execute('ROLLBACK')
            raise
        finally:
            connection.set_progress_handler(None, 0)

    @staticmethod
    def _columns(event):
        return (event.timestamp.timestamp(), event.src_ip, event.src_port, event.dst_ip, event.dst_port,
                event.transport, event.classification, event.confidence)

    def _cleanup(self, target):
        removed = self.connection.execute('DELETE FROM events WHERE seq IN '
            '(SELECT seq FROM events WHERE ingested_at < ? ORDER BY ingested_at LIMIT ?)',
            (self.clock() - self.config.retention_seconds, self.config.cleanup_batch)).rowcount
        count = self.connection.execute('SELECT count(*) FROM events').fetchone()[0]
        if count > target:
            removed += self.connection.execute('DELETE FROM events WHERE seq IN '
                '(SELECT seq FROM events ORDER BY seq LIMIT ?)',
                (min(self.config.cleanup_batch, count - target),)).rowcount
        return removed

    def _check_owner(self):
        if self.connection is None or self.owner != threading.get_ident():
            raise RuntimeError('storage operations require the owner writer thread')

    def disk_bytes(self):
        total = 0
        for suffix in ('', '-wal', '-shm'):
            try:
                total += Path(self.config.path + suffix).stat().st_size
            except FileNotFoundError:
                pass
        return total

    def _space_for_transaction(self):
        # Reserve enough for rewriting every page once plus WAL/SHM overhead.
        reserve = self.page_limit * (4096 + 24) + 65536
        return self.disk_bytes() + reserve <= self.config.max_bytes

    def write(self, event):
        self._check_owner()
        data = event.to_json()  # Payload/credential fields are removed at serialization.
        try:
            fraction = self.disk_bytes() / self.config.max_bytes
            self.pressure = ('CRITICAL' if fraction >= self.config.pressure_critical else
                             'WARNING' if fraction >= self.config.pressure_warning else 'NORMAL')
            if self.pressure == 'CRITICAL':
                record = json.loads(data)
                record.update(observations={'minimal_metadata': True}, enrichment={}, deception={},
                              limitations=['storage_pressure_minimal_metadata'])
                data = json.dumps(record, separators=(',', ':'))
                self.metrics['minimal_events'] += 1
            if self.connection.execute('SELECT 1 FROM events WHERE event_id=?', (event.event_id,)).fetchone():
                self.metrics['duplicates'] += 1
                return True
            self.connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            if not self._space_for_transaction():
                self.status, self.error = 'degraded', 'disk_budget_or_pinned_wal'
                self.metrics['dropped'] += 1
                return False
            self.connection.execute('BEGIN IMMEDIATE')
            removed = self._cleanup(max(0, self.config.max_events - 1))
            count = self.connection.execute('SELECT count(*) FROM events').fetchone()[0]
            if count >= self.config.max_events:
                self.connection.execute('COMMIT')
                self.metrics['dropped'] += 1
                self.status, self.error = 'degraded', 'retention_backlog'
                return False
            self.connection.execute('INSERT OR IGNORE INTO events(event_id,ingested_at,sensor_id,event_type,event_json,'
                'observed_at,src_ip,src_port,dst_ip,dst_port,transport,classification,confidence) '
                'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (event.event_id, self.clock(), event.sensor_id, event.event_type, data, *self._columns(NetworkEvent.from_json(data))))
            self.connection.execute('COMMIT')
            self.metrics['retention_deleted'] += removed
            self.metrics['written'] += 1
            self.metrics['retained_events'] = count + 1
            self.connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            self.metrics['disk_bytes'] = self.disk_bytes()
            self.status, self.error = ('healthy', None) if self.pressure == 'NORMAL' else ('degraded', 'storage_pressure')
            return True
        except sqlite3.Error as exc:
            if self.connection.in_transaction:
                self.connection.execute('ROLLBACK')
            self.metrics['write_errors'] += 1
            self.status, self.error = 'degraded', type(exc).__name__
            if getattr(exc, 'sqlite_errorcode', None) == sqlite3.SQLITE_FULL and self._space_for_transaction():
                # Make space for subsequent events; this failed event remains an explicit drop.
                count = self.connection.execute('SELECT count(*) FROM events').fetchone()[0]
                removed = self.connection.execute('DELETE FROM events WHERE seq IN '
                    '(SELECT seq FROM events ORDER BY seq LIMIT ?)', (min(self.config.cleanup_batch, max(1, count // 4)),)).rowcount
                self.metrics['retention_deleted'] += removed
                self.connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            return False

    def write_batch(self, events):
        """One bounded transaction; bool per input, duplicate IDs stay immutable."""
        self._check_owner()
        if not 1 <= len(events) <= self.config.max_batch_events:
            raise ValueError('batch exceeds configured bound')
        if len(events) == 1:
            return [self.write(events[0])]
        prepared = []
        for event in events:
            data = event.to_json()
            prepared.append((NetworkEvent.from_json(data), data))
        outcomes = [False] * len(events)
        pending, seen = [], set()
        try:
            fraction = self.disk_bytes() / self.config.max_bytes
            self.pressure = ('CRITICAL' if fraction >= self.config.pressure_critical else
                             'WARNING' if fraction >= self.config.pressure_warning else 'NORMAL')
            placeholders = ','.join('?' for _ in events)
            existing = {row[0] for row in self.connection.execute(
                f'SELECT event_id FROM events WHERE event_id IN ({placeholders})', [item.event_id for item, _ in prepared])}
            duplicates = []
            for index, (event, data) in enumerate(prepared):
                if event.event_id in existing:
                    outcomes[index] = True
                    self.metrics['duplicates'] += 1
                    continue
                if event.event_id in seen:
                    duplicates.append(index)
                    continue
                seen.add(event.event_id)
                if self.pressure == 'CRITICAL':
                    record = json.loads(data)
                    record.update(observations={'minimal_metadata': True}, enrichment={}, deception={},
                                  limitations=['storage_pressure_minimal_metadata'])
                    data = json.dumps(record, separators=(',', ':'))
                    self.metrics['minimal_events'] += 1
                pending.append((index, event, data))
            if not pending:
                return outcomes
            self.connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            if not self._space_for_transaction():
                self.status, self.error = 'degraded', 'disk_budget_or_pinned_wal'
                self.metrics['dropped'] += sum(not value for value in outcomes)
                return outcomes
            self.connection.execute('BEGIN IMMEDIATE')
            removed = self._cleanup(self.config.max_events - len(pending))
            count = self.connection.execute('SELECT count(*) FROM events').fetchone()[0]
            if count + len(pending) > self.config.max_events:
                self.connection.execute('COMMIT')
                self.metrics['retention_deleted'] += removed
                self.metrics['dropped'] += sum(not value for value in outcomes)
                self.status, self.error = 'degraded', 'retention_backlog'
                return outcomes
            for _, event, data in pending:
                self.connection.execute('INSERT INTO events(event_id,ingested_at,sensor_id,event_type,event_json,'
                    'observed_at,src_ip,src_port,dst_ip,dst_port,transport,classification,confidence) '
                    'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (event.event_id, self.clock(), event.sensor_id, event.event_type, data, *self._columns(event)))
            self.connection.execute('COMMIT')
            for index, _, _ in pending:
                outcomes[index] = True
            for index in duplicates:
                outcomes[index] = True
            self.metrics['duplicates'] += len(duplicates)
            self.metrics['written'] += len(pending)
            self.metrics['batches'] += 1
            self.metrics['retention_deleted'] += removed
            self.metrics['retained_events'] = count + len(pending)
            self.status, self.error = ('healthy', None) if self.pressure == 'NORMAL' else ('degraded', 'storage_pressure')
            self.connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            self.metrics['disk_bytes'] = self.disk_bytes()
            return outcomes
        except sqlite3.Error as exc:
            if self.connection.in_transaction:
                self.connection.execute('ROLLBACK')
            self.metrics['write_errors'] += 1
            self.status, self.error = 'degraded', type(exc).__name__
            if getattr(exc, 'sqlite_errorcode', None) == sqlite3.SQLITE_FULL and self._space_for_transaction():
                try:
                    removed = self.connection.execute('DELETE FROM events WHERE seq IN '
                        '(SELECT seq FROM events ORDER BY seq LIMIT ?)', (self.config.cleanup_batch,)).rowcount
                    self.metrics['retention_deleted'] += removed
                    self.connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                except sqlite3.Error:
                    self.metrics['maintenance_errors'] += 1
            return outcomes

    def maintenance(self):
        self._check_owner()
        try:
            self.connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            if self._space_for_transaction():
                removed = self._cleanup(self.config.max_events)
                self.metrics['retention_deleted'] += removed
                # Retention and vacuum are separate transactions; a pinned reader may
                # prevent reclaiming the first one's WAL, so reserve again for vacuum.
                self.connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                if self._space_for_transaction():
                    self.connection.execute('PRAGMA incremental_vacuum(16)')
                self.connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            self.metrics['retained_events'] = self.connection.execute('SELECT count(*) FROM events').fetchone()[0]
            self.metrics['disk_bytes'] = self.disk_bytes()
        except sqlite3.Error as exc:
            self.status, self.error = 'degraded', type(exc).__name__
            self.metrics['maintenance_errors'] += 1

    def close(self):
        if self.connection is not None:
            self._check_owner()
            try:
                self.connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            finally:
                self.connection.close()
                self.connection = None
                self.lease.close()
