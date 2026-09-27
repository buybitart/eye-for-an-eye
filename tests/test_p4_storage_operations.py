from contextlib import closing, redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from eye_for_an_eye.config import Config
from eye_for_an_eye.events import NetworkEvent
from eye_for_an_eye.event_types import EventType
from eye_for_an_eye.logging import EventLogger
from eye_for_an_eye.operations import main, export_events
from eye_for_an_eye.runtime import EventRuntime
from eye_for_an_eye.storage.operations import backup, storage_info
from eye_for_an_eye.storage.reader import Query, Reader
from eye_for_an_eye.storage.sqlite import APPLICATION_ID, SQLiteStore


class P4StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = Config()
        self.config.storage.enabled = True
        self.config.storage.path = str(Path(self.temp.name) / 'events.db')
        self.reader = Reader(self.config.storage.path, self.config.api)

    def old_database(self, bad=False):
        event = json.loads(NetworkEvent('192.0.2.1').to_json())
        event['schema_version'] = 2
        for key in ('classification', 'confidence', 'deception'):
            event.pop(key)
        with closing(sqlite3.connect(self.config.storage.path)) as connection:
            connection.executescript(f'''CREATE TABLE events(seq INTEGER PRIMARY KEY,event_id TEXT UNIQUE,ingested_at REAL,
                sensor_id TEXT,event_type TEXT,event_json TEXT);
                CREATE INDEX event_age ON events(ingested_at);
                CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,applied_at REAL);
                INSERT INTO schema_migrations VALUES(1,0);
                PRAGMA application_id={APPLICATION_ID}; PRAGMA user_version=1;''')
            connection.execute('INSERT INTO events VALUES(1,?,?,?,?,?)',
                (event['event_id'], time.time(), 'local', event['event_type'], 'bad-json' if bad else json.dumps(event)))
            connection.commit()

    def test_transactional_v1_migration_and_reopen(self):
        self.old_database()
        for _ in range(2):
            store = SQLiteStore(self.config.storage)
            store.open()
            try:
                info = storage_info(self.reader)
                self.assertEqual(info['user_version'], 2)
                self.assertEqual(info['events'], 1)
                rows, _ = self.reader.events(Query.parse({}, self.config.api))
                self.assertEqual(rows[0][1].schema_version, 3)
                indexes = {row[1] for row in store.connection.execute('PRAGMA index_list(events)')}
                self.assertTrue({'event_time', 'event_kind', 'event_source', 'event_class', 'event_port'} <= indexes)
            finally:
                store.close()

    def test_failed_migration_rolls_back_without_destroying_data(self):
        self.old_database(bad=True)
        with self.assertRaises(ValueError):
            SQLiteStore(self.config.storage).open()
        with closing(sqlite3.connect(self.config.storage.path)) as connection:
            self.assertEqual(connection.execute('PRAGMA user_version').fetchone()[0], 1)
            self.assertEqual(connection.execute('SELECT event_json FROM events').fetchone()[0], 'bad-json')
            self.assertNotIn('observed_at', {row[1] for row in connection.execute('PRAGMA table_info(events)')})

    def test_incremental_retention_critical_metadata_and_wal_backup(self):
        self.config.storage.cleanup_batch = 2
        clock = [time.time()]
        store = SQLiteStore(self.config.storage, clock=lambda: clock[0])
        store.open()
        try:
            for _ in range(12):
                self.assertTrue(store.write(NetworkEvent('192.0.2.1')))
            self.config.storage.pressure_warning = .00001
            self.config.storage.pressure_critical = .00002
            event = NetworkEvent('192.0.2.2', event_type=EventType.CORRELATION_RESULT,
                observations={'optional_detail': 'value'}, hypotheses={'behavior': {'classification': 'scanner', 'confidence': 'LOW'}})
            self.assertTrue(store.write(event))
            self.assertEqual(store.pressure, 'CRITICAL')
            saved = self.reader.event(event.event_id)
            self.assertEqual(saved.classification, 'scanner')
            self.assertNotIn('optional_detail', saved.observations)
            target = Path(self.temp.name) / 'backup.db'
            result = backup(self.reader, target, max_bytes=self.config.storage.max_bytes)
            self.assertEqual(result['status'], 'complete')
            with closing(sqlite3.connect(target)) as check:
                self.assertEqual(check.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
                self.assertEqual(check.execute('SELECT count(*) FROM events').fetchone()[0], 13)
            with self.assertRaises(FileExistsError):
                backup(self.reader, target, max_bytes=self.config.storage.max_bytes)
            failed = Path(self.temp.name) / 'failed.db'
            with self.assertRaises(TimeoutError):
                backup(self.reader, failed, max_bytes=1)
            self.assertFalse(failed.exists())
            clock[0] += self.config.storage.retention_seconds + 1
            before = storage_info(self.reader)['events']
            store.maintenance()
            self.assertEqual(before - storage_info(self.reader)['events'], 2)
        finally:
            store.close()

    def test_multiple_readers_with_single_writer_and_backup(self):
        store = SQLiteStore(self.config.storage)
        store.open()
        failures = []
        def read(index):
            try:
                for _ in range(20):
                    self.reader.events(Query.parse({}, self.config.api))
                backup(self.reader, Path(self.temp.name) / f'copy-{index}.db', max_bytes=self.config.storage.max_bytes)
            except (sqlite3.Error, OSError, ValueError) as exc:
                failures.append(type(exc).__name__)
        readers = [threading.Thread(target=read, args=(i,)) for i in range(2)]
        try:
            for reader in readers:
                reader.start()
            for _ in range(30):
                self.assertTrue(store.write(NetworkEvent('192.0.2.1')))
            for reader in readers:
                reader.join(5)
                self.assertFalse(reader.is_alive())
            self.assertEqual(failures, [])
            self.assertEqual(storage_info(self.reader)['events'], 30)
        finally:
            for reader in readers:
                reader.join(5)
            store.close()

    def test_failed_storage_open_uses_bounded_fallback(self):
        config = self.config
        config.correlation.enabled = False
        config.decision.enabled = False
        runtime = EventRuntime(config, logger=EventLogger(config.logging, writer=lambda line: None))
        with patch.object(SQLiteStore, 'open', side_effect=sqlite3.OperationalError('finite simulated failure')):
            runtime.start()
            for _ in range(300):
                runtime.emit(NetworkEvent('192.0.2.1'))
            self.assertTrue(runtime.close())
        self.assertEqual(len(runtime.fallback), 256)
        self.assertEqual(runtime.registry.snapshot()['storage_write_failures_total'], 300)
        self.assertTrue(all('bounded_volatile_storage_fallback' in value for value in runtime.fallback))

    def test_cli_diagnostics_status_and_exports(self):
        store = SQLiteStore(self.config.storage)
        store.open()
        try:
            store.write(NetworkEvent('192.0.2.1', event_id='=formula', observations={'password': 'PRIVATE'}))
            config_file = Path(self.temp.name) / 'config.toml'
            # The absolute path of the database this test just wrote to, rather
            # than the bare name. `path="events.db"` resolves against the working
            # directory, so this asserted that `doctor` exits 0 while pointing it
            # at a database that existed only when some earlier test had left an
            # `events.db` in the repository root. It passed in a full suite run,
            # failed on its own, and failed in a clean clone — which is what a
            # clean clone is for.
            config_file.write_text(
                '[storage]\nenabled=true\npath='
                + json.dumps(self.config.storage.path) + '\n', encoding='utf-8')
            for command, args in (('doctor', []), ('version', []), ('stats', []), ('events', ['tail']), ('storage', ['info'])):
                output = io.StringIO()
                with redirect_stdout(output), redirect_stderr(io.StringIO()):
                    code = main(command, args + ['--config', str(config_file)])
                # An unconfigured optional model is a normal state, not a degraded one.
                self.assertEqual(code, 0, command)
                self.assertNotIn('PRIVATE', output.getvalue())
                if command == 'doctor':
                    self.assertIn('NOT_CONFIGURED', output.getvalue())
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main('status', ['--config', str(config_file)]), 1)
            query = Query.parse({}, self.config.api)
            for format in ('csv', 'jsonl'):
                target = Path(self.temp.name) / ('export.' + format)
                result = export_events(self.reader, query, target, format=format, max_bytes=65536, redact_ip=True)
                text = target.read_text()
                self.assertEqual(result['records'], 1)
                self.assertNotIn('PRIVATE', text)
                self.assertNotIn('192.0.2.1', text)
                if format == 'csv':
                    self.assertIn("'=formula", text)
                with self.assertRaises(FileExistsError):
                    export_events(self.reader, query, target, format=format, max_bytes=65536)
            with self.assertRaises(ValueError):
                export_events(self.reader, query, Path(self.temp.name) / 'too-large', format='jsonl', max_bytes=1)
        finally:
            store.close()
