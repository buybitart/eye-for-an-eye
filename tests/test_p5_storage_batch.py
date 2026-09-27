from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from eye_for_an_eye.config import Config
from eye_for_an_eye.events import NetworkEvent
from eye_for_an_eye.logging import EventLogger
from eye_for_an_eye.runtime import EventRuntime
from eye_for_an_eye.storage.sqlite import SQLiteStore


class BatchTests(unittest.TestCase):
    def config(self, directory):
        config = Config()
        config.storage.enabled = True
        config.storage.path = str(Path(directory) / 'batch.db')
        config.storage.max_batch_events = 8
        config.correlation.enabled = False
        config.decision.enabled = False
        return config

    def test_atomic_failure_duplicates_redaction_retention_and_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(directory)
            config.storage.max_events = 8
            store = SQLiteStore(config.storage)
            store.open()
            try:
                rows = [NetworkEvent('192.0.2.1', event_id=f'row-{i}', observations={'password': 'PRIVATE'}) for i in range(8)]
                store.connection.execute("CREATE TEMP TRIGGER fail BEFORE INSERT ON events WHEN NEW.event_id='row-3' BEGIN SELECT RAISE(ABORT,'fixture'); END")
                self.assertEqual(store.write_batch(rows), [False] * 8)
                self.assertEqual(store.connection.execute('SELECT count(*) FROM events').fetchone()[0], 0)
                store.connection.execute('DROP TRIGGER fail')
                self.assertEqual(store.write_batch(rows), [True] * 8)
                data = '\\n'.join(r[0] for r in store.connection.execute('SELECT event_json FROM events'))
                self.assertNotIn('PRIVATE', data)
                self.assertEqual(store.write_batch([rows[0], rows[0]]), [True, True])
                fresh = [NetworkEvent('192.0.2.2') for _ in range(8)]
                self.assertEqual(store.write_batch(fresh), [True] * 8)
                self.assertEqual(store.connection.execute('SELECT count(*) FROM events').fetchone()[0], 8)
                self.assertLessEqual(store.disk_bytes(), config.storage.max_bytes)
                with self.assertRaises(ValueError):
                    store.write_batch(rows + rows)
            finally:
                store.close()

    def test_partial_batch_flush_delay_and_shutdown(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(directory)
            runtime = EventRuntime(config, logger=EventLogger(config.logging, writer=lambda line: None))
            runtime.start()
            first = NetworkEvent('192.0.2.1')
            runtime.emit(first)
            deadline = time.monotonic() + 1
            while runtime.registry.snapshot()['storage_writes_total'] < 1 and time.monotonic() < deadline:
                time.sleep(.005)
            self.assertEqual(runtime.registry.snapshot()['storage_writes_total'], 1)
            for _ in range(19):
                runtime.emit(NetworkEvent('192.0.2.2'))
            self.assertTrue(runtime.close())
            self.assertEqual(runtime.registry.snapshot()['storage_writes_total'], 20)
            self.assertLess(runtime.registry.snapshot()['storage_batches_total'], 20)
            self.assertEqual(runtime.pending, [])
            with closing(sqlite3.connect(config.storage.path)) as reader:
                self.assertEqual(reader.execute('SELECT count(*) FROM events').fetchone()[0], 20)
                self.assertEqual(json.loads(reader.execute('SELECT event_json FROM events WHERE event_id=?', (first.event_id,)).fetchone()[0])['event_id'], first.event_id)

    def test_batch_configuration_caps(self):
        for count, delay in ((33, 10), (8, 51), (0, 10)):
            config = Config()
            config.storage.max_batch_events, config.storage.max_batch_delay_ms = count, delay
            with self.assertRaises(ValueError):
                config.validate()

    def test_batch_disk_backpressure_preserves_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(directory)
            store = SQLiteStore(config.storage)
            store.open()
            try:
                existing = NetworkEvent('192.0.2.1')
                self.assertTrue(store.write(existing))
                store._space_for_transaction = lambda: False
                self.assertEqual(store.write_batch([existing, NetworkEvent('192.0.2.2')]), [True, False])
                self.assertEqual(store.status, 'degraded')
                self.assertEqual(store.connection.execute('SELECT count(*) FROM events').fetchone()[0], 1)
                self.assertFalse(store.connection.in_transaction)
            finally:
                store.close()
