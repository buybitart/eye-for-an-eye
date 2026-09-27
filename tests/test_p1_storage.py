import json
from contextlib import closing
import sqlite3
import socket
import threading
import tempfile
import time
import unittest
from unittest.mock import patch
from pathlib import Path
from eye_for_an_eye.config import Config, StorageConfig
from eye_for_an_eye.events import NetworkEvent, EventPipeline
from eye_for_an_eye.logging import EventLogger
from eye_for_an_eye.runtime import EventRuntime
from eye_for_an_eye.storage.sqlite import SQLiteStore
from eye_for_an_eye.network.listeners import SelectorServer


class StorageTests(unittest.TestCase):
    def test_storage_close_failure_cannot_report_successful_shutdown(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Config()
            config.storage.enabled = True
            config.storage.path = str(Path(directory) / 'close.db')
            runtime = EventRuntime(config, logger=EventLogger(config.logging, writer=lambda line: None))
            close = SQLiteStore.close
            def failed_close(store):
                close(store)
                raise OSError('simulated checkpoint/close failure')
            with patch.object(SQLiteStore, 'close', failed_close):
                runtime.start()
                self.assertFalse(runtime.close())
            self.assertFalse(runtime.thread.is_alive())
            self.assertEqual(runtime.snapshot()['health']['status'], 'unavailable')
            self.assertEqual(runtime.metrics['storage_close_errors'], 1)

    def test_duplicate_id_is_immutable(self):
        with tempfile.TemporaryDirectory() as directory:
            config = StorageConfig(path=str(Path(directory) / 'retry.db'), max_events=1)
            store = SQLiteStore(config)
            store.open()
            try:
                event = NetworkEvent('192.0.2.1', observations={'original': True})
                store.write(event)
                event.observations['original'] = False
                store.write(event)
                encoded = store.connection.execute('SELECT event_json FROM events').fetchone()[0]
                self.assertTrue(json.loads(encoded)['observations']['original'])
                self.assertEqual(store.metrics['duplicates'], 1)
            finally:
                store.close()

    def test_pinned_wal_reader_cannot_break_disk_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            config = StorageConfig(path=str(Path(directory) / 'pinned.db'), max_bytes=1_048_576, busy_timeout=.001)
            store = SQLiteStore(config)
            store.open()
            store.write(NetworkEvent('192.0.2.1'))
            try:
                with closing(sqlite3.connect(config.path)) as reader:
                    reader.execute('BEGIN')
                    reader.execute('SELECT * FROM events').fetchall()
                    for _ in range(120):
                        store.write(NetworkEvent('192.0.2.1', observations={f'field{i}': 'x' * 100 for i in range(20)}))
                        self.assertLessEqual(store.disk_bytes(), config.max_bytes)
                    self.assertGreater(store.metrics['dropped'] + store.metrics['write_errors'], 0)
                    reader.rollback()
                store.maintenance()
                self.assertTrue(store.write(NetworkEvent('192.0.2.2')))
            finally:
                store.close()

    def test_listener_to_storage_without_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Config()
            config.storage.enabled = True
            config.storage.path = str(Path(directory) / 'listener.db')
            runtime = EventRuntime(config, logger=EventLogger(config.logging, writer=lambda line: None))
            pipeline = EventPipeline(runtime)
            def received(peer, destination, data):
                pipeline.record(NetworkEvent(peer[0], peer[1], destination[0], destination[1], 'tcp',
                    'service_probe', observations={'payload_preview_hex': data.hex(), 'payload_length': len(data)}))
                return b'OK'
            runtime.start()
            server = SelectorServer(config, on_data=received, port=0)
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                self.assertTrue(server.ready.wait(1))
                with socket.create_connection(server.address, timeout=1) as client:
                    client.sendall(b'Authorization: secret-credential')
                    self.assertEqual(client.recv(16), b'OK')
            finally:
                server.stop()
                thread.join(2)
                self.assertTrue(runtime.close())
            with closing(sqlite3.connect(config.storage.path)) as connection:
                encoded = connection.execute('SELECT event_json FROM events').fetchone()[0]
            self.assertNotIn('secret-credential', encoded)
            self.assertNotIn(b'secret-credential'.hex(), encoded)
            self.assertIn('payload_length', encoded)

    def test_single_writer_ownership_is_released_on_close(self):
        with tempfile.TemporaryDirectory() as directory:
            config = StorageConfig(path=str(Path(directory) / 'owned.db'))
            first, second = SQLiteStore(config), SQLiteStore(config)
            first.open()
            try:
                with self.assertRaises(RuntimeError):
                    second.open()
            finally:
                first.close()
            second.open()
            second.close()

    def test_migration_retention_restart_and_payload_redaction(self):
        with tempfile.TemporaryDirectory() as directory:
            config = StorageConfig(path=str(Path(directory) / 'events.db'), max_events=2, retention_seconds=10)
            now = [100.0]
            store = SQLiteStore(config, clock=lambda: now[0])
            store.open()
            for index in range(3):
                store.write(NetworkEvent('192.0.2.1', observations={'payload_preview_hex': '736563726574', 'index': index}))
            rows = store.connection.execute('SELECT event_json FROM events ORDER BY seq').fetchall()
            self.assertEqual([json.loads(row[0])['observations']['index'] for row in rows], [1, 2])
            self.assertNotIn('736563726574', str(rows))
            self.assertEqual(store.connection.execute('PRAGMA user_version').fetchone()[0], 2)
            store.close()
            store = SQLiteStore(config, clock=lambda: now[0])
            store.open()
            self.assertEqual(store.connection.execute('SELECT count(*) FROM events').fetchone()[0], 2)
            now[0] = 111
            store.maintenance()
            self.assertEqual(store.metrics['retained_events'], 0)
            store.close()

    def test_future_or_foreign_schema_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'foreign.db')
            with closing(sqlite3.connect(path)) as connection:
                connection.execute('CREATE TABLE foreign_data(value TEXT)')
                connection.execute('PRAGMA user_version=99')
            store = SQLiteStore(StorageConfig(path=path))
            with self.assertRaises(ValueError):
                store.open()
            with closing(sqlite3.connect(path)) as connection:
                self.assertEqual(connection.execute('PRAGMA user_version').fetchone()[0], 99)

    def test_disk_envelope_under_retention_pressure(self):
        with tempfile.TemporaryDirectory() as directory:
            config = StorageConfig(path=str(Path(directory) / 'bounded.db'), max_bytes=1_048_576)
            store = SQLiteStore(config)
            store.open()
            try:
                for index in range(150):
                    event = NetworkEvent('192.0.2.1', observations={f'field{i}': 'x' * 150 for i in range(18)})
                    store.write(event)
                    self.assertLessEqual(store.disk_bytes(), config.max_bytes)
                self.assertGreater(store.metrics['written'], 0)
                self.assertGreater(store.metrics['retention_deleted'], 0)
            finally:
                store.close()

    def test_runtime_failed_enrichment_keeps_base_event_and_drains(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Config()
            config.storage.enabled = True
            config.storage.path = str(Path(directory) / 'events.db')
            config.runtime.status_file = str(Path(directory) / 'health.json')
            runtime = EventRuntime(config, logger=EventLogger(config.logging, writer=lambda line: None))
            pipeline = EventPipeline(runtime)
            runtime.start()
            event = NetworkEvent('192.0.2.1')
            self.assertTrue(pipeline.record(event))
            pipeline.enriched(event.event_id, event.src_ip, {'status': 'unavailable', 'reason': 'timeout'})
            self.assertTrue(runtime.close())
            with closing(sqlite3.connect(config.storage.path)) as connection:
                rows = [json.loads(row[0]) for row in connection.execute('SELECT event_json FROM events ORDER BY seq')]
            self.assertEqual(rows[0]['event_id'], event.event_id)
            self.assertEqual(rows[1]['observations']['parent_event_id'], event.event_id)
            self.assertEqual(runtime.snapshot()['health']['status'], 'degraded')
            self.assertFalse(runtime.thread.is_alive())
            self.assertFalse(json.loads(Path(config.runtime.status_file).read_text())['running'])

    def test_queue_overflow_is_nonblocking_and_explicit(self):
        config = Config()
        config.runtime.queue_events = 1
        runtime = EventRuntime(config, logger=EventLogger(config.logging, writer=lambda line: None))
        started = time.monotonic()
        self.assertTrue(runtime.emit(NetworkEvent('192.0.2.1')))
        self.assertFalse(runtime.emit(NetworkEvent('192.0.2.2')))
        self.assertLess(time.monotonic() - started, .2)
        self.assertEqual(runtime.snapshot()['metrics']['events_dropped_total'], 1)
        runtime.start()
        self.assertTrue(runtime.close())
