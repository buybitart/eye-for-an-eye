import os
from contextlib import closing
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from eye_for_an_eye.config import Config
from eye_for_an_eye.deception.engine import DeceptionEngine
from eye_for_an_eye.events import NetworkEvent
from eye_for_an_eye.logging import EventLogger
from eye_for_an_eye.runtime import EventRuntime
from eye_for_an_eye.storage.sqlite import SQLiteStore


class PersistenceTests(unittest.TestCase):
    def test_credential_attempts_persist_without_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Config()
            config.storage.enabled = True
            config.storage.path = str(Path(directory) / 'private.sqlite3')
            config.deception.port_profiles = {'1234': 'ftp'}
            config.deception.username_policy = 'hash'
            config.deception.preview_enabled = True
            runtime = EventRuntime(config, logger=EventLogger(config.logging, writer=lambda line: None))
            runtime.start()
            try:
                engine = DeceptionEngine(config, bytes(range(32)), runtime, load=runtime.deception_load)
                value = engine.open(('127.0.0.1', 32100), ('127.0.0.1', 1234))
                value.sent_bytes(len(value.start()))
                for command in (b'USER PRIVATE_USER\r\n', b'PASS PRIVATE_PASSWORD\r\n', b'QUIT\r\n'):
                    value.sent_bytes(len(value.feed(command)))
                value.close('test')
            finally:
                self.assertTrue(runtime.close())
            with closing(sqlite3.connect(config.storage.path)) as reader:
                rows = [row[0] for row in reader.execute('SELECT event_json FROM events')]
            data = '\n'.join(rows)
            self.assertIn('"event_type":"credential_attempt"', data)
            self.assertIn('username_hash', data)
            for value in ('PRIVATE_USER', 'PRIVATE_PASSWORD'):
                self.assertNotIn(value, data)
                self.assertNotIn(value.encode(), Path(config.storage.path).read_bytes())

    def test_real_writer_stall_changes_load_and_shuts_down(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Config()
            config.storage.enabled = True
            config.storage.path = str(Path(directory) / 'slow.sqlite3')
            runtime = EventRuntime(config, logger=EventLogger(config.logging, writer=lambda line: None))
            entered, release = threading.Event(), threading.Event()
            original = SQLiteStore.write
            def slow(store, event):
                entered.set()
                if not release.wait(1):
                    raise RuntimeError('finite test writer watchdog')
                return original(store, event)
            with patch.object(SQLiteStore, 'write', slow):
                runtime.start()
                try:
                    runtime.emit(NetworkEvent('127.0.0.1'))
                    self.assertTrue(entered.wait(1))
                    time.sleep(.12)
                    self.assertEqual(runtime.deception_load()['pressure'], 1.)
                    engine = DeceptionEngine(config, bytes(range(32)), runtime, load=runtime.deception_load)
                    value = engine.open(('127.0.0.1', 32100), ('127.0.0.1', 1234))
                    self.assertEqual(value.start(), b'')
                    value.close('test')
                finally:
                    release.set()
                    self.assertTrue(runtime.close())
            self.assertFalse(runtime.thread.is_alive())

    def test_actual_services_cli_restart_preserves_banner(self):
        with tempfile.TemporaryDirectory() as directory:
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            config = Path(directory) / 'sensor.toml'
            config.write_text(f'[deception]\nport_profiles={{"{port}"="ftp"}}\n', encoding='utf-8')
            env = os.environ.copy()
            env['EYE_FOR_AN_EYE_SECRET'] = bytes(range(32)).hex()
            banners = []
            for _ in range(2):
                process = subprocess.Popen([sys.executable, '-B', '-m', 'eye_for_an_eye', 'services', str(port),
                    'tcp', '--config', str(config)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                try:
                    deadline = time.monotonic() + 3
                    while True:
                        try:
                            client = socket.create_connection(('127.0.0.1', port), timeout=.3)
                            break
                        except OSError:
                            if time.monotonic() >= deadline or process.poll() is not None:
                                self.fail('CLI did not start in watchdog budget')
                            time.sleep(.03)
                    with client:
                        client.settimeout(1)
                        banners.append(client.recv(1024))
                        client.sendall(b'QUIT\r\n')
                        self.assertEqual(client.recv(1024), b'221 Goodbye\r\n')
                finally:
                    process.terminate()
                    try:
                        process.communicate(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate(timeout=2)
                        self.fail('CLI process did not terminate')
            self.assertEqual(banners[0], b'220 FTP service ready\r\n')
            self.assertEqual(banners[0], banners[1])
