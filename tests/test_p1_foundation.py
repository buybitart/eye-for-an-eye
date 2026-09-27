import contextlib
from dataclasses import asdict
import io
import json
import os
from pathlib import Path
import queue
import tempfile
import time
import unittest
from unittest.mock import patch
from eye_for_an_eye.cli import _parser, _settings, main
from eye_for_an_eye.config import load_config
from eye_for_an_eye.events import NetworkEvent
from eye_for_an_eye.queues import BoundedQueue
from eye_for_an_eye.observability.metrics import Metrics, health
from eye_for_an_eye.security.secrets import load_secret


class FoundationTests(unittest.TestCase):
    def test_mounted_secret_precedence_and_reference_redaction(self):
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / 'mounted.secret'
            secret.write_bytes(b'mounted-fixture-' * 3)
            secret.chmod(0o600)
            path = Path(directory) / 'settings.toml'
            path.write_text('[deception]\nsecret_file="mounted.secret"\n', encoding='utf-8')
            with patch.dict(os.environ, {'EYE_FOR_AN_EYE_SECRET': 'ab' * 32}, clear=True):
                config = load_config(path)
                self.assertEqual(load_secret(config), secret.read_bytes())
                output = io.StringIO()
                with patch.object(Path, 'open', side_effect=AssertionError('secret content read')), contextlib.redirect_stdout(output):
                    # ENV reference avoids opening a TOML file during this check.
                    with patch.dict(os.environ, {'E4E__DECEPTION__SECRET_FILE': str(secret)}):
                        self.assertEqual(main(['config', 'show', '--json']), 0)
                self.assertNotIn('mounted', output.getvalue())
                self.assertNotIn('ab' * 32, output.getvalue())
                self.assertEqual(json.loads(output.getvalue())['configuration']['deception']['secret_file'], '********')

    def test_health_cli_rejects_stale_and_stopped_snapshots(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'status.json'
            record = {'running': True, 'health': {'status': 'degraded'}, 'metrics': {'queue_depth': 0}}
            path.write_text(json.dumps(record), encoding='utf-8')
            args = ['--status-file', str(path)]
            with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()), patch('sqlite3.connect', side_effect=AssertionError('database')):
                self.assertEqual(main(['health', *args]), 0)
                self.assertEqual(main(['metrics', *args]), 0)
                old = time.time() - 10
                os.utime(path, (old, old))
                self.assertEqual(main(['health', *args]), 1)
                record['running'] = False
                path.write_text(json.dumps(record), encoding='utf-8')
                self.assertEqual(main(['health', *args]), 1)

    def test_config_precedence_and_boolean_cli_disable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'settings.toml'
            path.write_text('[network]\nport=1235\n[enrichment]\nenabled=true\n', encoding='utf-8')
            with patch.dict(os.environ, {'E4E__NETWORK__PORT': '1236'}, clear=True):
                self.assertEqual(load_config(path).network.port, 1236)
                settings = _settings(_parser('proto').parse_args(['1237', '--config', str(path), '--no-enrichment']))
                self.assertEqual(settings.network.port, 1237)
                self.assertFalse(settings.enrichment.enabled)
            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(load_config(path).network.port, 1235)

    def test_config_show_redacts_secret_and_opens_no_runtime(self):
        output = io.StringIO()
        with patch.dict(os.environ, {'EYE_FOR_AN_EYE_SECRET': 'ab' * 32}, clear=True), \
                patch('socket.socket', side_effect=AssertionError('socket')), \
                patch('sqlite3.connect', side_effect=AssertionError('database')), \
                patch('threading.Thread.start', side_effect=AssertionError('worker')), contextlib.redirect_stdout(output):
            self.assertEqual(main(['config', 'show', '--json']), 0)
            self.assertEqual(main(['config', 'validate', '--json']), 0)
        self.assertNotIn('ab' * 32, output.getvalue())
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(records[0]['configuration']['deception']['secret'], '********')
        self.assertEqual(records[1]['status'], 'valid')

    def test_unknown_environment_config_fails(self):
        with self.assertRaises(ValueError):
            load_config(environ={'E4E__UNKNOWN': '1'})

    def test_event_round_trip_legacy_and_privacy(self):
        event = NetworkEvent('192.0.2.1', sensor_id='lab-1', limitations=['synthetic'], observations={'ttl': 61})
        self.assertEqual(asdict(NetworkEvent.from_json(event.to_json())), asdict(event))
        record = event.to_dict()
        record['schema_version'] = 1
        record.pop('sensor_id')
        legacy = NetworkEvent.from_json(json.dumps(record))
        self.assertIn('legacy_schema_v1', legacy.limitations)
        event.observations = {'payload_preview_hex': b'secret'.hex(), 'password': 'secret', 'ttl': 61}
        self.assertNotIn('secret', event.to_json())
        self.assertNotIn(b'secret'.hex(), event.to_json())
        for value in ('{}', '{"schema_version":99}', '[' * 4000, 'x' * 4097):
            with self.subTest(value=value[:24]), self.assertRaises(ValueError):
                NetworkEvent.from_json(value)

    def test_queue_both_budgets_and_explicit_drop_newest(self):
        q = BoundedQueue(2, 5)
        self.assertTrue(q.put('first', 3))
        self.assertFalse(q.put('too many bytes', 3))
        self.assertTrue(q.put('second', 2))
        self.assertFalse(q.put('too many events', 0))
        self.assertEqual(q.get(), 'first')
        self.assertEqual(q.snapshot()['bytes'], 2)
        q.close()
        self.assertFalse(q.put('closed', 1))
        self.assertEqual(q.get(), 'second')
        with self.assertRaises(queue.Empty):
            q.get()
        self.assertEqual(q.snapshot()['dropped'], 3)

    def test_health_and_fixed_cardinality_metrics(self):
        metrics = Metrics()
        metrics.inc('events_created_total')
        self.assertEqual(metrics.snapshot()['events_created_total'], 1)
        with self.assertRaises(ValueError):
            metrics.inc('src_ip=192.0.2.1')
        self.assertEqual(health({'capture': 'healthy', 'storage': 'healthy', 'enrichment': 'unavailable'})['status'], 'degraded')
        self.assertEqual(health({'storage': 'unavailable'})['status'], 'unavailable')
