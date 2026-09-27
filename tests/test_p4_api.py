from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import socket
import sqlite3
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from eye_for_an_eye.api.models import ip_projection
from eye_for_an_eye.api.server import Endpoint, ReadOnlyAPI
from eye_for_an_eye.config import Config
from eye_for_an_eye.events import NetworkEvent
from eye_for_an_eye.event_types import EventType
from eye_for_an_eye.logging import EventLogger
from eye_for_an_eye.observability.metrics import Metrics
from eye_for_an_eye.observability.health import operational_health
from eye_for_an_eye.runtime import EventRuntime
from eye_for_an_eye.storage.reader import Query, Reader
from eye_for_an_eye.storage.sqlite import SQLiteStore


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def request(port, path, *, method='GET', headers=''):
    with socket.create_connection(('127.0.0.1', port), timeout=2) as sock:
        sock.sendall(f'{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{headers}\r\n'.encode())
        result = bytearray()
        while len(result) < 70000:
            chunk = sock.recv(8192)
            if not chunk:
                break
            result.extend(chunk)
    head, _, body = bytes(result).partition(b'\r\n\r\n')
    return int(head.split(b' ')[1]), body


class APITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = Config()
        self.config.storage.enabled = True
        self.config.storage.path = str(Path(self.temp.name) / 'api.db')
        self.config.api.requests_per_second = 1000
        self.config.api.max_page_size = 4
        self.store = SQLiteStore(self.config.storage)
        self.store.open()
        self.addCleanup(self.store.close)
        self.ids = []
        for index in range(10):
            event = NetworkEvent(f'192.0.2.{index % 3 + 1}', dst_port=80 + index, transport='tcp',
                observations={'header': 'Authorization: Bearer PRIVATE', 'payload': b'PRIVATE'})
            if index == 9:
                event = NetworkEvent('192.0.2.1', dst_port=80, event_type=EventType.CORRELATION_RESULT,
                    observations={'window_seconds': 60, 'window_start': 0, 'window_end': 60},
                    hypotheses={'behavior': {'classification': 'scanner', 'confidence': 'MEDIUM', 'score': 45,
                        'reasons': ['observed port breadth'], 'supporting_events': self.ids[-2:]}})
            self.ids.append(event.event_id)
            self.assertTrue(self.store.write(event))
        state = {'health': {'components': {'capture': 'healthy'}}, 'queue': {'dropped': 2}, 'metrics': {'storage_bytes': 123}}
        runtime = SimpleNamespace(registry=Metrics(), control_snapshot=lambda: state,
            health_response=lambda: operational_health(state, heartbeat=time.monotonic(), worker_alive=True))
        self.api = ReadOnlyAPI(self.config, runtime)

    def get(self, path, **params):
        return self.api.handle('GET', path, params, {})

    def test_health_ready_version_and_read_only(self):
        for path in ('/health', '/ready', '/version'):
            self.assertEqual(self.get(path)[0], 200)
        self.assertTrue(self.get('/ready')[1]['ready'])
        self.assertEqual(self.api.handle('POST', '/api/v1/events', {}, {})[0], 405)
        self.assertEqual(self.api.handle('GET', '/version', {}, {b'origin': b'https://invalid.example'})[0], 403)
        self.assertEqual(self.get('/openapi.json')[0], 404)
        self.assertNotIn(self.temp.name, json.dumps(self.get('/version')[1]))

    def test_pagination_has_no_duplicates(self):
        ids, cursor = [], None
        for _ in range(5):
            code, page = self.get('/api/v1/events', **({'cursor': cursor} if cursor else {}))
            self.assertEqual(code, 200)
            ids.extend(item['event_id'] for item in page['items'])
            cursor = page['next_cursor']
            if not cursor:
                break
        self.assertEqual(ids, self.ids[::-1])

    def test_hard_limits_invalid_filters_and_not_found(self):
        for params in ({'limit': '501'}, {'limit': '0'}, {'event_type': 'evil'}, {'transport': 'sql'},
                       {'source': "' OR 1=1 --"}, {'destination_port': '65536'}, {'confidence': 'absolute'},
                       {'classification': 'attacker'}, {'cursor': '-1'}, {'sql': 'SELECT'},
                       {'from': '2020-01-01T00:00:00Z'}, {'from': '2026-01-01'}):
            with self.subTest(params=params):
                self.assertEqual(self.get('/api/v1/events', **params)[0], 400)
        self.assertEqual(self.get('/api/v1/events/missing')[0], 404)
        self.assertEqual(self.get('/api/v1/events/' + self.ids[0])[0], 200)

    def test_source_stored_classification_detections_stats_redaction(self):
        code, sources = self.get('/api/v1/sources', limit='1')
        self.assertEqual(code, 200)
        source = sources['items'][0]
        self.assertEqual(source['classification'], 'scanner')
        self.assertEqual(source['events'], 4)
        following = self.get('/api/v1/sources', limit='1', cursor=sources['next_cursor'])[1]
        self.assertEqual(following['items'][0]['source'], '192.0.2.2')
        self.assertEqual(self.get('/api/v1/sources/192.0.2.99')[0], 404)
        item = self.get('/api/v1/detections')[1]['items'][0]
        self.assertEqual(item['score'], 45)
        self.assertEqual(item['supporting_event_ids'], self.ids[7:9])
        self.assertFalse(item['score_is_probability'])
        self.assertEqual(self.get('/api/v1/stats')[1]['activity']['events_last_hour'], 10)
        self.assertNotIn('PRIVATE', json.dumps(self.get('/api/v1/events')[1]))
        self.config.api.redact_ip = True
        private = self.get('/api/v1/sources', limit='1')[1]
        self.assertNotIn('192.0.2.1', json.dumps(private))
        self.assertEqual(self.get('/api/v1/sources', cursor=private['next_cursor'])[0], 200)
        projected = ip_projection({'2001:db8::1': 'peer [2001:db8::2], 192.0.2.4'})
        self.assertNotIn('2001:db8::', json.dumps(projected))

    def test_response_size_rate_and_query_failure(self):
        self.config.api.max_response_bytes = 1024
        endpoint = Endpoint(self.config, self.api.runtime)
        result = endpoint.received(None, None, b'GET /api/v1/events HTTP/1.0\r\n\r\n')
        self.assertLessEqual(len(result), 1024)
        self.assertIn(b'413', result.split(b'\r\n')[0])
        self.config.api.requests_per_second = 1
        api = ReadOnlyAPI(self.config, self.api.runtime)
        self.assertEqual(api.handle('GET', '/version', {}, {})[0], 200)
        self.assertEqual(api.handle('GET', '/version', {}, {})[0], 429)
        with patch.object(self.api.reader, 'events', side_effect=sqlite3.OperationalError('interrupted')):
            self.assertEqual(self.get('/api/v1/events')[0], 503)

    def test_real_query_cancellation_and_read_only(self):
        self.config.api.max_query_seconds = .01
        reader = Reader(self.config.storage.path, self.config.api)
        started = time.monotonic()
        with self.assertRaises(sqlite3.OperationalError), reader.connect() as connection:
            connection.execute('WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10000000) SELECT sum(x) FROM n').fetchone()
        self.assertLess(time.monotonic() - started, 1)
        with self.assertRaises(sqlite3.OperationalError), reader.connect() as connection:
            connection.execute('DELETE FROM events')

    def test_loopback_defaults_bind_override_and_strict_http(self):
        config = Config()
        self.assertFalse(config.api.enabled)
        self.assertFalse(config.metrics.enabled)
        self.assertEqual(config.api.bind_address, '127.0.0.1')
        config.api.enabled, config.api.bind_address = True, '0.0.0.0'
        with self.assertRaises(ValueError):
            config.validate()
        config.api.allow_insecure_non_loopback = True
        config.validate()
        endpoint = Endpoint(self.config, self.api.runtime)
        for raw in (b'GET /version HTTP/1.1\r\nHost: attacker.example\r\n\r\n',
                    b'GET /version HTTP/1.0\r\nContent-Length: 1\r\n\r\n',
                    b'GET /version HTTP/1.0\r\nX: 1\r\nX: 2\r\n\r\n',
                    b'GET /api/v1/events?limit=1&limit=2 HTTP/1.0\r\n\r\n',
                    b'GET /version HTTP/1.0\r\nX: \x00\r\n\r\n'):
            self.assertIn(endpoint.received(None, None, raw).split(b' ')[1], (b'400', b'403'))
        token = Path(self.temp.name) / 'api-token'
        token.write_text('a' * 32)
        self.config.api.token_file = str(token)
        endpoint = Endpoint(self.config, self.api.runtime, metrics=True)
        self.assertIn(b'401', endpoint.received(None, None, b'GET /metrics HTTP/1.0\r\n\r\n'))
        self.assertIn(b'200 OK', endpoint.received(None, None, b'GET /metrics HTTP/1.0\r\nAuthorization: Bearer ' + b'a' * 32 + b'\r\n\r\n'))

    def test_time_filtered_query(self):
        end = datetime.now(timezone.utc) - timedelta(days=1)
        query = Query.parse({'to': end.isoformat(), 'destination_port': '80'}, self.config.api)
        self.assertEqual(self.api.reader.events(query)[0], [])


class OperationalHealthTests(unittest.TestCase):
    def test_optional_failures_dead_worker_and_saturated_queue(self):
        state = {'health': {'components': {'capture': 'healthy', 'enrichment': 'unavailable',
                 'api': 'unavailable', 'storage': 'unavailable', 'metrics': 'unavailable'}},
                 'queue': {'depth': 0, 'max_events': 2, 'bytes': 0, 'max_bytes': 1024}}
        result = operational_health(state, heartbeat=10, worker_alive=True, now=11)
        self.assertTrue(result['ready'])
        self.assertEqual(result['status'], 'DEGRADED')
        self.assertFalse(operational_health(state, heartbeat=1, worker_alive=True, now=11)['live'])
        state['queue']['depth'] = 2
        result = operational_health(state, heartbeat=10, worker_alive=True, now=11)
        self.assertTrue(result['live'])
        self.assertFalse(result['ready'])

    @contextmanager
    def runtime(self):
        config = Config()
        config.api.enabled = config.metrics.enabled = True
        config.api.port, config.metrics.port = free_port(), free_port()
        runtime = EventRuntime(config, logger=EventLogger(config.logging, writer=lambda line: None))
        runtime.start()
        try:
            yield runtime
        finally:
            self.assertTrue(runtime.close())

    def test_real_http_metrics_and_shutdown(self):
        with self.runtime() as runtime:
            for path in ('/health', '/ready', '/version'):
                code, body = request(runtime.config.api.port, path)
                self.assertEqual(code, 200, body)
            runtime.emit(NetworkEvent('192.0.2.1', event_type=EventType.DECEPTION_RESPONSE, observations={'response_length': 12}))
            code, body = request(runtime.config.metrics.port, '/metrics')
            self.assertEqual(code, 200)
            self.assertIn(b'e4e_deception_response_bytes_total 12', body)
            self.assertNotIn(b'192.0.2.1', body)
        self.assertTrue(all(not endpoint.thread.is_alive() for endpoint in runtime.endpoints.values()))

    def test_failed_api_bind_does_not_stop_sensor(self):
        with patch.object(Endpoint, 'start', side_effect=OSError('finite simulated bind failure')):
            with self.runtime() as runtime:
                self.assertTrue(runtime.thread.is_alive())
                self.assertTrue(runtime.emit(NetworkEvent('192.0.2.1')))
                self.assertTrue(runtime.health_response()['ready'])
                self.assertEqual(runtime.metrics['api_start_errors'], 1)
