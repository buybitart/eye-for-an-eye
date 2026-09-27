from collections import Counter
import socket
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from eye_for_an_eye.config import Config
from eye_for_an_eye.enrichment.cache import TTLCache
from eye_for_an_eye.events import NetworkEvent
from eye_for_an_eye.event_types import EventType
from eye_for_an_eye.logging import EventLogger
from eye_for_an_eye.network.listeners import SelectorServer
from eye_for_an_eye.runtime import EventRuntime


def until(predicate):
    deadline = time.monotonic() + 2
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError('finite test watchdog expired')
        time.sleep(.01)


class P4MetricsTests(unittest.TestCase):
    def test_actual_connections_gauges_drops_evictions_and_failures(self):
        config = Config()
        config.runtime.queue_events = 2
        config.correlation.max_sources = 1
        config.limits.max_connections = config.limits.max_connections_per_ip = 1
        config.limits.first_byte_timeout = 2
        runtime = EventRuntime(config, logger=EventLogger(config.logging, writer=lambda line: None))
        server = SelectorServer(config, on_data=lambda *args: b'ok', port=0, max_duration=5)
        enricher = SimpleNamespace(cache=TTLCache(1, 30), metrics=Counter(started=1, completed=1, latency_seconds=.1))
        runtime.attach(listener=server, enrichment=enricher)
        for ip in ('192.0.2.1', '192.0.2.2', '192.0.2.3'):
            runtime.emit(NetworkEvent(ip, dst_ip='192.0.2.10', dst_port=80))
        self.assertEqual(runtime.queue.snapshot()['dropped'], 1)
        runtime.start()
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        client = None
        try:
            self.assertTrue(server.ready.wait(1))
            client = socket.create_connection(server.address, timeout=1)
            until(lambda: server.active_connections == 1)
            self.assertEqual(runtime.snapshot()['metrics']['connections_active'], 1)
            with socket.create_connection(server.address, timeout=1) as rejected:
                try:
                    rejected.recv(1)
                except ConnectionResetError:
                    pass
            until(lambda: server.metrics['rejected'] >= 1)
            client.sendall(b'x')
            self.assertEqual(client.recv(2), b'ok')
            client.close()
            client = None
            until(lambda: server.active_connections == 0)
            until(lambda: runtime.queue.empty())
            runtime.emit(NetworkEvent('192.0.2.1', event_type=EventType.ENRICHMENT_RESULT, enrichment={'status': 'unavailable'}))
            runtime.emit(NetworkEvent('192.0.2.1', event_type=EventType.FINGERPRINT_RESULT, observations={'status': 'unavailable'}))
            until(lambda: runtime.queue.empty())
            metrics = runtime.snapshot()['metrics']
            for name in ('connections_accepted_total', 'connections_rejected_total', 'events_dropped_total',
                         'cache_evictions_total', 'enrichment_failures_total', 'fingerprint_errors_total'):
                self.assertGreaterEqual(metrics[name], 1, name)
            self.assertEqual(metrics['connections_active'], 0)
            self.assertEqual(metrics['enrichment_duration_seconds_count'], 1)
            self.assertGreater(metrics['handler_duration_seconds_count'], 0)
            self.assertNotIn('192.0.2.', runtime.registry.prometheus())
        finally:
            if client:
                client.close()
            server.stop()
            thread.join(2)
            self.assertTrue(runtime.close())

    def test_disk_pressure_drops_logs_without_stopping_runtime(self):
        config = Config()
        with tempfile.TemporaryDirectory() as directory:
            config.logging.file = directory + '/events.jsonl'
            logger = EventLogger(config.logging)
            with patch('eye_for_an_eye.logging.shutil.disk_usage', return_value=SimpleNamespace(free=0)):
                logger.start()
                logger.emit(NetworkEvent('192.0.2.1'))
                self.assertTrue(logger.close())
            self.assertEqual(logger.metrics['disk_pressure_drops'], 1)
            self.assertEqual(logger.metrics['written'], 0)
