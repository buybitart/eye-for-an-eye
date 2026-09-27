import io
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from eye_for_an_eye.config import LoggingConfig
from eye_for_an_eye.events import EventPipeline, NetworkEvent
from eye_for_an_eye.logging import EventLogger, serialize_event


class EventTests(unittest.TestCase):
    def test_base_event_precedes_enrichment(self):
        order = []
        class Sink:
            def emit(self, event):
                order.append('event')
                return True
        class Enricher:
            def submit(self, *args):
                order.append('enrichment')
        EventPipeline(Sink(), Enricher()).record(NetworkEvent('192.0.2.1'))
        self.assertEqual(order, ['event', 'enrichment'])

    def test_safe_bounded_json(self):
        line = serialize_event(NetworkEvent('192.0.2.1', observations={'payload': b'\x1b' * 100000,
                               'text': '\x1b\n' * 10000}))
        self.assertLessEqual(len(line), 4096)
        self.assertNotIn('\x1b', line)
        self.assertNotIn('\n', line)
        self.assertNotIn('payload', json.loads(line)['observations'])

    def test_queue_sampling_and_shutdown(self):
        output = io.StringIO()
        config = LoggingConfig(queue_size=2)
        logger = EventLogger(config, writer=output.write)
        for i in range(100):
            logger.emit(NetworkEvent('192.0.2.1'))
        self.assertLessEqual(logger.queue.qsize(), 2)
        self.assertGreater(logger.metrics['sampled'] + logger.metrics['dropped'], 0)
        logger.start()
        self.assertTrue(logger.close())
        self.assertTrue(output.getvalue())

    def test_fractional_source_rate_allows_initial_event(self):
        logger = EventLogger(LoggingConfig(per_source_per_second=.5))
        self.assertTrue(logger.emit(NetworkEvent('192.0.2.1')))
        self.assertFalse(logger.emit(NetworkEvent('192.0.2.1')))

    def test_slow_writer_keeps_queue_bounded_and_reports_stall(self):
        entered, release = threading.Event(), threading.Event()
        def stalled_writer(line):
            entered.set()
            release.wait(2)
        logger = EventLogger(LoggingConfig(queue_size=2), writer=stalled_writer)
        logger.start()
        try:
            logger.emit(NetworkEvent('192.0.2.1'))
            self.assertTrue(entered.wait(1))
            for index in range(50):
                logger.emit(NetworkEvent(f'192.0.2.{index + 2}'))
            self.assertLessEqual(logger.queue.qsize(), 2)
            self.assertGreater(logger.metrics['dropped'], 0)
            self.assertFalse(logger.close(timeout=.02))
        finally:
            release.set()
            self.assertTrue(logger.close())

    def test_rotation_and_write_errors_are_counted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events.jsonl'
            config = LoggingConfig(file=str(path), max_bytes=512, backups=2)
            logger = EventLogger(config)
            for index in range(20):
                logger.emit(NetworkEvent(f'192.0.2.{index + 1}'))
            logger.start()
            self.assertTrue(logger.close())
            self.assertLessEqual(len(list(Path(directory).glob('events.jsonl*'))), 3)
            self.assertTrue(all(p.stat().st_size <= 512 + 4097 for p in Path(directory).iterdir()))
            logger = EventLogger(config)
            logger.start()
            with patch.object(logger.handler, 'shouldRollover', side_effect=OSError('disk failure')):
                logger.emit(NetworkEvent('192.0.2.1'))
                self.assertTrue(logger.close())
            self.assertEqual(logger.metrics['write_errors'], 1)
            self.assertEqual(logger.metrics['written'], 0)
