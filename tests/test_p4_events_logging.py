import json
import unittest
from eye_for_an_eye.config import LoggingConfig
from eye_for_an_eye.events import NetworkEvent, SCHEMA_VERSION
from eye_for_an_eye.event_types import EventType
from eye_for_an_eye.logging import EventLogger, serialize_event
from eye_for_an_eye.observability.metrics import Metrics


class P4EventTests(unittest.TestCase):
    def test_migration_v1_v2_and_current_sections(self):
        event = NetworkEvent('192.0.2.1', event_type=EventType.CORRELATION_RESULT,
            hypotheses={'behavior': {'classification': 'scanner', 'confidence': 'MEDIUM'}})
        for version in (1, 2):
            old = json.loads(event.to_json())
            old['schema_version'] = version
            for key in ('classification', 'confidence', 'deception'):
                old.pop(key)
            new = NetworkEvent.from_json(json.dumps(old))
            self.assertEqual(new.schema_version, SCHEMA_VERSION)
            self.assertEqual(new.classification, 'scanner')
            self.assertEqual(new.confidence, 'MEDIUM')
            self.assertIn('legacy_schema_v' + str(version), new.limitations)
        with self.assertRaises(ValueError):
            NetworkEvent('192.0.2.1', event_type='arbitrary')

    def test_central_value_redaction_binary_controls_and_truncation(self):
        event = NetworkEvent('192.0.2.1', observations={'header': 'Authorization: Bearer PRIVATE',
            'value': 'password=PRIVATE', 'another': 'eyJabcde.abcdefg.hijklmn', 'binary': b'PRIVATE',
            'session': 'PRIVATE', 'cookie': 'PRIVATE', 'long': 'z' * 20000, 'control': '\x1b\n'})
        for encoded in (event.to_json(), serialize_event(event)):
            self.assertNotIn('PRIVATE', encoded)
            self.assertNotIn('eyJabcde', encoded)
            self.assertNotIn('\x1b', encoded)
            self.assertNotIn('\n', encoded)
            self.assertIn('[truncated]', encoded)
            self.assertLessEqual(len(encoded), 4096)

    def test_repeated_errors_and_event_type_limit(self):
        config = LoggingConfig(events_per_second=10000, per_source_per_second=10000, per_event_type_per_second=2)
        logger = EventLogger(config, writer=lambda line: None)
        for _ in range(1000):
            logger.emit(NetworkEvent('192.0.2.1', event_type=EventType.PARSE_ERROR, observations={'reason': 'invalid'}))
        self.assertEqual(logger.queue.qsize(), 1)
        self.assertEqual(logger.metrics['suppressed_count'], 999)
        for index in range(100):
            logger.emit(NetworkEvent(f'192.0.2.{index + 1}'))
        self.assertLessEqual(logger.queue.qsize(), 4)
        self.assertIn('level', json.loads(logger.queue.get_nowait()))

    def test_prometheus_fixed_cardinality(self):
        metrics = Metrics()
        metrics.inc('events_dropped_total', 2)
        metrics.observe('handler_duration_seconds', .1)
        output = metrics.prometheus()
        self.assertIn('e4e_events_dropped_total 2', output)
        self.assertIn('e4e_handler_duration_seconds_count 1', output)
        self.assertNotIn('{', output)
        with self.assertRaises(ValueError):
            metrics.inc('192.0.2.1')
