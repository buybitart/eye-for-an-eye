from datetime import datetime, timezone
import json
import unittest
from eye_for_an_eye.config import Config, CorrelationConfig, load_config
from eye_for_an_eye.correlation.engine import CorrelationEngine
from eye_for_an_eye.correlation.features import PayloadFeatures
from eye_for_an_eye.events import NetworkEvent
from eye_for_an_eye.network.flow import FlowKey
from eye_for_an_eye.network.flow_state import FlowEvidence
from eye_for_an_eye.fingerprint.probes import ProbeKey


def event(index, *, src='192.0.2.1', dst='198.51.100.1', port=80, stamp=None, kind='connection', **observations):
    return NetworkEvent(src, 12345, dst, port, 'tcp', kind, observations=observations,
        timestamp=datetime.fromtimestamp(index if stamp is None else stamp, timezone.utc), event_id=f'e{src}-{index}')


class CorrelationTests(unittest.TestCase):
    def test_partial_environment_weights_preserve_other_defaults(self):
        config = load_config(environ={'E4E__CORRELATION__WEIGHTS': '{"credentials":50}'})
        self.assertEqual(config.correlation.weights['credentials'], 50)
        self.assertEqual(config.correlation.weights['port_breadth'], 25)

    def test_capped_history_cannot_create_focused_hypothesis(self):
        engine = CorrelationEngine(CorrelationConfig(max_events_per_source=12))
        results = []
        for index in range(20):
            results.extend(engine.observe(event(index, stamp=index * 30, credential_like_attempt=True)))
        capped = [item for item in results if 'sample_cap_counts_are_lower_bounds' in item.limitations]
        self.assertTrue(capped)
        self.assertTrue(all(item.classification != 'targeted-hypothesis' and item.confidence != 'MEDIUM' for item in capped))

    def test_normal_connection_has_reason_without_claim_of_benign_identity(self):
        results = CorrelationEngine(CorrelationConfig()).observe(event(0))
        self.assertEqual(len(results), 2)
        for result in results:
            self.assertEqual(result.classification, 'noise')
            self.assertEqual(result.confidence, 'UNKNOWN')
            self.assertTrue(result.reasons)
            self.assertTrue(result.supporting_events)
            self.assertIn('single_sensor_visibility', result.limitations)
            encoded = json.loads(result.event(event(0)).to_json())
            self.assertFalse(encoded['hypotheses']['behavior']['score_is_probability'])

    def test_vertical_and_horizontal_scan_explanations(self):
        for horizontal in (False, True):
            engine, results = CorrelationEngine(CorrelationConfig()), []
            for index in range(32):
                results.extend(engine.observe(event(index, port=80 if horizontal else 1000 + index,
                    dst=f'198.51.100.{index + 1}' if horizontal else '198.51.100.1')))
            with self.subTest(horizontal=horizontal):
                scanner = [item for item in results if item.classification == 'scanner']
                self.assertTrue(scanner)
                self.assertTrue(all(item.reasons and item.supporting_events for item in scanner))

    def test_slow_scan_uses_long_window_and_expires(self):
        engine, results = CorrelationEngine(CorrelationConfig()), []
        for index in range(30):
            results.extend(engine.observe(event(index, stamp=index * 25, port=1000 + index)))
        self.assertTrue(any(item.classification == 'scanner' and item.window_seconds == 900 for item in results))
        self.assertFalse(any(item.classification == 'scanner' and item.window_seconds == 60 for item in results))
        later = engine.observe(event(31, stamp=2000, port=80))
        self.assertTrue(all(item.features['events'] == 1 for item in later))

    def test_bot_like_pattern_and_retransmission_limit(self):
        payload = PayloadFeatures(key=b'x' * 32)
        features = payload.observe(b'GET / HTTP/1.0\r\n\r\n', 'tcp')
        engine, results = CorrelationEngine(CorrelationConfig()), []
        for index in range(12):
            results.extend(engine.observe(event(index, kind='service_probe', **features)))
        self.assertTrue(any(item.classification == 'bot' for item in results))
        engine, retries = CorrelationEngine(CorrelationConfig()), []
        for index in range(12):
            retries.extend(engine.observe(event(index, kind='service_probe', retry_observed=True, **features)))
        self.assertFalse(any(item.classification == 'bot' for item in retries))

    def test_credentials_are_counted_without_content_or_digest(self):
        payload = PayloadFeatures(key=b'x' * 32)
        features = payload.observe(b'Authorization: Basic private-password', 'tcp')
        self.assertTrue(features['credential_like_attempt'])
        self.assertNotIn('probe_digest', features)
        engine, results = CorrelationEngine(CorrelationConfig()), []
        for index in range(4):
            results.extend(engine.observe(event(index, kind='service_probe', **features)))
        self.assertTrue(any(item.classification == 'suspicious' for item in results))
        encoded = event(9, **features).to_json()
        self.assertIn('credential_like_attempt', encoded)
        self.assertNotIn('private-password', encoded)
        self.assertNotIn('private-password', event(9, credential_like_attempt='private-password').to_json())

    def test_targeted_is_only_local_persistence_hypothesis(self):
        engine, results = CorrelationEngine(CorrelationConfig()), []
        for index in range(14):
            results.extend(engine.observe(event(index, stamp=index * 30, kind='service_probe', credential_like_attempt=True)))
        focused = [item for item in results if item.classification == 'targeted-hypothesis']
        self.assertTrue(focused)
        self.assertTrue(all(item.confidence == 'LOW' and 'only_local_focus_not_global_targeting' in item.limitations for item in focused))

    def test_distributed_similarity_not_identity(self):
        engine, results = CorrelationEngine(CorrelationConfig()), []
        for index in range(8):
            results.extend(engine.observe(event(index, src=f'192.0.2.{index + 1}', kind='service_probe', probe_digest='a' * 64)))
        patterns = [item for item in results if item.classification == 'distributed_scan_pattern']
        self.assertTrue(patterns)
        self.assertIn('not_same_attacker_or_botnet_owner', patterns[0].limitations)
        self.assertTrue(patterns[0].supporting_events)

    def test_spoofed_sources_memory_bounded_and_accounted(self):
        config = CorrelationConfig(max_sources=32, distributed_groups=16, max_bytes=131072, max_events_per_source=8)
        engine = CorrelationEngine(config)
        for index in range(2000):
            engine.observe(event(index, src=f'10.{index // 65536}.{index // 256 % 256}.{index % 256}', probe_digest=f'{index:064x}'))
        stats = engine.snapshot()
        self.assertLessEqual(stats['sources'], 32)
        self.assertLessEqual(stats['groups'], 16)
        self.assertLessEqual(stats['bytes'], config.max_bytes)
        self.assertGreater(stats['source_cache']['eviction'], 0)

    def test_duplicate_late_and_sample_cap(self):
        config = CorrelationConfig(max_events_per_source=8)
        engine = CorrelationEngine(config)
        first = event(1)
        engine.observe(first)
        self.assertEqual(engine.observe(first), [])
        for index in range(2, 16):
            engine.observe(event(index))
        self.assertGreater(engine.metrics['sample_drops'], 0)
        result = engine.observe(event(20))[0]
        self.assertIn('sample_cap_counts_are_lower_bounds', result.limitations)
        engine.observe(event(21, stamp=2000))
        self.assertEqual(engine.observe(event(22, stamp=1)), [])
        self.assertEqual(engine.metrics['late_events'], 1)

    def test_reorder_same_sensor_scope_and_config_weights(self):
        config = CorrelationConfig()
        config.weights = dict.fromkeys(config.weights, 0)
        engine, results = CorrelationEngine(config), []
        for index in range(32):
            results.extend(engine.observe(event(index, port=1000 + index)))
        self.assertTrue(all(item.classification == 'noise' for item in results))
        engine.observe(event(40, stamp=20))
        self.assertEqual(engine.metrics['late_events'], 0)
        for setting, value in (('windows', [60] * 5), ('max_bytes', 1), ('weights', {'bad': 10})):
            config = Config()
            setattr(config.correlation, setting, value)
            with self.subTest(setting=setting), self.assertRaises(ValueError):
                config.validate()

    def test_probe_minimum_and_per_process_digest_scope(self):
        probes = {ProbeKey('tcp', 'Fixture'): b'hello-world'}
        strict = PayloadFeatures(probes, 12, key=b'x' * 32)
        self.assertNotIn('probe_name', strict.observe(b'hello-world', 'tcp'))
        matched = PayloadFeatures(probes, 8, key=b'x' * 32).observe(b'hello-world', 'tcp')
        self.assertEqual(matched['probe_name'], 'Fixture')
        self.assertIn('identity unknown', matched['probe_description'])
        self.assertNotEqual(PayloadFeatures().observe(b'hello-world', 'tcp')['probe_digest'], matched['probe_digest'])

    def test_handshake_requires_three_packets_and_continuation(self):
        evidence = FlowEvidence()
        client = FlowKey('192.0.2.1', 1234, '198.51.100.1', 80)
        server = FlowKey(client.dst_ip, client.dst_port, client.src_ip, client.src_port)
        self.assertFalse(evidence.observe(client, 16, 100, 200, 0)['completed_handshake'])
        evidence.observe(client, 2, 99, 0, 0)
        evidence.observe(server, 18, 199, 100, 0)
        self.assertTrue(evidence.observe(client, 16, 100, 200, 0)['completed_handshake'])
        self.assertFalse(evidence.observe(client, 16, 100, 200, 0)['completed_handshake'])
        evidence.observe(server, 24, 200, 100, 10)
        self.assertTrue(evidence.observe(client, 24, 100, 210, 10)['response_continuation'])
        self.assertTrue(evidence.observe(client, 24, 100, 210, 10)['retry_observed'])
