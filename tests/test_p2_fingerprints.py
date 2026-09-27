from dataclasses import asdict
import json
import unittest
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop, IPv6ExtHdrFragment
from scapy.packet import Raw
from eye_for_an_eye.fingerprint.result import FingerprintResult
from eye_for_an_eye.fingerprint.ttl import ttl_fingerprint
from eye_for_an_eye.fingerprint.ip_id import IpIdTracker
from eye_for_an_eye.fingerprint.tcp_timestamp import TimestampTracker
from eye_for_an_eye.fingerprint.tcp_options import tcp_options
from eye_for_an_eye.fingerprint.ipv6 import ipv6_observation
from eye_for_an_eye.fingerprint.p0f_adapter import P0fAdapter
from eye_for_an_eye.fingerprint.path import path_characteristics
from eye_for_an_eye.network.flow import FlowKey
from eye_for_an_eye.network.capture import PacketObserver
from eye_for_an_eye.events import EventPipeline, NetworkEvent
from eye_for_an_eye.config import Config


class P2FingerprintTests(unittest.TestCase):
    def test_ttl_candidates_ambiguity_custom_and_invalid(self):
        value = ttl_fingerprint(51)
        self.assertEqual(value.observations, {'observed_ttl': 51})
        self.assertEqual(value.hypothesis['estimated_hops'], [13])
        ambiguous = ttl_fingerprint(31, max_hops=64)
        self.assertEqual(ambiguous.hypothesis['initial_ttl_candidates'], [32, 64])
        self.assertTrue(ambiguous.hypothesis['ambiguity'])
        self.assertIsNone(ambiguous.hypothesis['os_hint'])
        self.assertEqual(ttl_fingerprint(90, candidates=[100]).hypothesis['estimated_hops'], [10])
        for value in (0, -1, 256, True, None, '51'):
            with self.subTest(value=value):
                self.assertEqual(ttl_fingerprint(value).confidence, 'UNKNOWN')

    def test_no_uncalibrated_high_and_separate_result_sections(self):
        with self.assertRaises(ValueError):
            FingerprintResult('ttl', confidence='HIGH')
        result = asdict(ttl_fingerprint(51))
        self.assertNotIn('estimated_hops', result['observations'])
        self.assertIn('estimated_hops', result['hypothesis'])

    def test_id_descriptive_samples_wrap_random_and_fragments(self):
        tracker = IpIdTracker(max_samples=8)
        for stamp, value in enumerate((65533, 65534, 65535, 0, 1, 2, 3, 4)):
            result = tracker.observe('a', value, observed_at=stamp)
        self.assertEqual(result['wrap_events'], 1)
        self.assertEqual(result.hypothesis['behavior'], 'mostly_monotonic')
        self.assertEqual(result['delta_distribution']['median'], 1)
        for stamp, value in enumerate((100, 60000, 12, 33000, 940, 52000, 12345, 300)):
            result = tracker.observe('b', value, observed_at=stamp)
        self.assertEqual(result.hypothesis['behavior'], 'random_like')
        self.assertEqual(tracker.observe('c', 9, mf=True).confidence, 'UNKNOWN')
        self.assertIsNone(tracker.cache.get('c'))

    def test_timestamp_offsets_echo_and_independent_portless_flow(self):
        tracker = TimestampTracker()
        flow = FlowKey('192.0.2.1', 1, '192.0.2.2', 80)
        for stamp, ts in enumerate((0xffffff00, 0xffffff80, 0)):
            result = tracker.observe(flow, ts, stamp, tsecr=77)
        self.assertTrue(result['wrap'])
        self.assertEqual(result['tsecr'], 77)
        self.assertEqual(result.hypothesis['frequency_hz'], 128)
        self.assertEqual(tracker.observe(flow, 0xffffffff, 3).hypothesis['offset_behavior'], 'discontinuity_or_reordering')
        other = FlowKey('2001:db8::1', None, '2001:db8::2', None, 'icmpv6')
        self.assertEqual(tracker.observe(other, 100, 3).confidence, 'UNKNOWN')
        self.assertEqual(FlowKey('2001:0db8::1', 1, '::1', 2).src_ip, '2001:db8::1')

    def test_tcp_options_observed_and_partial_malformed(self):
        data = bytes(TCP(window=8192, flags='SF', options=[('MSS', 1460), ('NOP', None), ('WScale', 7),
                                                       ('SAckOK', b''), ('Timestamp', (10, 20))]))
        result = tcp_options(data)
        self.assertEqual(result['mss'], 1460)
        self.assertEqual(result['window_scale'], 7)
        self.assertEqual(result['timestamps'], {'tsval': 10, 'tsecr': 20})
        self.assertEqual(result['option_order'][:3], [2, 1, 3])
        self.assertIn('syn_with_fin_or_rst', result['quirks'])
        malformed = bytearray(bytes(TCP(options=[('MSS', 1460)])))
        malformed[21] = 0
        partial = tcp_options(bytes(malformed))
        self.assertTrue(partial['malformed'])
        self.assertEqual(partial.status, 'partial')
        self.assertIsNone(partial['mss'])
        self.assertEqual(tcp_options(b'').status, 'partial')

    def test_duplicate_timestamp_is_partial_and_complete_option_order_survives_json(self):
        duplicate = tcp_options(bytes(TCP(options=[('Timestamp', (1, 0)), ('Timestamp', (2, 0))])))
        self.assertTrue(duplicate['malformed'])
        self.assertIn('duplicate_singleton_option', duplicate.evidence)
        options = tcp_options(bytes(TCP(options=[('NOP', None)] * 40)))
        self.assertEqual(len(options['option_order']), 40)
        self.assertEqual(options['option_order_codes'], ','.join(['1'] * 40))
        record = json.loads(NetworkEvent('192.0.2.1', observations={'measurements': options.observations}).to_json())
        self.assertEqual(len(record['observations']['measurements']['option_order']), 24)
        self.assertEqual(record['observations']['measurements']['option_order_codes'], options['option_order_codes'])

    def test_ipv6_extensions_fragment_and_truncation(self):
        packet = IPv6(fl=123, hlim=51) / IPv6ExtHdrHopByHop() / IPv6ExtHdrFragment(m=1, id=42) / TCP()
        result = ipv6_observation(bytes(packet))
        self.assertEqual(result['flow_label'], 123)
        self.assertEqual(result['hop_limit'], 51)
        self.assertEqual(result['extension_headers'], [0, 44])
        self.assertEqual(result['fragment_header']['identification'], 42)
        self.assertTrue(ipv6_observation(bytes(packet)[:42])['malformed'])

    def test_p0f_fuzzy_unmatched_and_explicit_error(self):
        fuzzy = P0fAdapter(backend=lambda p: (('s', 'unix', 'Fixture', 'x'), 11, True)).fingerprint(None)
        self.assertEqual(fuzzy.confidence, 'LOW')
        self.assertEqual(fuzzy.hypothesis['class'], 'unix')
        self.assertEqual(P0fAdapter(backend=lambda p: None).fingerprint(None).status, 'unmatched')
        self.assertEqual(P0fAdapter(backend=lambda p: 3).fingerprint(None).status, 'error')
        self.assertEqual(P0fAdapter().fingerprint(None).status, 'unavailable')

    def test_path_has_only_unknown_nat_hypothesis(self):
        result = path_characteristics(51, {'reply_ttl': 63})
        self.assertEqual(result.hypothesis, {'nat_hypothesis': 'UNKNOWN'})
        self.assertNotIn('estimated_hop_difference', str(asdict(result)))

    def test_runtime_separates_features_and_handles_malformed(self):
        events = []
        class Sink:
            def emit(self, event):
                events.append(event)
                return True
        observer = PacketObserver(Config(), EventPipeline(Sink()))
        observer.observe(IP(src='192.0.2.1', dst='127.0.0.1', ttl=51) / TCP())
        ttl = next(event for event in events if event.observations.get('feature') == 'ttl')
        self.assertNotIn('estimated_hops', str(ttl.observations))
        self.assertEqual(ttl.hypotheses['ttl']['hypothesis']['estimated_hops'], [13])
        observer.observe(Raw(bytes(IP())[:10]))
        self.assertGreater(observer.errors, 0)

    def test_capture_truncation_does_not_claim_source_protocol_anomaly(self):
        events = []
        class Sink:
            def emit(self, event):
                events.append(event)
                return True
        observer = PacketObserver(Config(), EventPipeline(Sink()))
        original = bytes(IP(src='192.0.2.1', dst='198.51.100.1') / TCP() / Raw(b'x' * 2000))
        observer.observe(IP(original[:100]))
        base = events[0]
        self.assertTrue(base.observations['capture_truncated'])
        self.assertFalse(base.observations['malformed'])
        self.assertNotIn('probe_digest', base.observations)
