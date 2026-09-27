import unittest
from eye_for_an_eye.fingerprint.ip_id import IpIdTracker
from eye_for_an_eye.fingerprint.ttl import ttl_observation
from eye_for_an_eye.fingerprint.tcp_timestamp import FlowKey, TimestampTracker
from eye_for_an_eye.fingerprint.p0f_adapter import P0fAdapter
from eye_for_an_eye.fingerprint.path import PathProbe


class FingerprintTests(unittest.TestCase):
    def test_id_zero_wrap_reorder(self):
        for previous, current, delta in ((0, 5, 5), (65535, 0, 1), (100, 90, 65526)):
            tracker = IpIdTracker()
            self.assertIsNone(tracker.observe('a', previous)['ip_id_delta'])
            result = tracker.observe('a', current)
            self.assertEqual(result['ip_id_delta'], delta)
            if current == 90:
                self.assertEqual(result['confidence'], 'UNKNOWN')
                self.assertIn('reorder', result['reason'])
        self.assertEqual(tracker.observe('b', 1, df=True)['confidence'], 'UNKNOWN')

    def test_ttl_has_no_os_claim(self):
        result = ttl_observation(51)
        self.assertEqual(result['estimated_hops'], 13)
        self.assertIsNone(result['os_hint'])
        self.assertEqual(result['confidence'], 'LOW')
        self.assertEqual(ttl_observation(0)['confidence'], 'UNKNOWN')

    def test_timestamp_flow_isolation_wrap_and_rate(self):
        tracker = TimestampTracker(max_entries=2)
        a = FlowKey('192.0.2.1', 1, '127.0.0.1', 80, 'tcp')
        b = FlowKey('192.0.2.2', 1, '127.0.0.1', 80, 'tcp')
        for i in range(3):
            result = tracker.observe(a, (0xffffff00 + i * 250) & 0xffffffff, i + 1)
        self.assertEqual(result['frequency_hz'], 250)
        self.assertEqual(tracker.observe(b, 42, 3)['confidence'], 'UNKNOWN')
        self.assertEqual(tracker.observe(a, 12, 1)['confidence'], 'UNKNOWN')
        self.assertEqual(tracker.observe(a, None, 4)['confidence'], 'UNKNOWN')
        self.assertNotIn('boot_time', result)

    def test_state_is_bounded(self):
        ids, stamps = IpIdTracker(max_entries=2), TimestampTracker(max_entries=2)
        for i in range(100):
            ids.observe(str(i), i)
            stamps.observe(str(i), i, i + 1)
        self.assertLessEqual(len(ids.cache), 2)
        self.assertLessEqual(len(stamps.cache), 2)

    def test_p0f_contract_and_failure(self):
        def backend(p):
            return (('s', 'unix', 'Linux', '6.x'), 3, False)
        result = P0fAdapter(backend=backend).fingerprint(object())
        self.assertEqual(result.status, 'matched')
        self.assertFalse(result.fuzzy)
        self.assertEqual(result.distance, 3)
        self.assertEqual(result.confidence, 'MEDIUM')
        for backend in (lambda p: None, lambda p: ('http', False)):
            self.assertEqual(P0fAdapter(backend=backend).fingerprint(None).confidence, 'UNKNOWN')
        def broken(packet):
            raise ValueError('bad')
        self.assertEqual(P0fAdapter(backend=broken).fingerprint(None).reason, 'backend_error')
        self.assertEqual(P0fAdapter().fingerprint(None).reason, 'database_missing')

    def test_path_passive_timeout_and_negative_cache(self):
        calls = []
        def sender(ip, timeout):
            calls.append(ip)
        self.assertEqual(PathProbe(sender=sender).measure('127.0.0.1', 64).reason, 'disabled')
        self.assertEqual(calls, [])
        probe = PathProbe(enabled=True, allowed_cidrs=['127.0.0.1/32'], sender=sender)
        self.assertEqual(probe.measure('192.0.2.1', 64).reason, 'not_allowed')
        self.assertEqual(probe.measure('127.0.0.1', 64).reason, 'timeout')
        self.assertEqual(probe.measure('127.0.0.1', 64).reason, 'timeout')
        self.assertEqual(calls, ['127.0.0.1'])

    def test_path_response_validation(self):
        probe = PathProbe(enabled=True, allowed_cidrs=['127.0.0.1/32'],
                          sender=lambda *args: {'src_ip': '127.0.0.2', 'ttl': 64})
        self.assertEqual(probe.measure('127.0.0.1', 64).reason, 'invalid_response')
