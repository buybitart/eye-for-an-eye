import unittest
from copy import deepcopy
from dataclasses import FrozenInstanceError, fields
from eye_for_an_eye.correlation.engine import CorrelationEngine
from eye_for_an_eye.config import Config
from benchmarks.workloads import event
from eye_for_an_eye.security.redaction import REDACT_KEYS, sensitive_key, _short_sensitive_key, bounded_value


class PerformanceContracts(unittest.TestCase):
    def test_immutable_samples_share_only_scalar_values(self):
        engine = CorrelationEngine(Config().correlation)
        source = event(1)
        engine.observe(source)
        key = (source.sensor_id, source.src_ip)
        first = engine.cache.get(key)
        sample = first['samples'][0]
        self.assertTrue(all(type(getattr(sample, field.name)) in (str, float, int, bool, type(None)) for field in fields(sample)))
        self.assertIs(deepcopy(sample), sample)
        with self.assertRaises(FrozenInstanceError):
            sample.port = 22
        first['samples'].clear()
        first['emitted'].clear()
        self.assertEqual(len(engine.cache.get(key)['samples']), 1)

    def test_key_cache_preserves_redaction_and_is_bounded(self):
        _short_sensitive_key.cache_clear()
        keys = ['safe', 'Authorization', 'COOKIE', 'x' * 1000 + 'token', 'api_key', 'sessionid']
        keys += [f'untrusted_{index}' for index in range(5000)]
        for key in keys:
            self.assertEqual(sensitive_key(key), any(word in str(key).lower() for word in REDACT_KEYS))
        self.assertLessEqual(_short_sensitive_key.cache_info().currsize, 1024)
        self.assertEqual(bounded_value({'payload_length': 12, 'password': 'PRIVATE'}), {'payload_length': 12})
