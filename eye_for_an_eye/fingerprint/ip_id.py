import math
import statistics
from ..enrichment.cache import TTLCache
from .result import FingerprintResult


class IpIdTracker:
    def __init__(self, max_entries=10000, ttl_seconds=600, max_samples=32):
        if type(max_samples) is not int or not 3 <= max_samples <= 128:
            raise ValueError('IP ID sample limit must be 3..128')
        self.max_samples = max_samples
        self.cache = TTLCache(max_entries, ttl_seconds, max_bytes=8_388_608)

    def observe(self, key, current, *, df=False, mf=False, fragment_offset=0, observed_at=None):
        obs = {'ip_id_current': current, 'ip_id_previous': None, 'ip_id_delta': None,
               'df': bool(df), 'mf': bool(mf), 'fragment_offset': fragment_offset}
        limitations = ['descriptive_only', 'no_traffic_volume_or_intent_inference', 'bounded_sample_window']
        result = FingerprintResult('ip_id', 'unknown', obs, evidence=['insufficient_samples'], limitations=limitations)
        if type(current) is not int or not 0 <= current <= 65535:
            result.evidence = ['invalid_id']
            return result
        if observed_at is not None and (type(observed_at) not in (int, float) or not math.isfinite(observed_at)):
            result.evidence = ['invalid_capture_time']
            return result
        if mf or fragment_offset or df:
            result.evidence = ['fragment_id_not_packet_counter' if mf or fragment_offset else 'atomic_id_has_no_counter_semantics']
            return result
        key = key.tuple() if hasattr(key, 'tuple') else key
        samples = self.cache.get(key, [])
        if samples:
            previous, stamp = samples[-1]
            delta = (current - previous) & 65535
            obs.update(ip_id_previous=previous, ip_id_delta=delta)
            if observed_at is not None and stamp is not None and observed_at <= stamp:
                result.evidence = ['duplicate_or_reordered_capture_time']
                return result
            if delta > 32768:
                result.evidence = ['possible_reorder_or_generator_change']
        samples = (samples + [(current, observed_at)])[-self.max_samples:]
        self.cache.set(key, samples)
        values = [item[0] for item in samples]
        deltas = [(b - a) & 65535 for a, b in zip(values, values[1:])]
        obs.update(samples=len(values), zero_rate=values.count(0) / len(values),
                   constant_rate=sum(delta == 0 for delta in deltas) / max(1, len(deltas)),
                   monotonic_rate=sum(0 < delta <= 32768 for delta in deltas) / max(1, len(deltas)),
                   wrap_events=sum(b < a and 0 < ((b - a) & 65535) <= 32768 for a, b in zip(values, values[1:])),
                   delta_distribution={'min': min(deltas, default=0), 'median': statistics.median(deltas) if deltas else None,
                                       'max': max(deltas, default=0), 'distinct': len(set(deltas))})
        if len(values) < 3:
            return result
        behavior = 'constant' if obs['constant_rate'] >= .8 else (
            'mostly_monotonic' if obs['monotonic_rate'] >= .8 else 'irregular')
        if len(values) >= 8 and len(set(deltas)) >= len(deltas) * .8 and obs['monotonic_rate'] < .8:
            behavior = 'random_like'
            limitations.append('not_a_randomness_test_reordering_can_look_similar')
        result.hypothesis = {'behavior': behavior}
        result.status = 'observed'
        if result.reason != 'possible_reorder_or_generator_change':
            result.confidence = 'LOW'
            result.evidence = ['bounded_modular_sample_statistics']
        return result
