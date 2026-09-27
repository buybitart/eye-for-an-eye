import math
import statistics
from ..enrichment.cache import TTLCache
from ..network.flow import FlowKey
from .result import FingerprintResult

__all__ = ['FlowKey', 'TimestampTracker']


class TimestampTracker:
    def __init__(self, max_entries=10000, ttl_seconds=600, max_samples=8):
        if not 3 <= max_samples <= 32:
            raise ValueError('max_samples must be 3..32')
        self.max_samples = max_samples
        self.cache = TTLCache(max_entries, ttl_seconds, max_bytes=16_777_216)

    def observe(self, flow, tsval, observed_at, *, tsecr=None, reset=False):
        obs = {'tsval': tsval, 'tsecr': tsecr, 'sample_count': 0, 'delta_ts': None, 'delta_wall_time': None, 'wrap': False}
        result = FingerprintResult('tcp_timestamp', 'unknown', obs, {'frequency_hz': None, 'stability': 'unknown',
            'offset_behavior': 'unknown'}, evidence=['insufficient_samples'],
            limitations=['flow_scope_only', 'no_boot_time', 'offsets_can_be_randomized', 'no_cross_ip_identity'])
        if type(tsval) is not int or not 0 <= tsval <= 0xffffffff:
            result.evidence = ['missing_or_invalid_timestamp']
            return result
        if tsecr is not None and (type(tsecr) is not int or not 0 <= tsecr <= 0xffffffff):
            result.evidence = ['invalid_echo_timestamp']
            return result
        if type(observed_at) not in (int, float) or not math.isfinite(observed_at):
            result.evidence = ['invalid_capture_time']
            return result
        key = flow.tuple() if hasattr(flow, 'tuple') else flow
        samples = [] if reset else self.cache.get(key, [])
        unwrapped = tsval
        if samples:
            last_time, last_ts, last_unwrapped = samples[-1]
            delta = (tsval - last_ts) & 0xffffffff
            obs.update(delta_ts=delta, delta_wall_time=observed_at - last_time, wrap=tsval < last_ts and delta < 0x80000000)
            if observed_at <= last_time:
                result.evidence = ['duplicate_or_reordered_capture_time']
                return result
            if delta >= 0x80000000:
                result.evidence = ['offset_change_or_reorder']
                result.hypothesis['offset_behavior'] = 'discontinuity_or_reordering'
                return result
            unwrapped = last_unwrapped + delta
        samples = (samples + [(observed_at, tsval, unwrapped)])[-self.max_samples:]
        self.cache.set(key, samples)
        obs['sample_count'] = len(samples)
        result.status = 'observed'
        if len(samples) >= 3:
            rates = [(b[2] - a[2]) / (b[0] - a[0]) for a, b in zip(samples, samples[1:])]
            rate = statistics.median(rates)
            if rate > 0 and max(abs(value - rate) for value in rates) <= max(1, rate * .1):
                result.hypothesis.update(frequency_hz=rate, stability='consistent', offset_behavior='continuous_within_flow')
                result.confidence, result.evidence = 'LOW', ['within_flow_clock_estimate']
            else:
                result.hypothesis['stability'] = 'inconsistent'
                result.evidence = ['unstable_clock_samples']
        return result
