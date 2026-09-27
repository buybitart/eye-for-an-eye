"""Event-time sliding windows. Counts describe this sensor, never source identity."""
from ..event_types import EventType
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import statistics
from ..decision.auth import (AuthenticationEvent, MECHANISM_UNKNOWN, RESULTS,
                             UNKNOWN as AUTH_UNKNOWN)
from ..enrichment.cache import TTLCache
from ..events import NetworkEvent
from .auth_state import AuthLedger


@dataclass(frozen=True, slots=True)
class Sample:
    time: float
    event_id: str
    destination: str
    port: int | None
    transport: str
    attempt: bool
    handshake: bool
    digest: str
    probe: str
    family: str
    credential: bool
    anomaly: bool
    continuation: bool
    retry: bool
    payload_known: bool = False
    deception: bool = False

    def __deepcopy__(self, memo):
        # Internal frozen value object: all fields are scalar, set by _sample.
        # Lists/dicts containing samples are still copied by TTLCache.
        return self


@dataclass(slots=True)
class DetectionResult:
    classification: str
    score: int
    confidence: str
    reasons: list[str]
    supporting_events: list[str]
    window_seconds: int
    window_start: float
    window_end: float
    limitations: list[str]
    features: dict

    def event(self, base):
        return NetworkEvent(base.src_ip, event_type=EventType.CORRELATION_RESULT, sensor_id=base.sensor_id,
            timestamp=datetime.fromtimestamp(self.window_end, timezone.utc),
            observations={'window_seconds': self.window_seconds, 'window_start': self.window_start,
                          'window_end': self.window_end, 'features': self.features},
            hypotheses={'behavior': {'classification': self.classification, 'score': self.score,
                'score_is_probability': False, 'confidence': self.confidence, 'reasons': self.reasons,
                'supporting_events': self.supporting_events}}, limitations=self.limitations)


def aggregate(samples, window):
    ports = {item.port for item in samples if item.port is not None}
    destinations = {item.destination for item in samples}
    probes = {item.probe for item in samples if item.probe}
    families = {item.family for item in samples if item.family and item.family != 'unknown'}
    informative = [item for item in samples if item.digest or item.credential]
    timeline = informative or [item for item in samples if item.attempt]
    times = [item.time for item in timeline]
    intervals = [b - a for a, b in zip(times, times[1:])]
    mean = statistics.mean(intervals) if intervals else 0
    cv = statistics.pstdev(intervals) / mean if mean > 0 and len(intervals) >= 3 else None
    requests = [item for item in samples if item.attempt] or timeline
    sequence = [item.port for item in requests if item.port is not None]
    deltas = [b - a for a, b in zip(sequence, sequence[1:])]
    sequential = sum(abs(delta) == 1 for delta in deltas) / max(1, len(deltas))
    repeated_sequence = any(len(sequence) >= period * 3 and len(set(sequence[-period:])) >= 2 and
        all(sequence[-index - 1] == sequence[-(index % period) - 1] for index in range(period * 3))
        for period in (2, 3, 4))
    repetitions = Counter(item.digest for item in samples if item.digest and not item.retry)
    return {'events': len(samples), 'unique_destination_ports': len(ports), 'unique_destinations': len(destinations),
        'unique_protocol_probes': len(probes), 'probe_family_diversity': len(families),
        'connection_attempts': sum(item.attempt for item in samples),
        'completed_handshakes': sum(item.handshake for item in samples),
        'max_probe_repetition': max(repetitions.values(), default=0),
        'inter_arrival_mean_seconds': mean if intervals else None, 'inter_arrival_cv': cv,
        'sequential_port_fraction': sequential, 'repeated_sequence': repeated_sequence,
        'credential_attempts': sum(item.credential for item in samples),
        'protocol_anomalies': sum(item.anomaly for item in samples),
        'response_continuations': sum(item.continuation for item in samples),
        'retry_observations': sum(item.retry for item in samples),
        'observed_span_seconds': samples[-1].time - samples[0].time,
        'attempts_per_second': sum(item.attempt for item in samples) / window}


def classify(features, config, *, capped=False):
    f, w = features, config.weights
    stable = f['inter_arrival_cv'] is not None and f['inter_arrival_cv'] <= .15 and f['events'] >= 8
    scan = {'port_breadth': min(1, f['unique_destination_ports'] / 16) if f['unique_destination_ports'] >= 4 else 0,
            'host_breadth': min(1, f['unique_destinations'] / 16) if f['unique_destinations'] >= 4 else 0,
            'probe_diversity': min(1, f['unique_protocol_probes'] / 4),
            'connection_rate': min(1, f['attempts_per_second'] / (20 / 60)),
            'sequential_ports': f['sequential_port_fraction'] if f['unique_destination_ports'] >= 4 else 0}
    suspicion = {'anomalies': min(1, f['protocol_anomalies'] / 3),
                 'credentials': min(1, f['credential_attempts'] / 3),
                 'persistence': min(1, f['observed_span_seconds'] / config.focused_seconds) if f['events'] >= 8 else 0,
                 'repeated_probe': min(1, f['max_probe_repetition'] / 6) if f['max_probe_repetition'] >= 3 else 0}
    bot = {'repeated_probe': 1 if f['max_probe_repetition'] >= 6 else 0,
           'timing_regular': int(stable), 'sequence_repeat': int(f['repeated_sequence'])}
    def score(terms):
        return min(100, round(sum(value * w[name] for name, value in terms.items())))
    focus = (not capped and f['events'] >= 12 and f['observed_span_seconds'] >= config.focused_seconds and
             f['unique_destination_ports'] <= 2 and f['unique_destinations'] <= 2 and
             (f['credential_attempts'] >= 3 or f['protocol_anomalies'] >= 3))
    if focus and score(suspicion) >= config.suspicious_threshold:
        label, terms, confidence = 'targeted-hypothesis', suspicion, 'LOW'
    elif (max(f['unique_destination_ports'], f['unique_destinations']) >= 8 and
          sum(value > 0 for value in scan.values()) >= 2 and score(scan) >= config.scanner_threshold):
        label, terms, confidence = 'scanner', scan, 'MEDIUM'
    elif bot['repeated_probe'] and (stable or bot['sequence_repeat']) and score(bot) >= config.bot_threshold:
        label, terms, confidence = 'bot', bot, 'MEDIUM'
    elif (f['credential_attempts'] >= 3 or f['protocol_anomalies'] >= 3) and score(suspicion) >= config.suspicious_threshold:
        label, terms, confidence = 'suspicious', suspicion, 'LOW'
    else:
        return 'noise', 0, 'UNKNOWN', ['insufficient consistent behavior evidence; not a benign verdict']
    reasons = [f'{name}: {round(value * w[name], 2)} rule points' for name, value in terms.items() if value and w[name]][:6]
    reasons.insert(0, f"{f['unique_destination_ports']} ports, {f['unique_destinations']} destinations, {f['events']} events in window")
    if label == 'targeted-hypothesis':
        reasons.insert(0, 'locally persistent / focused behavior against this sensor')
    if label == 'bot':
        reasons.insert(0, 'bot-like behavior: repeated probe and consistent timing/sequence')
    return label, score(terms), 'LOW' if capped else confidence, reasons[:8]


class CorrelationEngine:
    def __init__(self, config):
        self.config = config
        self.watermark = 0.0
        def clock():
            return self.watermark
        self.cache = TTLCache(config.max_sources, config.ttl_seconds, max_bytes=config.max_bytes * 3 // 4, clock=clock)
        self.distributed = TTLCache(config.distributed_groups, config.ttl_seconds, max_bytes=config.max_bytes // 4, clock=clock)
        # P15.4. Authentication history, bounded independently of the sample
        # cache because a different kind of event feeds it: the server's reply,
        # which is never a sample of its own but is where the outcome lives.
        self.auth = AuthLedger(config.max_sources, config.ttl_seconds, clock=clock)
        self.metrics = Counter()

    def _sample(self, event, stamp):
        obs = event.observations
        def text(key):
            value = obs.get(key)
            return value[:128] if isinstance(value, str) else ''
        return Sample(stamp, event.event_id, event.dst_ip or 'unknown', event.dst_port, event.transport,
            event.event_type in (EventType.CONNECTION_ACCEPTED, EventType.DECEPTION_CONNECTION) or obs.get('syn_observed') is True,
            event.event_type in (EventType.CONNECTION_ACCEPTED, EventType.DECEPTION_CONNECTION) or obs.get('completed_handshake') is True,
            text('probe_digest'), text('probe_name'), text('protocol_family'),
            obs.get('credential_like_attempt') is True,
            obs.get('protocol_anomaly') is True or obs.get('malformed') is True,
            obs.get('response_continuation') is True, obs.get('retry_observed') is True,
            any(name in obs for name in ('payload_length', 'request_length', 'credential_like_attempt', 'protocol_anomaly')),
            event.event_type in (EventType.DECEPTION_CONNECTION, EventType.PROTOCOL_COMMAND))

    def _record_auth(self, event):
        """File an observed authentication outcome against the client. §4, §7.

        Only a result the sensor actually read is recorded. `UNKNOWN` — an
        encrypted session, a truncated capture, a reply in a protocol this
        parser does not speak — files nothing, because an outcome nobody
        observed is not a failure and counting it as one would rebuild the P15.3
        defect one layer down.
        """
        obs = event.observations
        outcome = obs.get('auth_result')
        client = event.dst_ip
        if not outcome or outcome not in RESULTS or outcome == AUTH_UNKNOWN or not client:
            return
        self.auth.observe((event.sensor_id, client), AuthenticationEvent(
            timestamp=event.timestamp.timestamp(), source_group=str(client),
            auth_attempted=True, result=outcome,
            mechanism=obs.get('auth_mechanism') or MECHANISM_UNKNOWN,
            credential_present=True,
            principal=str(obs.get('auth_principal') or '')))
        self.metrics['auth_outcomes'] += 1

    def observe(self, event):
        if not self.config.enabled or event.event_type not in (EventType.CONNECTION_ACCEPTED, EventType.SERVICE_PROBE, EventType.PACKET_OBSERVED,
                                                               EventType.DECEPTION_CONNECTION, EventType.PROTOCOL_COMMAND):
            return []
        if event.observations.get('direction') == 'response':
            # A response is not this source's behaviour and never becomes a
            # sample. It is, however, the only place an authentication outcome
            # exists, so it is recorded against the *client* before being
            # dropped — src and dst are reversed on a reply (P15.4).
            self._record_auth(event)
            return []
        if not event.dst_ip:
            return []
        try:
            ipaddress.ip_address(event.src_ip)
        except ValueError:
            return []
        stamp = event.timestamp.timestamp()
        self.watermark = max(self.watermark, stamp)
        if stamp < self.watermark - max(self.config.windows):
            self.metrics['late_events'] += 1
            return []
        self.metrics['input_events'] += 1
        key = (event.sensor_id, event.src_ip)
        state = self.cache.get(key, {'samples': [], 'emitted': {}, 'capped': False})
        if any(item.event_id == event.event_id for item in state['samples']):
            self.metrics['duplicates'] += 1
            return []
        sample = self._sample(event, stamp)
        samples = sorted([item for item in state['samples'] if item.time >= self.watermark - max(self.config.windows)] + [sample],
                         key=lambda item: (item.time, item.event_id))
        if len(samples) > self.config.max_events_per_source:
            state['capped'] = True
            self.metrics['sample_drops'] += len(samples) - self.config.max_events_per_source
        state['samples'] = samples[-self.config.max_events_per_source:]
        results = []
        for window in sorted(self.config.windows):
            active = [item for item in state['samples'] if item.time >= self.watermark - window]
            if not active:
                continue
            features = aggregate(active, window)
            label, score, confidence, reasons = classify(features, self.config, capped=state['capped'])
            last_label, last_stamp = state['emitted'].get(window, (None, float('-inf')))
            if label != last_label or self.watermark - last_stamp >= self.config.emit_interval:
                limits = ['single_sensor_visibility', 'observed_source_address_not_identity', 'scores_are_not_probabilities',
                          'uncalibrated_rules', 'bounded_supporting_event_ids', 'packet_loss_and_retransmission_possible']
                if state['capped']:
                    limits.append('sample_cap_counts_are_lower_bounds')
                if label == 'targeted-hypothesis':
                    limits.append('only_local_focus_not_global_targeting')
                results.append(DetectionResult(label, score, confidence, reasons, [item.event_id for item in active[-8:]],
                    window, self.watermark - window, self.watermark, limits, features))
                state['emitted'][window] = (label, self.watermark)
        if not self.cache.set(key, state):
            self.metrics['state_rejected'] += 1
        results.extend(self._distributed(event, sample))
        self.metrics['results'] += len(results)
        return results

    def _distributed(self, event, sample):
        signature = sample.digest or sample.probe
        if not signature or sample.credential or sample.retry:
            return []
        key = (event.sensor_id, signature, sample.destination, sample.port, sample.transport)
        state = self.distributed.get(key, {'samples': [], 'emitted': {}})
        rows = [row for row in state['samples'] if row[0] >= self.watermark - max(self.config.windows)]
        rows.append((sample.time, event.src_ip, sample.event_id))
        state['samples'] = sorted(rows)[-self.config.max_events_per_source:]
        results = []
        for window in sorted(self.config.windows):
            active = [row for row in state['samples'] if row[0] >= self.watermark - window]
            count = len({row[1] for row in active})
            if count >= self.config.distributed_sources and self.watermark - state['emitted'].get(window, float('-inf')) >= self.config.emit_interval:
                results.append(DetectionResult('distributed_scan_pattern', min(100, count * 5), 'LOW',
                    [f'{count} observed source addresses used similar probes against one destination/service'],
                    [row[2] for row in active[-8:]], window, self.watermark - window, self.watermark,
                    ['not_same_attacker_or_botnet_owner', 'spoofing_possible', 'common_clients_can_share_probes',
                     'single_sensor_visibility', 'scores_are_not_probabilities', 'bounded_group_samples'],
                    {'source_addresses': count, 'destination': sample.destination, 'destination_port': sample.port}))
                state['emitted'][window] = self.watermark
        if not self.distributed.set(key, state):
            self.metrics['state_rejected'] += 1
        return results

    def snapshot(self):
        return {'sources': len(self.cache), 'groups': len(self.distributed),
                'bytes': self.cache.current_bytes + self.distributed.current_bytes,
                'source_cache': self.cache.metrics, 'group_cache': self.distributed.metrics, **self.metrics}

    def final_results(self):
        """Latest active source windows, independent of output rate limiting."""
        for (sensor, source), state in self.cache.items():
            for window in sorted(self.config.windows):
                active = [item for item in state['samples'] if item.time >= self.watermark - window]
                if not active:
                    continue
                features = aggregate(active, window)
                label, score, confidence, reasons = classify(features, self.config, capped=state['capped'])
                limits = ['single_sensor_visibility', 'uncalibrated_rules', 'scores_are_not_probabilities',
                          'observed_source_address_not_identity', 'bounded_supporting_event_ids']
                if state['capped']:
                    limits.append('sample_cap_counts_are_lower_bounds')
                if label == 'targeted-hypothesis':
                    limits.append('only_local_focus_not_global_targeting')
                yield sensor, source, DetectionResult(label, score, confidence, reasons, [item.event_id for item in active[-8:]],
                    window, self.watermark - window, self.watermark, limits, features)
