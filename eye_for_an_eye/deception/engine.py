"""Per-connection bounded sessions connected to telemetry and response admission."""
from ..event_types import EventType
from collections import Counter, deque
import time
import uuid
from ..correlation.features import PayloadFeatures
from ..events import NetworkEvent
from .policy import PORT_FAMILIES, ResponsePolicy
from .privacy import Privacy
from .protocols import ProtocolSession
from .selector import profile_seed, select_profile


class DeceptionEngine:
    def __init__(self, config, secret, sink, *, load=None, probes=None):
        self.config, self.secret, self.sink = config, secret, sink
        self.policy = ResponsePolicy(config)
        self.privacy = Privacy(secret, usernames=config.deception.username_policy, preview=config.deception.preview_enabled)
        self.features = PayloadFeatures(probes or {}, config.fingerprint.min_probe_evidence)
        self.load = load or (lambda: {'pressure': 0.0, 'failed': False})
        self.metrics = Counter()
        self.loss_until = 0.0
        self._cpu_stamp, self._cpu_previous, self._cpu_ratio = time.monotonic(), time.process_time(), 0.0

    def pressure(self):
        result = self.load()
        now, cpu = time.monotonic(), time.process_time()
        elapsed = now - self._cpu_stamp
        if elapsed >= 1:
            # Saturation of one process CPU-second per wall second, not host utilization.
            self._cpu_ratio = min(1.0, max(0.0, (cpu - self._cpu_previous) / elapsed))
            self._cpu_stamp, self._cpu_previous = now, cpu
        return max(result['pressure'], self._cpu_ratio), result['failed'] or now < self.loss_until

    def open(self, peer, destination):
        return ManagedSession(self, peer, destination)


class ManagedSession:
    def __init__(self, engine, peer, destination):
        self.engine, self.peer, self.destination = engine, peer, destination
        self.started = time.monotonic()
        self.connection_id = uuid.uuid4().hex
        pressure, failed = engine.pressure()
        self.decision = engine.policy.decide(peer[0], destination, pressure=pressure, failed=failed, charge=False)
        self.protocol = None
        self.profile = None
        self.delay = 0.0
        self.closed = self.decision.action != 'respond'
        self.reported_closed = False
        self.pending = deque()
        self.sent_total = self.received_total = self.command_count = 0
        self.previous_digest = ''
        self.max_request = engine.config.limits.max_request_bytes
        self.idle_timeout = engine.config.limits.idle_timeout
        self.total_timeout = engine.config.limits.total_timeout
        if not self.closed:
            dec = engine.config.deception
            family = dec.port_profiles.get(str(destination[1]), PORT_FAMILIES.get(destination[1]))
            self.profile = select_profile(engine.secret, *destination, 'tcp', dec.catalogue_version, family)
            self.protocol = ProtocolSession(self.profile, engine.config.limits, engine.privacy,
                max_messages=1 if self.decision.load_mode == 'DEGRADED' else dec.max_messages,
                max_transitions=dec.max_transitions, features=engine.features)
            self.max_request = self.protocol.max_request
            self.idle_timeout, self.total_timeout = self.protocol.idle_timeout, self.protocol.total_timeout
            if dec.jitter_enabled:
                seed = profile_seed(engine.secret, *destination, 'tcp', dec.catalogue_version)
                self.delay = (dec.jitter_min_ms + int.from_bytes(seed[:2], 'big') % (dec.jitter_max_ms - dec.jitter_min_ms + 1)) / 1000

    def event(self, kind, command='NONE', request=0, response=0, **extra):
        observations = {'profile_id': self.profile.profile_id if self.profile else None,
            'profile_version': self.profile.profile_version if self.profile else None,
            'catalogue_version': self.engine.config.deception.catalogue_version,
            'service_family': self.profile.service_family if self.profile else None,
            'connection_id': self.connection_id, 'request_length': request, 'response_length': response,
            'duration': max(0, time.monotonic() - self.started), 'command_class': command,
            'load_mode': self.engine.policy.load.mode, **extra}
        event = NetworkEvent(self.peer[0], self.peer[1],
            self.destination[0] if self.destination else None, self.destination[1] if self.destination else None,
            'tcp', kind, observations=observations,
            limitations=['synthetic_service_profile', 'single_sensor_visibility', 'no_client_identity_attribution'])
        if not self.engine.sink.emit(event):
            self.engine.metrics['telemetry_drops'] += 1
            self.engine.loss_until = time.monotonic() + self.engine.config.deception.recovery_seconds
        self.engine.metrics['events'] += 1
        return event.event_id

    def start(self):
        self.event(EventType.DECEPTION_CONNECTION, completed_handshake=True, policy_reason=self.decision.reason,
                   original_destination='linux_ipv4_required' if self.engine.config.deception.redirected else 'direct_socket')
        return self._steps(self.protocol.start()) if self.protocol else b''

    def allowed(self, *, charge=False):
        pressure, failed = self.engine.pressure()
        self.decision = self.engine.policy.decide(self.peer[0], self.destination, pressure=pressure, failed=failed,
            profile_id=self.profile.profile_id if self.profile else None, charge=charge)
        if self.decision.load_mode == 'DEGRADED' and self.protocol:
            self.protocol.max_messages = min(self.protocol.max_messages, 1)
        return self.decision.action == 'respond'

    def _steps(self, steps):
        output = []
        for step in steps:
            if step.command != 'GREETING' and self.command_count >= 1 and self.decision.load_mode == 'DEGRADED':
                self.closed = True
                break
            if step.command != 'GREETING':
                self.command_count += 1
                flags = {'credential_like_attempt': step.credential, 'protocol_anomaly': step.anomaly,
                         'response_continuation': self.sent_total > 0, 'protocol_family': self.profile.service_family}
                if step.probe_digest:
                    flags.update(probe_digest=step.probe_digest, probe_name=step.probe_name)
                if step.safe_preview:
                    flags['safe_preview'] = step.safe_preview
                if step.username:
                    flags['username_hash' if self.engine.config.deception.username_policy == 'hash' else 'username_redacted'] = step.username
                parent = self.event(EventType.PROTOCOL_COMMAND, step.command, step.request_length, **flags)
                if self.command_count == 1:
                    self.event(EventType.PROTOCOL_PROBE, step.command, step.request_length, parent_event_id=parent)
                if step.credential:
                    self.event(EventType.CREDENTIAL_ATTEMPT, step.command, step.request_length, parent_event_id=parent, **flags)
                if step.anomaly:
                    self.event(EventType.PROTOCOL_ANOMALY, step.command, step.request_length, parent_event_id=parent)
            if step.response:
                if not self.allowed(charge=True):
                    self.closed = True
                    break
                output.append(step.response)
                self.pending.append([step.command, len(step.response), 0])
            self.closed = self.closed or step.close
        return b''.join(output)

    def feed(self, data):
        self.received_total += len(data)
        if not self.protocol or not self.allowed():
            self.closed = True
            return b''
        return self._steps(self.protocol.feed(data))

    def sent_bytes(self, size):
        self.sent_total += size
        self.engine.metrics['response_bytes'] += size
        while size and self.pending:
            row = self.pending[0]
            amount = min(size, row[1] - row[2])
            row[2] += amount
            size -= amount
            if row[2] == row[1]:
                self.event(EventType.DECEPTION_RESPONSE, row[0], response=row[2])
                self.pending.popleft()

    def close(self, reason):
        if self.reported_closed:
            return
        self.reported_closed, self.closed = True, True
        if self.protocol:
            self.protocol.close()
        if self.pending and self.pending[0][2]:
            row = self.pending[0]
            self.event(EventType.DECEPTION_RESPONSE, row[0], response=row[2], partial=True)
        self.pending.clear()
        self.event(EventType.CONNECTION_CLOSED, request=self.received_total, response=self.sent_total, close_reason=reason)
        self.engine.metrics['closed'] += 1
