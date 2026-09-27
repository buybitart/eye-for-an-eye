"""SOURCE A, live mode: real loopback sessions against the production sensor.

A client opens real TCP connections to real listeners bound on 127.0.0.1. The events are
produced by `SelectorServer` and `DeceptionEngine` - the same code the honeypot runs - so the
timing is real and the observation shape is not an imitation of the sensor, it is the sensor.

The safety boundary here is not ours alone: production config validation refuses deception
`mode = lab` unless the bind address is loopback and the source allowlist is narrow and
non-global. A run that is not local does not start.

Live runs are short by construction, because real time cannot be compressed. They are the
smallest and most trustworthy part of the LAB source, and they cross-check the event schema the
time-compressed scenarios emulate.
"""
from contextlib import contextmanager
import secrets
import socket
import threading
import time
from eye_for_an_eye.config import Config
from eye_for_an_eye.deception.engine import DeceptionEngine
from eye_for_an_eye.event_types import EventType
from eye_for_an_eye.events import NetworkEvent
from eye_for_an_eye.network.listeners import SelectorServer
from ..generators.base import REQUESTS, rng
from ..safety import SafetyLimits, validate_live_target

LIVE_LIMITS = SafetyLimits(max_duration_seconds=45, max_connections=200, max_packets=2000,
                           max_bytes=262_144, max_destinations=8, max_samples=80)
PROFILES = ('http', 'ssh', 'ftp')
CORRELATION_INPUT = (EventType.CONNECTION_ACCEPTED, EventType.SERVICE_PROBE, EventType.PACKET_OBSERVED,
                     EventType.DECEPTION_CONNECTION, EventType.PROTOCOL_COMMAND)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class _Sink:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)
        return True


def lab_config(ports, *, bind='127.0.0.1'):
    """Production config for a loopback lab honeypot. Validation refuses anything wider."""
    validate_live_target(bind)
    config = Config()
    config.deployment.profile = 'honeypot'
    config.deception.mode = 'lab'
    config.deception.source_allowlist = ['127.0.0.1/32', '::1/128']
    config.network.bind_address = bind
    config.network.port = ports[0]
    config.deception.decoy_ports = list(ports)
    config.deception.port_profiles = {str(port): PROFILES[index % len(PROFILES)]
                                      for index, port in enumerate(ports)}
    config.limits.max_connections = config.limits.max_connections_per_ip = 32
    config.storage.enabled = config.api.enabled = config.metrics.enabled = False
    config.ml.enabled = False
    return config.validate()


@contextmanager
def sensor(port_count=3, *, plain_ports=1, max_seconds=45):
    """Bind decoy listeners plus a plain service listener on loopback and yield the sink."""
    decoys = []
    while len(decoys) < port_count:
        candidate = free_port()
        if candidate not in decoys:
            decoys.append(candidate)
    plain = []
    while len(plain) < plain_ports:
        candidate = free_port()
        if candidate not in decoys and candidate not in plain:
            plain.append(candidate)
    config = lab_config(decoys)
    sink = _Sink()
    engine = DeceptionEngine(config, secrets.token_bytes(32), sink)
    servers, threads = [], []

    def accepted(peer, destination):
        sink.emit(NetworkEvent(peer[0], peer[1], destination[0], destination[1], 'tcp',
                               EventType.CONNECTION_ACCEPTED,
                               observations={'completed_handshake': True},
                               limitations=['single_sensor_visibility']))
        return b''

    try:
        for port in decoys:
            server = SelectorServer(config, on_data=lambda *args: b'', session_factory=engine.open,
                                    on_connect=accepted, port=port, max_duration=max_seconds,
                                    max_accepts=LIVE_LIMITS.max_connections)
            servers.append(server)
        for port in plain:
            # A plain service listener, so a decoy interaction is not the only thing the live
            # sensor ever sees and `deception_60s` cannot stand in for the source or the label.
            server = SelectorServer(config, on_data=lambda *args: b'+OK lab\r\n', on_connect=accepted,
                                    port=port, max_duration=max_seconds,
                                    max_accepts=LIVE_LIMITS.max_connections)
            servers.append(server)
        for server in servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
            if not server.ready.wait(3) or server.error:
                raise RuntimeError(f'lab listener did not start: {server.error}')
        yield sink, decoys + plain, config
    finally:
        for server in servers:
            server.stop()
        for thread in threads:
            thread.join(2)


def _talk(port, messages, *, timeout=1.5, read=True):
    """One bounded conversation with a local listener. Errors are the point sometimes."""
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=timeout) as client:
            for message in messages:
                if message:
                    client.sendall(message)
                if read:
                    try:
                        client.recv(2048)
                    except OSError:
                        break
                time.sleep(.01)
    except OSError:
        return False
    return True


# Short live behaviours. Both label classes touch decoy and plain ports, so neither the port
# nor a decoy interaction can stand in for the label.
LIVE_SCENARIOS = {
    'live/benign/service-client': {
        'label': 'benign_like', 'kind': 'benign', 'family': 'live-benign-client',
        'connections': 8, 'gap': (.25, .7), 'ports': 'few',
        'bodies': ('http_get', 'http_status', 'ssh_banner'), 'read': True},
    'live/benign/health-probe': {
        'label': 'benign_like', 'kind': 'hard_negative', 'family': 'live-benign-health',
        'connections': 14, 'gap': (.18, .28), 'ports': 'few',
        'bodies': ('http_head', 'http_metrics'), 'read': True},
    'live/malicious/decoy-enumeration': {
        'label': 'malicious_automation_like', 'kind': 'malicious_automation',
        'family': 'live-malicious-enumeration',
        'connections': 16, 'gap': (.1, .3), 'ports': 'all',
        'bodies': ('http_get', 'ftp_feat', 'redis_probe', 'binary_probe', 'generic_probe'), 'read': True},
    'live/malicious/credential-probe': {
        'label': 'malicious_automation_like', 'kind': 'malicious_automation',
        'family': 'live-malicious-credential',
        'connections': 14, 'gap': (.15, .35), 'ports': 'few',
        'bodies': ('ftp_user', 'auth_probe', 'login_probe'), 'read': True},
}


def run(scenario_id, run_index, *, max_seconds=25):
    """Execute one live scenario and return the events the production sensor produced."""
    if scenario_id not in LIVE_SCENARIOS:
        raise KeyError('unknown live scenario')
    spec = LIVE_SCENARIOS[scenario_id]
    stream = rng(f'{scenario_id}:{run_index}:live')
    started = time.time()
    with sensor(max_seconds=max_seconds) as (sink, ports, config):
        pool = ports if spec['ports'] == 'all' else ports[:2]
        deadline = time.monotonic() + max_seconds
        attempted = failed = 0
        for index in range(spec['connections']):
            if time.monotonic() > deadline:
                break
            port = pool[index % len(pool)] if spec['ports'] == 'all' else stream.choice(pool)
            body = REQUESTS[stream.choice(spec['bodies'])]
            messages = [body] if stream.random() < .8 else [body, REQUESTS['http_status']]
            attempted += 1
            if not _talk(port, messages, read=spec['read']):
                failed += 1
            time.sleep(stream.uniform(*spec['gap']))
        time.sleep(.4)
    events = sorted((event for event in sink.events if event.event_type in CORRELATION_INPUT),
                    key=lambda event: (event.timestamp, event.event_id))
    return events, {'scenario_id': scenario_id, 'run': run_index, 'label': spec['label'],
                    'kind': spec['kind'], 'family': spec['family'],
                    'connections_attempted': attempted, 'connections_failed': failed,
                    'listeners': len(ports), 'wall_seconds': round(time.time() - started, 3),
                    'events': len(events), 'transmitted_packets': 0,
                    'target_policy': 'loopback only, enforced by production config validation'}
