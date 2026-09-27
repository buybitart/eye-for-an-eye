"""One finite rootless loopback conversation with storage, status and API verification."""
import http.client
import json
from pathlib import Path
import secrets
import socket
import tempfile
import threading
import time
from .config import Config
from .deception.engine import DeceptionEngine
from .events import NetworkEvent
from .logging import EventLogger
from .network.listeners import SelectorServer
from .runtime import EventRuntime


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def run():
    config = Config()
    from .security.privileges import ensure_analysis_user
    ensure_analysis_user(config.runtime.enforce_unprivileged)
    config.deployment.profile = 'honeypot'
    ports = set()
    for _ in range(16):
        ports.add(free_port())
        if len(ports) == 3:
            break
    if len(ports) != 3:
        raise RuntimeError('could not allocate three distinct loopback demo ports')
    config.network.port, config.api.port, config.metrics.port = sorted(ports)
    config.deception.decoy_ports = [config.network.port]
    config.deception.port_profiles = {str(config.network.port): 'http'}
    config.limits.max_connections = config.limits.max_connections_per_ip = 4
    config.storage.enabled = config.api.enabled = config.metrics.enabled = True
    config.runtime.queue_events = 64
    config.storage.max_events = 100
    config.storage.max_bytes = 16777216
    with tempfile.TemporaryDirectory(prefix='e4e-demo-') as directory:
        config.storage.path = str(Path(directory)/'events.db')
        config.runtime.status_file = str(Path(directory)/'status.json')
        runtime = EventRuntime(config, logger=EventLogger(config.logging, writer=lambda line: None), mode='services')
        engine = DeceptionEngine(config, secrets.token_bytes(32), runtime, load=runtime.deception_load)
        def connected(peer, dst):
            runtime.emit(NetworkEvent(peer[0], peer[1], dst[0], dst[1]))
            return b''
        server = SelectorServer(config, on_data=lambda peer, dst, data: b'', session_factory=engine.open,
            max_duration=8, max_accepts=2, on_connect=connected)
        runtime.attach(listener=server)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        try:
            runtime.start()
            if any(endpoint.status != 'healthy' for endpoint in runtime.endpoints.values()):
                raise RuntimeError('demo operational endpoint bind failed')
            thread.start()
            if not server.ready.wait(2) or server.error:
                raise RuntimeError('demo listener did not start')
            with socket.create_connection(('127.0.0.1', config.network.port), timeout=2) as client:
                client.sendall(b'GET / HTTP/1.0\r\n\r\n')
                response = client.recv(1024)
            if not response.startswith(b'HTTP/'):
                raise RuntimeError('demo did not receive bounded HTTP response')
            deadline = time.monotonic()+3
            while runtime.registry.snapshot()['storage_writes_total'] < 1 and time.monotonic() < deadline:
                time.sleep(.01)
            connection = http.client.HTTPConnection('127.0.0.1', config.api.port, timeout=2)
            try:
                connection.request('GET', '/api/v1/events?limit=10')
                reply = connection.getresponse()
                body = json.loads(reply.read(65537))
                if reply.status != 200 or not body.get('items'):
                    raise RuntimeError('demo API did not expose the stored event')
            finally:
                connection.close()
            runtime._publish_status()
            result = {'schema_version': 1, 'status': 'complete', 'loopback_only': True, 'external_requests': 0,
                'response_bytes': len(response), 'stored_events': runtime.registry.snapshot()['storage_writes_total'],
                'api_status': reply.status, 'event': body['items'][0], 'health': runtime.health_response()}
        finally:
            stopping = time.monotonic()
            server.stop()
            if thread.ident is not None:
                thread.join(2)
            closed = runtime.close()
        if thread.is_alive() or not closed:
            raise RuntimeError('demo shutdown did not complete')
        result.update(shutdown_seconds=time.monotonic()-stopping, temporary_state_removed=True)
        return result
