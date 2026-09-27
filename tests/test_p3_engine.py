import json
import socket
import struct
import threading
import time
import unittest
from unittest.mock import Mock, patch
from eye_for_an_eye.config import Config, load_config
from eye_for_an_eye.correlation.engine import CorrelationEngine
from eye_for_an_eye.deception.engine import DeceptionEngine
from eye_for_an_eye.deception.policy import LoadController
from eye_for_an_eye.events import NetworkEvent
from eye_for_an_eye.network.listeners import SelectorServer, original_destination
from eye_for_an_eye.runtime import EventRuntime


class Sink:
    def __init__(self):
        self.events = []
        self.accept = True

    def emit(self, event):
        self.events.append(NetworkEvent.from_json(event.to_json()))
        return self.accept


class EngineTests(unittest.TestCase):
    def start(self, family='ftp', config=None, load=None):
        config = config or Config()
        self.sink = Sink()
        self.engine = DeceptionEngine(config, bytes(range(32)), self.sink, load=load)
        self.server = SelectorServer(config, on_data=lambda *args: b'', session_factory=self.engine.open, port=0, max_duration=6)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)
        self.assertTrue(self.server.ready.wait(2))
        self.assertIsNone(self.server.error)
        address = self.server.address
        config.deception.port_profiles[str(address[1])] = family
        self.engine.policy.ports = {address[1]}
        return address

    def stop(self):
        self.server.stop()
        self.thread.join(2)
        self.assertFalse(self.thread.is_alive())
        self.assertIsNone(self.server.error)
        self.assertEqual(self.server.active_connections, 0)

    def test_real_ftp_dialog_and_private_telemetry_reaches_correlation(self):
        address = self.start()
        with socket.create_connection(address, timeout=1) as client:
            self.assertTrue(client.recv(1024).startswith(b'220'))
            client.sendall(b'USER sensitive-user\r\n')
            self.assertTrue(client.recv(1024).startswith(b'331'))
            client.sendall(b'PASS password-value\r\n')
            self.assertTrue(client.recv(1024).startswith(b'530'))
            client.sendall(b'QUIT\r\n')
            self.assertTrue(client.recv(1024).startswith(b'221'))
            self.assertEqual(client.recv(1), b'')
        self.stop()
        encoded = '\n'.join(event.to_json() for event in self.sink.events)
        self.assertNotIn('sensitive-user', encoded)
        self.assertNotIn('password-value', encoded)
        kinds = {event.event_type for event in self.sink.events}
        self.assertTrue({'deception_connection', 'protocol_command', 'protocol_probe',
                         'credential_attempt', 'deception_response', 'connection_closed'} <= kinds)
        closed = next(event for event in self.sink.events if event.event_type == 'connection_closed')
        self.assertEqual(closed.observations['response_length'], self.server.metrics['response_bytes'])
        engine = CorrelationEngine(Config().correlation)
        for event in self.sink.events:
            engine.observe(event)
        final = next(engine.final_results())[2]
        self.assertEqual(final.features['connection_attempts'], 1)
        self.assertEqual(final.features['credential_attempts'], 2)
        self.assertEqual(final.features['response_continuations'], 3)
        self.assertTrue(all(event.observations.get('profile_id') == 'ftp-control-v2' for event in self.sink.events))

    def test_real_http_and_ssh_stability_and_close(self):
        for family, request, expected in (('http', b'HEAD / HTTP/1.0\r\n\r\n', b'HTTP/1.0 200'),
                                           ('ssh', b'SSH-2.0-Client\r\n', b'SSH-2.0-')):
            address = self.start(family)
            outputs = []
            for _ in range(2):
                with socket.create_connection(address, timeout=1) as client:
                    if family == 'http':
                        client.sendall(request)
                    response = client.recv(1024)
                    outputs.append(response)
                    self.assertTrue(response.startswith(expected))
                    if family == 'ssh':
                        client.sendall(request)
                    self.assertEqual(client.recv(1), b'')
            self.assertEqual(outputs[0], outputs[1])
            self.stop()

    def test_overload_stops_existing_response_and_new_greeting(self):
        load = {'pressure': 0., 'failed': False}
        address = self.start(load=lambda: load.copy())
        with socket.create_connection(address, timeout=1) as client:
            greeting = client.recv(1024)
            self.assertTrue(greeting.startswith(b'220'))
            sent = len(greeting)
            load['pressure'] = .95
            client.sendall(b'SYST\r\n')
            try:
                self.assertEqual(client.recv(1), b'')
            except ConnectionResetError:
                pass  # Windows can reset when closing with unread request bytes.
            with socket.create_connection(address, timeout=1) as second:
                self.assertEqual(second.recv(1), b'')
            self.assertEqual(self.server.metrics['response_bytes'], sent)
        self.assertEqual(self.engine.policy.load.mode, 'OBSERVE_ONLY')

    def test_failed_telemetry_never_increases_traffic(self):
        address = self.start()
        self.sink.accept = False
        with socket.create_connection(address, timeout=1) as client:
            self.assertEqual(client.recv(1), b'')
        self.assertEqual(self.server.metrics['response_bytes'], 0)
        self.assertGreater(self.engine.metrics['telemetry_drops'], 0)

    def test_hysteresis_and_degraded_message_budget(self):
        clock = [1.]
        control = LoadController(Config().deception, clock=lambda: clock[0])
        self.assertEqual(control.update(.75), 'DEGRADED')
        self.assertEqual(control.update(.95), 'OBSERVE_ONLY')
        self.assertEqual(control.update(.1), 'OBSERVE_ONLY')
        clock[0] += 3
        self.assertEqual(control.update(.1), 'NORMAL')
        address = self.start(load=lambda: {'pressure': .75, 'failed': False})
        with socket.create_connection(address, timeout=1) as client:
            client.recv(1024)
            client.sendall(b'SYST\r\nFEAT\r\nQUIT\r\n')
            self.assertEqual(client.recv(1024), b'215 UNIX Type: L8\r\n')
            self.assertEqual(client.recv(1), b'')

    def test_100_idle_clients_and_bounded_shutdown(self):
        config = Config()
        config.limits.max_connections = config.limits.max_connections_per_ip = 128
        config.limits.connections_per_second = 200
        address = self.start('http', config)
        clients = []
        try:
            for _ in range(100):
                clients.append(socket.create_connection(address, timeout=1))
            deadline = time.monotonic() + 1
            while self.server.active_connections < 100 and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(self.server.active_connections, 100)
            self.assertEqual(self.server.metrics['response_bytes'], 0)
            self.stop()
        finally:
            for client in clients:
                client.close()

    def test_reconnect_oversize_and_slow_clients(self):
        config = Config()
        config.limits.first_byte_timeout = config.limits.idle_timeout = .15
        config.limits.total_timeout = .3
        address = self.start('http', config)
        for _ in range(25):
            with socket.create_connection(address, timeout=1) as client:
                client.sendall(b'GET / HTTP/1.0\r\n\r\n')
                self.assertTrue(client.recv(1024).startswith(b'HTTP/'))
        with socket.create_connection(address, timeout=1) as client:
            self.assertEqual(client.recv(1), b'')
        with socket.create_connection(address, timeout=1) as client:
            client.sendall(b'x' * 5000)
            try:
                self.assertEqual(client.recv(1), b'')
            except ConnectionResetError:
                pass
        self.stop()
        self.assertLessEqual(self.server.metrics['request_bytes'], 25 * 18 + 4096)
        self.assertEqual(self.engine.metrics['closed'], self.server.metrics['closed'])

    def test_queue_saturation_and_storage_slowdown_signals(self):
        config = Config()
        config.runtime.queue_events = 2
        runtime = EventRuntime(config)
        event = NetworkEvent('127.0.0.1')
        runtime.emit(event)
        runtime.emit(event)
        self.assertEqual(runtime.deception_load()['pressure'], 1.)
        sink = Sink()
        engine = DeceptionEngine(config, bytes(range(32)), sink, load=runtime.deception_load)
        session = engine.open(('127.0.0.1', 12345), ('127.0.0.1', 1234))
        self.assertEqual(session.start(), b'')
        session.close('test')
        runtime.queue.discard()
        runtime.store = Mock(status='healthy')
        runtime.storage_started = time.monotonic() - .2
        self.assertEqual(runtime.deception_load()['pressure'], 1.)

    def test_unknown_redirect_and_protected_ports_fail_closed(self):
        config = Config()
        config.deception.redirected = True
        sink = Sink()
        engine = DeceptionEngine(config, bytes(range(32)), sink)
        self.assertEqual(engine.open(('127.0.0.1', 1), None).start(), b'')
        self.assertEqual(engine.open(('127.0.0.1', 1), ('127.0.0.1', 22)).start(), b'')
        for setting in ('real_service_ports', 'management_ports'):
            config = Config()
            setattr(config.firewall, setting, [1234])
            with self.assertRaises(ValueError):
                config.validate()
        config = Config()
        config.deception.mode = 'lab'
        config.deception.source_allowlist = ['192.0.2.1/32']
        config.validate()
        config.deception.source_allowlist = ['8.8.8.8/32']
        with self.assertRaises(ValueError):
            config.validate()

    def test_original_destination_ipv4_contract_and_unsupported_ipv6_udp(self):
        sock = Mock(family=socket.AF_INET, type=socket.SOCK_STREAM)
        sock.getsockname.return_value = ('127.0.0.1', 1234)
        sock.getsockopt.return_value = struct.pack('=H', socket.AF_INET) + struct.pack('!H', 80) + socket.inet_aton('192.0.2.1') + bytes(8)
        with patch('eye_for_an_eye.network.listeners.sys.platform', 'linux'):
            self.assertEqual(original_destination(sock, redirected=True), ('192.0.2.1', 80))
            self.assertEqual(original_destination(sock), ('127.0.0.1', 1234))
            sock.getsockopt.side_effect = OSError()
            self.assertIsNone(original_destination(sock, redirected=True))
            sock.family = socket.AF_INET6
            self.assertIsNone(original_destination(sock, redirected=True))
            sock.family, sock.type = socket.AF_INET, socket.SOCK_DGRAM
            self.assertIsNone(original_destination(sock, redirected=True))

    def test_many_source_simulations_and_no_network_effects(self):
        sink = Sink()
        engine = DeceptionEngine(Config(), bytes(range(32)), sink)
        with patch('socket.socket', side_effect=AssertionError('outbound socket')), \
             patch('subprocess.Popen', side_effect=AssertionError('execution')), \
             patch('builtins.open', side_effect=AssertionError('filesystem')):
            for index in range(600):
                value = engine.open((f'192.0.2.{1 + index % 250}', 1234), ('127.0.0.1', 1234))
                self.assertEqual(value.start(), b'')
                value.close('test')
        self.assertFalse(hasattr(engine, 'sessions'))
        self.assertNotIn('192.0.2.1', str(engine.metrics))

    def test_config_mode_and_secret_redaction(self):
        config = load_config(environ={'E4E__DECEPTION__PORT_PROFILES': '{"1234":"ftp"}'})
        self.assertEqual(config.deception.port_profiles['1234'], 'ftp')
        self.assertFalse(config.network.udp_responses)
        from eye_for_an_eye.config import redacted_config
        self.assertNotIn(bytes(range(32)).hex(), json.dumps(redacted_config(config)))

    def test_all_handlers_no_shell_file_fetch_or_callbacks(self):
        for family, request in (
                ('http', b'GET /../../etc/passwd?token=TOP_SECRET HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic TOP_SECRET\r\n\r\n'),
                ('ftp', b'USER PRIVATE_NAME\r\nPASS TOP_SECRET\r\nSITE EXEC cmd\r\nPORT 8,8,8,8,0,80\r\nRETR ../../file\r\nQUIT\r\n'),
                ('ssh', b'SSH-2.0-Client\r\ncommand execution\r\n')):
            config = Config()
            config.deception.port_profiles = {'1234': family}
            config.deception.preview_enabled = True
            sink = Sink()
            engine = DeceptionEngine(config, bytes(range(32)), sink)
            with patch('socket.socket', side_effect=AssertionError('outbound socket')), \
                 patch('socket.getaddrinfo', side_effect=AssertionError('DNS/SSRF')), \
                 patch('subprocess.Popen', side_effect=AssertionError('execution')), \
                 patch('builtins.open', side_effect=AssertionError('filesystem')):
                value = engine.open(('127.0.0.1', 12345), ('127.0.0.1', 1234))
                greeting = value.start()
                value.sent_bytes(len(greeting))
                response = value.feed(request)
                value.sent_bytes(len(response))
                value.close('done')
            encoded = '\n'.join(event.to_json() for event in sink.events)
            self.assertNotIn('TOP_SECRET', encoded)
            self.assertNotIn('PRIVATE_NAME', encoded)
            self.assertLessEqual(len(greeting) + len(response), 1024)

    def test_deterministic_jitter_and_total_deadline(self):
        config = Config()
        config.deception.jitter_enabled = True
        config.deception.port_profiles = {'1234': 'ftp'}
        engine = DeceptionEngine(config, bytes(range(32)), Sink())
        first = engine.open(('127.0.0.1', 1), ('127.0.0.1', 1234))
        second = engine.open(('127.0.0.1', 2), ('127.0.0.1', 1234))
        self.assertEqual(first.delay, second.delay)
        self.assertTrue(.01 <= first.delay <= .15)
        config.limits.first_byte_timeout = config.limits.idle_timeout = .2
        config.limits.total_timeout = .3
        address = self.start('ftp', config)
        started = time.monotonic()
        with socket.create_connection(address, timeout=1) as client:
            client.recv(1024)
            self.assertEqual(client.recv(1), b'')
        self.assertLess(time.monotonic() - started, .7)

    def test_mid_batch_degradation_does_not_send_all_parsed_responses(self):
        load = {'pressure': 0., 'failed': False}
        sink = Sink()
        config = Config()
        config.deception.port_profiles = {'1234': 'ftp'}
        engine = DeceptionEngine(config, bytes(range(32)), sink, load=lambda: load.copy())
        value = engine.open(('127.0.0.1', 1), ('127.0.0.1', 1234))
        value.sent_bytes(len(value.start()))
        emit = sink.emit
        def changed(event):
            if event.event_type == 'protocol_command':
                load['pressure'] = .75
            return emit(event)
        sink.emit = changed
        response = value.feed(b'SYST\r\nFEAT\r\nQUIT\r\n')
        self.assertEqual(response, b'215 UNIX Type: L8\r\n')
        self.assertTrue(value.closed)
