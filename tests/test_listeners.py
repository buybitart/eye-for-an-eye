import socket
import threading
import time
import unittest
import selectors
from unittest.mock import Mock
from eye_for_an_eye.config import Config
from eye_for_an_eye.network.listeners import Connection, SelectorServer


class ListenerTests(unittest.TestCase):
    def test_partial_write_keeps_unsent_tail_and_closes_once(self):
        server = SelectorServer(Config(), on_data=lambda *args: b'')
        connection = Mock()
        connection.send.side_effect = [2, BlockingIOError(), 3]
        selector = Mock()
        state = Connection(connection, ('127.0.0.1', 12345), ('127.0.0.1', 80), 1, 1,
                           response=b'ABCDE')
        server._connections[id(state)] = state
        server._sources[state.peer[0]] = 1
        for _ in range(3):
            server._tcp(selector, state, selectors.EVENT_WRITE)
        self.assertEqual([call.args[0] for call in connection.send.call_args_list], [b'ABCDE', b'CDE', b'CDE'])
        connection.close.assert_called_once()
        self.assertEqual(server.active_connections, 0)
        self.assertEqual(server.metrics['response_bytes'], 5)

    def test_per_source_limit_with_spare_global_capacity(self):
        config = Config()
        config.limits.max_connections = 8
        config.limits.max_connections_per_ip = 1
        address = self.start_server(config=config)
        with socket.create_connection(address, timeout=1):
            deadline = time.monotonic() + 1
            while self.server.active_connections != 1 and time.monotonic() < deadline:
                time.sleep(.01)
            with socket.create_connection(address, timeout=1) as second:
                self.assertEqual(second.recv(1), b'')
            self.assertEqual(self.server.active_connections, 1)
            self.assertGreaterEqual(self.server.metrics['rejected'], 1)

    def start_server(self, *, protocol='tcp', callback=None, connect=None, config=None):
        config = config or Config()
        config.network.protocol = protocol
        self.server = SelectorServer(config, on_data=callback or (lambda *args: b'OK'), on_connect=connect, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.assertTrue(self.server.ready.wait(2))
        self.assertIsNone(self.server.error)
        self.addCleanup(self.stop_server)
        return self.server.address

    def stop_server(self):
        self.server.stop()
        self.thread.join(2)
        self.assertFalse(self.thread.is_alive())
        self.assertEqual(self.server.active_connections, 0)

    def test_idle_client_does_not_block_second(self):
        address = self.start_server()
        with socket.create_connection(address, timeout=1) as idle, socket.create_connection(address, timeout=1) as active:
            active.sendall(b'hello')
            self.assertEqual(active.recv(8), b'OK')
            idle.settimeout(0.1)
            with self.assertRaises(socket.timeout):
                idle.recv(1)

    def test_deadline_and_shutdown(self):
        config = Config()
        config.limits.first_byte_timeout = 0.15
        config.limits.idle_timeout = 0.15
        config.limits.total_timeout = 0.3
        address = self.start_server(config=config)
        with socket.create_connection(address, timeout=1) as client:
            self.assertEqual(client.recv(1), b'')

    def test_request_and_response_limits(self):
        observed = []
        config = Config()
        config.limits.max_request_bytes = 32
        config.limits.max_response_bytes = 8
        address = self.start_server(config=config, callback=lambda p, d, data: observed.append(data) or b'x' * 100)
        with socket.create_connection(address, timeout=1) as client:
            client.sendall(b'a' * 128)
            result = b''
            try:
                while chunk := client.recv(128):
                    result += chunk
            except ConnectionResetError:
                pass  # closing an oversized request can reset unread kernel data
        self.assertLessEqual(len(result), 8)
        self.assertTrue(observed)
        self.assertLessEqual(max(map(len, observed)), 32)

    def test_connection_limit(self):
        config = Config()
        config.limits.max_connections = config.limits.max_connections_per_ip = 1
        address = self.start_server(config=config)
        with socket.create_connection(address, timeout=1):
            deadline = time.monotonic() + 1
            while self.server.active_connections != 1 and time.monotonic() < deadline:
                time.sleep(.01)
            with socket.create_connection(address, timeout=1) as second:
                self.assertEqual(second.recv(1), b'')
            self.assertLessEqual(self.server.active_connections, 1)

    def test_udp_never_responds_even_if_callback_returns_data(self):
        observed = threading.Event()
        address = self.start_server(protocol='udp', callback=lambda *args: observed.set() or b'must not send')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(.2)
            client.sendto(b'hello', address)
            self.assertTrue(observed.wait(1))
            with self.assertRaises(socket.timeout):
                client.recvfrom(1024)

    def test_oversized_udp_does_not_stop_listener(self):
        observed = threading.Event()
        config = Config()
        config.limits.max_request_bytes = 32
        address = self.start_server(protocol='udp', config=config,
                                    callback=lambda *args: observed.set())
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.sendto(b'x' * 1024, address)
            time.sleep(.1)
            self.assertTrue(self.thread.is_alive())
            self.assertFalse(observed.is_set())
            client.sendto(b'', address)
            self.assertTrue(observed.wait(1))
        self.assertEqual(self.server.metrics['dropped_datagrams'], 1)

    def test_shutdown_closes_live_clients(self):
        address = self.start_server()
        with socket.create_connection(address, timeout=1) as client:
            self.server.stop()
            self.thread.join(2)
            self.assertFalse(self.thread.is_alive())
            try:
                self.assertEqual(client.recv(1), b'')
            except ConnectionResetError:
                pass  # Windows may reset a connection still in the accept backlog.

    def test_total_deadline_applies_to_continuously_active_client(self):
        config = Config()
        config.limits.first_byte_timeout = .2
        config.limits.idle_timeout = .2
        config.limits.total_timeout = .35
        address = self.start_server(config=config, callback=lambda *args: b'')
        started = time.monotonic()
        with socket.create_connection(address, timeout=1) as client:
            client.settimeout(.05)
            while time.monotonic() - started < 1:
                try:
                    client.sendall(b'x')
                    if client.recv(1) == b'':
                        break
                except socket.timeout:
                    continue
                except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                    break
            else:
                self.fail('total deadline was not enforced')
        self.assertLess(time.monotonic() - started, .8)

    def test_callback_failure_is_contained(self):
        def broken(*args):
            raise RuntimeError('bad callback')
        address = self.start_server(callback=broken)
        with socket.create_connection(address, timeout=1) as client:
            client.sendall(b'data')
            time.sleep(.1)
            self.assertTrue(self.thread.is_alive())
            self.assertGreater(self.server.metrics['handler_errors'], 0)
