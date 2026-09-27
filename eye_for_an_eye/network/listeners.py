"""Portable selectors-based bounded TCP handling and receive-only UDP."""
from collections import Counter
from dataclasses import dataclass, field
import ipaddress
import errno
import selectors
import socket
import struct
import sys
import threading
import time
from ..limits import TokenBucket


def original_destination(sock, *, redirected=False):
    """Direct listeners use local endpoint; required redirect lookup fails closed."""
    if not redirected:
        local = sock.getsockname()
        return local[0], local[1]
    if sys.platform.startswith('linux') and sock.family == socket.AF_INET and sock.type == socket.SOCK_STREAM:
        try:
            raw = sock.getsockopt(socket.SOL_IP, 80, 16)
            if len(raw) == 16 and struct.unpack('=H', raw[:2])[0] == socket.AF_INET:
                address, port = socket.inet_ntoa(raw[4:8]), struct.unpack('!H', raw[2:4])[0]
                if port and not ipaddress.ip_address(address).is_unspecified and not ipaddress.ip_address(address).is_multicast:
                    return address, port
        except OSError:
            pass
    return None  # IPv6/UDP redirect unsupported; never fabricate an original endpoint.


@dataclass
class Connection:
    sock: socket.socket
    peer: tuple
    destination: tuple
    started: float
    activity: float
    request: bytearray = field(default_factory=bytearray)
    response: bytes = b''
    sent: int = 0
    session: object = None
    received_total: int = 0
    sent_total: int = 0
    send_at: float = 0.0


class SelectorServer:
    def __init__(self, config, *, on_data, on_connect=None, on_status=None,
                 port=None, max_duration=None, max_accepts=None, lab_only=False, session_factory=None):
        self.config = config.validate()
        self.on_data, self.on_connect, self.on_status = on_data, on_connect, on_status
        self.session_factory = session_factory
        self.deception = getattr(session_factory, '__self__', None)
        if session_factory and config.network.protocol != 'tcp':
            raise ValueError('stateful deception supports TCP only')
        if session_factory and config.network.port in config.firewall.real_service_ports + config.firewall.management_ports:
            raise ValueError('deception listener cannot bind a protected service port')
        self.port = config.network.port if port is None else port
        if not 0 <= self.port <= 65535:
            raise ValueError('invalid port')
        self.max_duration, self.max_accepts, self.lab_only = max_duration, max_accepts, lab_only
        if lab_only and not ipaddress.ip_address(config.network.bind_address).is_loopback:
            raise ValueError('LAB ONLY: loopback required')
        self.ready = threading.Event()
        self.cancel = threading.Event()
        self.address = None
        self.error = None
        self.heartbeat = 0.0
        self.running = False
        self._connections = {}
        self._sources = Counter()
        self.metrics = Counter()
        self._rate = TokenBucket(config.limits.connections_per_second)

    @property
    def active_connections(self):
        return len(self._connections)

    def stop(self):
        self.cancel.set()

    def _call(self, callback, *args):
        try:
            return callback(*args)
        except Exception:
            # Isolate application/plugin failure, while propagating cancellation signals.
            self.metrics['handler_errors'] += 1
            return b''

    def _close(self, selector, state, reason):
        if id(state) not in self._connections:
            return
        try:
            selector.unregister(state.sock)
        except (KeyError, ValueError):
            pass  # cleanup is idempotent
        try:
            state.sock.close()
        finally:
            self._connections.pop(id(state), None)
            self._sources[state.peer[0]] -= 1
            if self._sources[state.peer[0]] <= 0:
                del self._sources[state.peer[0]]
            self.metrics['closed'] += 1
        if state.session:
            self._call(state.session.close, reason)
        state.request.clear()
        if self.on_status:
            self._call(self.on_status, state.peer, state.destination, reason)

    def _response(self, selector, state, data):
        if not data:
            return
        if not isinstance(data, bytes):
            raise TypeError('handler response must be bytes')
        remaining = self.config.limits.max_response_bytes - state.sent_total
        if len(data) > remaining:
            self._close(selector, state, 'response_limit')
            return
        state.response, state.sent = data, 0
        state.send_at = time.monotonic() + (state.session.delay if state.session else 0)
        selector.modify(state.sock, selectors.EVENT_WRITE, state)

    def _accept(self, selector, listener):
        for _ in range(16):
            if self.max_accepts and self.metrics['accepted'] >= self.max_accepts:
                return
            try:
                client, peer = listener.accept()
            except BlockingIOError:
                return
            except ConnectionAbortedError:
                self.metrics['aborted_accepts'] += 1
                continue
            transferred = False
            try:
                limit = self.config.limits
                if (not self._rate.allow() or len(self._connections) >= limit.max_connections or
                        self._sources[peer[0]] >= limit.max_connections_per_ip or
                        (self.lab_only and not ipaddress.ip_address(peer[0]).is_loopback)):
                    self.metrics['rejected'] += 1
                    continue
                client.setblocking(False)
                now = time.monotonic()
                destination = original_destination(client, redirected=bool(self.session_factory and self.config.deception.redirected))
                state = Connection(client, peer, destination, now, now)
                selector.register(client, selectors.EVENT_READ, state)
                self._connections[id(state)] = state
                self._sources[peer[0]] += 1
                self.metrics['accepted'] += 1
                transferred = True
                if self.session_factory:
                    state.session = self.session_factory(peer, destination)
                    response = state.session.start()
                    self._response(selector, state, response)
                    if not response and state.session.closed:
                        self._close(selector, state, 'observe_only')
                elif self.on_connect:
                    self._response(selector, state, self._call(self.on_connect, peer, state.destination))
            except Exception:
                self.metrics['handler_errors'] += 1
                if transferred:
                    self._close(selector, state, 'handler_error')
            finally:
                if not transferred:
                    client.close()

    def _tcp(self, selector, state, mask):
        try:
            if state.session and not state.session.allowed():
                self._close(selector, state, 'policy_observe_only')
                return
            if mask & selectors.EVENT_WRITE:
                if time.monotonic() < state.send_at:
                    return
                sent = state.sock.send(state.response[state.sent:])
                if sent == 0:
                    self._close(selector, state, 'broken_pipe')
                    return
                state.sent += sent
                state.sent_total += sent
                self.metrics['response_bytes'] += sent
                if state.session:
                    state.session.sent_bytes(sent)
                state.activity = time.monotonic()
                if state.sent == len(state.response):
                    if state.session and not state.session.closed:
                        state.response, state.sent = b'', 0
                        selector.modify(state.sock, selectors.EVENT_READ, state)
                    else:
                        self._close(selector, state, 'response_complete')
                return
            maximum = min(self.config.limits.max_request_bytes, state.session.max_request) if state.session else self.config.limits.max_request_bytes
            remaining = maximum - state.received_total
            if remaining <= 0:
                self._close(selector, state, 'request_limit')
                return
            data = state.sock.recv(min(4096, remaining))
            if not data:
                self._close(selector, state, 'eof')
                return
            state.received_total += len(data)
            if not state.session:
                state.request.extend(data)
            state.activity = time.monotonic()
            self.metrics['request_bytes'] += len(data)
            response = state.session.feed(data) if state.session else self._call(self.on_data, state.peer, state.destination, bytes(state.request))
            self._response(selector, state, response)
            if not state.response and (state.received_total >= maximum or (state.session and state.session.closed)):
                self._close(selector, state, 'request_limit')
        except BlockingIOError:
            return
        except Exception:
            self.metrics['handler_errors'] += 1
            self._close(selector, state, 'io_or_handler_error')

    def _udp(self, listener):
        try:
            data, peer = listener.recvfrom(self.config.limits.max_request_bytes + 1)
        except BlockingIOError:
            return
        except OSError as exc:
            # Windows raises WSAEMSGSIZE instead of returning a truncated datagram.
            if exc.errno in (errno.EMSGSIZE, errno.ECONNRESET) or getattr(exc, 'winerror', None) in (10040, 10054):
                self.metrics['dropped_datagrams'] += 1
                return
            raise
        if not self._rate.allow() or len(data) > self.config.limits.max_request_bytes:
            self.metrics['dropped_datagrams'] += 1
            return
        local = listener.getsockname()
        # No sendto path: arbitrary UDP cannot trigger reflection in P0.
        self._call(self.on_data, peer, (local[0], local[1]), data)
        self.metrics['datagrams'] += 1

    def serve_forever(self):
        selector = selectors.DefaultSelector()
        listener = None
        started = time.monotonic()
        try:
            family = socket.AF_INET6 if ':' in self.config.network.bind_address else socket.AF_INET
            tcp = self.config.network.protocol == 'tcp'
            listener = socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
            if family == socket.AF_INET6:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            if sys.platform != 'win32':
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.config.network.bind_address, self.port))
            listener.setblocking(False)
            if tcp:
                listener.listen(self.config.limits.max_connections)
            selector.register(listener, selectors.EVENT_READ, None)
            self.address = listener.getsockname()[:2]
            self.ready.set()
            self.running = True
            while not self.cancel.is_set():
                now = time.monotonic()
                self.heartbeat = now
                if self.max_duration is not None and now - started >= self.max_duration:
                    break
                if self.max_accepts and self.metrics['accepted'] >= self.max_accepts:
                    if listener is not None:
                        selector.unregister(listener)
                        listener.close()
                        listener = None
                    if not self._connections:
                        break
                selected = selector.select(.05)
                for key, mask in selected:
                    if self.cancel.is_set():
                        break
                    if key.data is None:
                        if tcp:
                            self._accept(selector, key.fileobj)
                        else:
                            self._udp(key.fileobj)
                    else:
                        self._tcp(selector, key.data, mask)
                now = time.monotonic()
                for state in list(self._connections.values()):
                    idle = self.config.limits.idle_timeout if state.request or state.response else self.config.limits.first_byte_timeout
                    total = self.config.limits.total_timeout
                    if state.session:
                        if state.received_total or state.sent_total:
                            idle = self.config.limits.idle_timeout
                        idle = min(state.session.idle_timeout, idle)
                        total = min(total, state.session.total_timeout)
                    if now - state.started >= total or now - state.activity >= idle:
                        self._close(selector, state, 'timeout')
                # Writable sockets awaiting a tiny optional jitter must not busy-spin.
                if selected and all(key.data and key.data.send_at > now for key, _ in selected):
                    self.cancel.wait(min(.01, min(key.data.send_at - now for key, _ in selected)))
        except (OSError, ValueError, TypeError) as exc:
            self.error = exc
        finally:
            self.running = False
            self.ready.set()
            for state in list(self._connections.values()):
                self._close(selector, state, 'shutdown')
            if listener is not None:
                listener.close()
            selector.close()
