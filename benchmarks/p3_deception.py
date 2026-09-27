"""Finite localhost-only measurements; worker is killed by the parent watchdog."""
import argparse
import ctypes
from ctypes import wintypes
import gc
import hashlib
import json
from pathlib import Path
import platform
import socket
import statistics
import subprocess
import sys
import threading
import time
from eye_for_an_eye.config import Config
from eye_for_an_eye.deception.engine import DeceptionEngine
from eye_for_an_eye.deception.privacy import Privacy
from eye_for_an_eye.deception.profiles import PROFILES
from eye_for_an_eye.deception.protocols import ProtocolSession
from eye_for_an_eye.network.listeners import SelectorServer
from eye_for_an_eye.runtime import EventRuntime


def resources():
    result = {'threads': threading.active_count(), 'cpu_seconds': time.process_time()}
    if sys.platform == 'win32':
        class Memory(ctypes.Structure):
            _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD),
                        ('PeakWorkingSetSize', ctypes.c_size_t), ('WorkingSetSize', ctypes.c_size_t),
                        ('QuotaPeakPagedPoolUsage', ctypes.c_size_t), ('QuotaPagedPoolUsage', ctypes.c_size_t),
                        ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t), ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
                        ('PagefileUsage', ctypes.c_size_t), ('PeakPagefileUsage', ctypes.c_size_t)]
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        process = kernel.GetCurrentProcess
        process.restype = wintypes.HANDLE
        handle = process()
        count = wintypes.DWORD()
        counter = kernel.GetProcessHandleCount
        counter.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        memory = Memory()
        memory.cb = ctypes.sizeof(memory)
        query = ctypes.WinDLL('psapi', use_last_error=True).GetProcessMemoryInfo
        query.argtypes = [wintypes.HANDLE, ctypes.POINTER(Memory), wintypes.DWORD]
        if not counter(handle, ctypes.byref(count)) or not query(handle, ctypes.byref(memory), memory.cb):
            raise OSError(ctypes.get_last_error(), 'resource query failed')
        result.update(handles=count.value, rss_bytes=memory.WorkingSetSize, fd_kind='Windows process handles, includes more than sockets')
    elif Path('/proc/self/status').is_file():
        status = Path('/proc/self/status').read_text()
        rss = next(line for line in status.splitlines() if line.startswith('VmRSS:'))
        result.update(handles=len(list(Path('/proc/self/fd').iterdir())), rss_bytes=int(rss.split()[1]) * 1024, fd_kind='Linux /proc/self/fd')
    else:
        result.update(handles=None, rss_bytes=None, fd_kind='unavailable')
    return result


class DiscardLogger:
    def __init__(self):
        self.metrics = {}

    def start(self):
        pass

    def emit(self, event):
        event.to_json()
        return True

    def close(self, timeout=0):
        return True


def measure(count, idle):
    before = resources()
    config = Config()
    config.limits.max_connections = config.limits.max_connections_per_ip = 128
    config.limits.connections_per_second = 1000
    config.limits.first_byte_timeout = 3
    runtime = EventRuntime(config, logger=DiscardLogger(), mode='services')
    server = None
    def load():
        value = runtime.deception_load()
        if server:
            value['pressure'] = max(value['pressure'], server.active_connections / config.limits.max_connections)
        return value
    engine = DeceptionEngine(config, bytes(range(32)), runtime, load=load)  # Public fixture, never a runtime default.
    server = SelectorServer(config, on_data=lambda *args: b'', session_factory=engine.open, port=0, max_duration=20)
    runtime.attach(listener=server)
    runtime.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    clients = []
    latencies = []
    response_bytes = completed = 0
    try:
        if not server.ready.wait(2) or server.error:
            raise RuntimeError('benchmark listener startup failed')
        address = server.address
        engine.policy.ports = {address[1]}
        config.deception.port_profiles[str(address[1])] = 'http'
        started, cpu = time.perf_counter(), time.process_time()
        for _ in range(count):
            stamp = time.perf_counter()
            with socket.create_connection(address, timeout=2) as client:
                client.sendall(b'GET / HTTP/1.0\r\n\r\n')
                received = b''
                try:
                    while chunk := client.recv(1024):
                        received += chunk
                        if len(received) > 1024:
                            raise AssertionError('response budget exceeded')
                except ConnectionResetError:
                    pass
                response_bytes += len(received)
                completed += received.startswith(b'HTTP/1.0 200 OK')
            latencies.append((time.perf_counter() - stamp) * 1000)
        elapsed, cpu = time.perf_counter() - started, time.process_time() - cpu
        # Drain the finite workload before separately measuring idle connections.
        deadline = time.monotonic() + 10
        while not runtime.queue.empty() and time.monotonic() < deadline:
            time.sleep(.02)
        if not runtime.queue.empty():
            raise RuntimeError('benchmark analysis drain exceeded budget')
        gc.collect()
        idle_before = resources()
        for _ in range(idle):
            clients.append(socket.create_connection(address, timeout=2))
        deadline = time.monotonic() + 1
        while server.active_connections < idle and time.monotonic() < deadline:
            time.sleep(.01)
        active = server.active_connections
        idle_during = resources()
    finally:
        stopped = time.monotonic()
        server.stop()
        thread.join(2)
        for client in clients:
            client.close()
        closed = runtime.close(timeout=10)
        shutdown = time.monotonic() - stopped
    if thread.is_alive() or not closed or server.error:
        raise RuntimeError('benchmark failed bounded shutdown')
    after = resources()
    parser_timings = []
    privacy = Privacy(bytes(range(32)))
    for index in range(count):
        profile = PROFILES[index % len(PROFILES)]
        parser = ProtocolSession(profile, config.limits, privacy)
        parser.start()
        request = {'http': b'GET / HTTP/1.0\r\n\r\n', 'ftp': b'SYST\r\n', 'ssh': b'SSH-2.0-Client\r\n'}[profile.service_family]
        stamp = time.perf_counter()
        parser.feed(request)
        parser_timings.append((time.perf_counter() - stamp) * 1000)
    parser_timings.sort()
    digest = hashlib.sha256()
    for path in sorted(Path('eye_for_an_eye').rglob('*.py')):
        digest.update(path.as_posix().encode())
        digest.update(path.read_bytes())
    ordered = sorted(latencies)
    def percentile(fraction):
        return ordered[int((len(ordered) - 1) * fraction)]
    return {'schema_version': 1, 'source_sha256': digest.hexdigest(), 'python': platform.python_version(),
        'platform': platform.platform(), 'workload': 'localhost HTTP + real event queue/P2 correlation/JSON serialization; no SQLite',
        'connections': count, 'completed_http_responses': completed, 'connections_per_second': count / elapsed,
        'seconds': elapsed, 'cpu_seconds': cpu, 'latency_mean_ms': statistics.mean(latencies),
        'latency_p50_ms': percentile(.5), 'latency_p95_ms': percentile(.95), 'latency_p99_ms': percentile(.99),
        'handler_latency_p50_ms': parser_timings[int((count - 1) * .5)],
        'handler_latency_p95_ms': parser_timings[int((count - 1) * .95)],
        'handler_latency_p99_ms': parser_timings[int((count - 1) * .99)],
        'handler_workload': '100 calls round-robin HTTP/FTP/SSH ProtocolSession.feed; construction and telemetry queue excluded',
        'response_bytes': response_bytes, 'queue_drops': runtime.queue.dropped,
        'idle_requested': idle, 'active_connections_measured': active,
        'rss_bytes_per_idle_connection': (idle_during['rss_bytes'] - idle_before['rss_bytes']) / active if active and idle_during['rss_bytes'] is not None else None,
        'rss_delta_idle_bytes': idle_during['rss_bytes'] - idle_before['rss_bytes'] if idle_during['rss_bytes'] is not None else None,
        'resources_before': before, 'resources_idle_before': idle_before, 'resources_idle': idle_during, 'resources_after': after,
        'shutdown_seconds': shutdown, 'active_after_shutdown': server.active_connections,
        'response_limit': config.limits.max_response_bytes, 'deception': dict(engine.metrics),
        'limitations': ['single synthetic Windows/Linux process run', 'client sockets share measured process with server',
                        'latency is full loopback interaction, includes scheduling and telemetry enqueue',
                        'RSS delta includes allocator/runtime noise, not isolated per-connection ownership',
                        'CPU uses process CPU time; native handle count is not exclusively socket FDs',
                        'logging disk writes, SQLite and live redirected traffic are not benchmarked']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--connections', type=int, default=100)
    parser.add_argument('--idle', type=int, default=100)
    parser.add_argument('--output', required=True)
    parser.add_argument('--worker', action='store_true')
    args = parser.parse_args()
    if not 10 <= args.connections <= 200 or not 1 <= args.idle <= 100:
        parser.error('bounded benchmark supports 10..200 connections and 1..100 idle clients')
    if not args.worker:
        result = subprocess.run([sys.executable, '-B', '-X', 'utf8', '-m', 'benchmarks.p3_deception', '--worker',
            '--connections', str(args.connections), '--idle', str(args.idle), '--output', args.output],
            timeout=40, capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stderr[-3000:])
        print(result.stdout)
        return
    data = measure(args.connections, args.idle)
    Path(args.output).write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: data[key] for key in ('connections_per_second', 'active_connections_measured', 'queue_drops', 'shutdown_seconds')}))


if __name__ == '__main__':
    main()
