"""Offline Scapy decode -> PacketObserver -> serialization -> P2; no sockets."""
import tracemalloc
import struct
from benchmarks.common import config, configuration, measure
from eye_for_an_eye.events import EventPipeline
from eye_for_an_eye.network.capture import PacketObserver
from eye_for_an_eye.offline import OfflineSink


def run(full=False):
    from scapy.layers.inet import IP, TCP
    settings = config()
    rows = [bytes(IP(src=f'192.0.2.{i % 16 + 1}', dst='192.0.2.100', id=i, ttl=51) /
                  TCP(sport=1234, dport=8000 + i % 32, flags='S', options=[('MSS',1460),('Timestamp',(i,0))]))
            for i in range(64)]
    sink = OfflineSink(settings, lambda line: None, max_output_bytes=134217728)
    observer = PacketObserver(settings, EventPipeline(sink))
    def packet(index):
        value = IP(rows[index % len(rows)])
        value.time = 1700000000 + index / 1000
        observer.observe(value)
    count = 1000 if full else 300
    result = measure(count, packet)
    tracemalloc.start()
    for index in range(32):
        packet(count + index)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    malformed = [b'', b'\x45' + b'\0' * 8, rows[0][:24], rows[0][:41]]
    def bad(index):
        try:
            value = IP(malformed[index % len(malformed)])
            value.time = 1700000100 + index / 1000
            observer.observe(value)
        except (ValueError, IndexError, TypeError, struct.error):
            pass
    return {'configuration': configuration(settings), 'workload': {'packets': count, 'sources': 16,
        'payload_sizes': sorted(set(map(len,rows))), 'socket_traffic': False}, 'pipeline': result,
        'malformed': measure(200, bad), 'events': dict(sink.stats),
        'allocation_sample_32_packets': {'current_bytes': current,'peak_bytes': peak,'timing_separate': True}}
