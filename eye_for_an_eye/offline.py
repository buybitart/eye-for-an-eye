"""Local classic-PCAP replay; no listener, capture helper or enrichment process."""
from .event_types import EventType
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from itertools import chain
from pathlib import Path
import struct
import sqlite3
import sys
from .analysis import EventAnalysis
from .config import load_config
from .events import EventPipeline, NetworkEvent
from .network.capture import PacketObserver
from .storage.sqlite import SQLiteStore
from .security.privileges import ensure_analysis_user


def packets(path, *, max_bytes=536870912):
    path = Path(path)
    if not path.is_file() or path.stat().st_size > max_bytes:
        raise ValueError('PCAP missing or exceeds input budget')
    with path.open('rb') as stream:
        header = stream.read(24)
        formats = {b'\xd4\xc3\xb2\xa1': ('<', 1000000), b'\xa1\xb2\xc3\xd4': ('>', 1000000),
                   b'\x4d\x3c\xb2\xa1': ('<', 1000000000), b'\xa1\xb2\x3c\x4d': ('>', 1000000000)}
        if len(header) != 24 or header[:4] not in formats:
            raise ValueError('unsupported capture format; classic PCAP v2.4 required (PCAPNG unsupported)')
        order, scale = formats[header[:4]]
        major, minor, _, _, snaplen, linktype = struct.unpack(order + 'HHIIII', header[4:])
        if (major, minor) != (2, 4) or not 1 <= snaplen <= 1048576 or linktype not in (1, 101, 113, 228, 229, 276):
            raise ValueError('unsupported PCAP version, linktype or snaplen')
        consumed = 24
        while True:
            frame = stream.read(16)
            if not frame:
                break
            if len(frame) != 16:
                raise ValueError('truncated PCAP record header')
            seconds, fraction, included, original = struct.unpack(order + 'IIII', frame)
            consumed += 16 + included
            if fraction >= scale or included > min(snaplen, 1048576) or included > original or consumed > max_bytes:
                raise ValueError('invalid or oversized PCAP record')
            data = stream.read(included)
            if len(data) != included:
                raise ValueError('truncated PCAP record body')
            if linktype == 1:
                if len(data) < 14:
                    yield seconds + fraction / scale, b''
                    continue
                kind, offset = int.from_bytes(data[12:14], 'big'), 14
                for _ in range(2):
                    if kind not in (0x8100, 0x88a8):
                        break
                    if len(data) < offset + 4:
                        kind = 0
                        break
                    kind, offset = int.from_bytes(data[offset + 2:offset + 4], 'big'), offset + 4
                if kind not in (0x800, 0x86dd):
                    continue
                data = data[offset:]
            elif linktype in (113, 276):
                offset = 16 if linktype == 113 else 20
                kind = int.from_bytes(data[14:16] if linktype == 113 else data[:2], 'big')
                if len(data) < offset or kind not in (0x800, 0x86dd):
                    continue
                data = data[offset:]
            yield seconds + fraction / scale, data


class OfflineSink:
    def __init__(self, config, writer, *, max_output_bytes=67108864):
        self.config, self.writer = config, writer
        self.analysis = EventAnalysis(config, offline=True)
        self.stats = Counter()
        self.store = SQLiteStore(config.storage) if config.storage.enabled else None
        self.max_output_bytes = max_output_bytes

    def emit(self, event):
        event.sensor_id = self.config.runtime.sensor_id
        event = NetworkEvent.from_json(event.to_json())
        for record in self.analysis.process(event):
            encoded = record.to_json()
            self.stats['events'] += 1
            if self.store and not self.store.write(record):
                self.stats['storage_dropped'] += 1
            size = len(encoded) + 1
            if self.stats['output_bytes'] + size <= self.max_output_bytes:
                self.writer(encoded + '\n')
                self.stats['output_bytes'] += size
            else:
                self.stats['output_dropped'] += 1
        return True


def analyze_pcap(path, config=None, *, writer=None, max_packets=100000, max_input_bytes=536870912,
                 max_output_bytes=67108864, on_final=None):
    config = (config or load_config()).validate()
    if config.enrichment.enabled or config.enrichment.rdap_enabled or config.active_probes.enabled or config.firewall.enabled or config.enforcement.enabled:
        raise ValueError('offline analysis forbids enrichment, active probes and firewall policies')
    if not 1 <= max_packets <= 1000000 or not 24 <= max_input_bytes <= 2147483648 or not 4096 <= max_output_bytes <= 1073741824:
        raise ValueError('invalid offline processing budget')
    ensure_analysis_user(config.runtime.enforce_unprivileged)
    # Concrete IP parsers only; importing scapy.all would initialize live metadata.
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
    from scapy.error import Scapy_Exception
    sink = OfflineSink(config, writer or sys.stdout.write, max_output_bytes=max_output_bytes)
    observer = PacketObserver(config, EventPipeline(sink), mode='offline')
    count, limited = 0, False
    reader = packets(path, max_bytes=max_input_bytes)
    try:
        first = next(reader, None)  # Validate input/header before creating storage.
        sink.analysis.start()
        if sink.store:
            sink.store.open()
        for stamp, data in chain(() if first is None else (first,), reader):
            if count >= max_packets:
                limited = True
                break
            count += 1
            try:
                if not data or data[0] >> 4 not in (4, 6):
                    raise ValueError('missing IP header')
                packet = IP(data) if data[0] >> 4 == 4 else IPv6(data)
                packet.time = stamp
                observer.observe(packet)
            except (ValueError, TypeError, IndexError, struct.error, RecursionError, Scapy_Exception):
                observer.errors += 1
                sink.emit(NetworkEvent('unknown', event_type=EventType.PARSE_ERROR, observations={'reason': 'malformed_offline_packet'},
                    timestamp=datetime.fromtimestamp(stamp, timezone.utc)))
        for sensor, source, result in sink.analysis.correlator.final_results():
            if on_final:
                on_final(sensor, source, result)
            # Final summaries are emitted even when rate limiting suppressed an intermediate result.
            sink.emit(result.event(NetworkEvent(source, sensor_id=sensor)))
        return {'packets': count, 'parse_errors': observer.errors, 'packet_limit_reached': limited,
                **sink.stats, 'correlation': sink.analysis.correlator.snapshot()}
    finally:
        sink.analysis.close()
        reader.close()
        if sink.store:
            sink.store.close()


def cli(argv):
    parser = argparse.ArgumentParser(prog='eye-for-an-eye analyze-pcap')
    parser.add_argument('pcap')
    parser.add_argument('--config')
    parser.add_argument('--output', help='new JSONL file; default stdout')
    parser.add_argument('--probes')
    parser.add_argument('--p0f-db')
    parser.add_argument('--storage-path')
    parser.add_argument('--max-packets', type=int, default=100000)
    parser.add_argument('--max-input-bytes', type=int, default=536870912)
    parser.add_argument('--max-output-bytes', type=int, default=67108864)
    args = parser.parse_args(argv)
    output = None
    try:
        config = load_config(args.config, validate=False)
        if args.probes:
            config.probes_path = args.probes
        if args.p0f_db:
            config.capture.p0f_db = args.p0f_db
        if args.storage_path:
            config.storage.enabled, config.storage.path = True, args.storage_path
        config.validate()
        if config.enrichment.enabled or config.enrichment.rdap_enabled or config.active_probes.enabled or config.firewall.enabled:
            raise ValueError('offline analysis forbids enrichment, active probes and firewall policies')
        if args.output:
            output = Path(args.output).open('x', encoding='utf-8')
        stats = analyze_pcap(args.pcap, config, writer=output.write if output else sys.stdout.write,
            max_packets=args.max_packets, max_input_bytes=args.max_input_bytes, max_output_bytes=args.max_output_bytes)
        sys.stderr.write(json.dumps(stats) + '\n')
        return 1 if stats.get('storage_dropped') or stats.get('output_dropped') or stats['packet_limit_reached'] else 0
    except (OSError, ValueError, ImportError, RuntimeError, sqlite3.Error) as exc:
        sys.stderr.write(f'offline analysis failed: {type(exc).__name__}: {exc}\n')
        return 1
    finally:
        if output:
            output.close()
