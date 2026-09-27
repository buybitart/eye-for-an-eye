"""Capture is optional. Analysis uses measured fields and separate hypotheses."""
from ..event_types import EventType
from datetime import datetime, timezone
import math
import os
from pathlib import Path
import select
import socket
import stat
import sys
from ..events import NetworkEvent
from ..fingerprint.ip_id import IpIdTracker
from ..fingerprint.ttl import ttl_fingerprint
from ..fingerprint.tcp_timestamp import TimestampTracker
from ..fingerprint.tcp_options import tcp_options
from ..fingerprint.ipv6 import ipv6_observation
from ..fingerprint.p0f_adapter import P0fAdapter
from ..fingerprint.result import FingerprintResult
from ..fingerprint.path import allowed_address, path_characteristics
from ..fingerprint.probes import load_probes
from ..correlation.features import PayloadFeatures
from ..limits import TokenBucket
from .flow import FlowKey
from .flow_state import FlowEvidence
from .addressing import outer_ip as _outer_ip
from .ipc import receive_frame, validate_peer


class PacketObserver:
    def __init__(self, config, pipeline, *, mode='ip_id', path_service=None):
        self.config, self.pipeline, self.mode, self.path_service = config, pipeline, mode, path_service
        self.ids = IpIdTracker(config.limits.state_entries, config.limits.state_ttl, config.fingerprint.ip_id_samples)
        self.timestamps = TimestampTracker(config.limits.state_entries, config.limits.state_ttl)
        self.p0f = P0fAdapter(config.capture.p0f_db)
        self.clock = 0.0
        self.ids.cache.clock = self.timestamps.cache.clock = lambda: self.clock
        self.flows = FlowEvidence(config.limits.state_entries, config.limits.state_ttl, clock=lambda: self.clock)
        self.payload_features = PayloadFeatures(load_probes(config.probes_path) if config.probes_path else {},
                                               config.fingerprint.min_probe_evidence)
        self.path_rate = TokenBucket(1, burst=1)
        self.errors = 0
        self.ipc_status = 'healthy' if config.capture.pcap_path else 'degraded'
        if hasattr(pipeline.sink, 'attach'):
            pipeline.sink.attach(capture=self)

    def _result(self, base, result):
        self.pipeline.sink.emit(NetworkEvent(base.src_ip, base.src_port, base.dst_ip, base.dst_port, base.transport,
            EventType.FINGERPRINT_RESULT,
            observations={'parent_event_id': base.event_id, 'feature': result.feature, 'status': result.status,
                          'measurements': result.observations},
            hypotheses={result.feature: {'hypothesis': result.hypothesis, 'confidence': result.confidence,
                                        'evidence': result.evidence}},
            limitations=[*base.limitations, *result.limitations], timestamp=base.timestamp))

    def observe(self, packet):
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        from scapy.error import Scapy_Exception
        try:
            network = _outer_ip(packet)
            if network is None:
                raise ValueError('missing outer IP header')
            data = bytes(network)
            if len(data) > 65575:
                raise ValueError('packet budget exceeded')
            version = data[0] >> 4 if data else 0
            v6 = None
            if isinstance(network, IP) and version == 4:
                if len(data) < 20 or data[0] & 15 < 5:
                    raise ValueError('truncated IPv4')
                header = (data[0] & 15) * 4
                total = int.from_bytes(data[2:4], 'big')
                capture_truncated = header > len(data) or len(data) < total
                malformed = total < header
                flags = int.from_bytes(data[6:8], 'big')
                fragment = bool(flags & 0x3fff)
                ttl, protocol = data[8], data[9]
                offset = header
            elif isinstance(network, IPv6) and version == 6:
                v6 = ipv6_observation(data)
                ttl = v6.observations.get('hop_limit')
                capture_truncated = v6.observations['capture_truncated']
                malformed = v6.observations['malformed'] and not capture_truncated
                fragment = v6.observations['fragment_header'] is not None
                offset, protocol = v6.observations.get('upper_offset', len(data)), v6.observations.get('upper_protocol', 59)
                total = min(len(data), 40 + v6.observations.get('declared_payload_length', 0))
            else:
                raise ValueError('invalid outer IP')
            raw_transport = data[offset:total]
            tcp = protocol == 6 and not fragment and len(raw_transport) >= 20
            udp = protocol == 17 and not fragment and len(raw_transport) >= 8
            transport = ('tcp' if tcp else 'udp' if udp else 'icmp' if version == 4 and protocol == 1
                         else 'icmpv6' if version == 6 and protocol == 58 else 'other')
            source_port = int.from_bytes(raw_transport[:2], 'big') if tcp or udp else None
            destination_port = int.from_bytes(raw_transport[2:4], 'big') if tcp or udp else None
            stamp = float(packet.time)
            if not math.isfinite(stamp):
                raise ValueError('invalid time')
            self.clock = max(self.clock, stamp)
            options = tcp_options(raw_transport) if protocol == 6 and not fragment else None
            measured = {'ip_version': version, 'ttl_or_hop_limit': ttl, 'fragmented': fragment,
                        'capture_time': stamp, 'capture_truncated': capture_truncated,
                        'malformed': malformed or bool(options and options.observations['malformed'] and not capture_truncated)}
            if options:
                measured['tcp_flags'] = options.observations.get('flags')
                measured['syn_observed'] = bool(measured['tcp_flags'] is not None and measured['tcp_flags'] & 2 and not measured['tcp_flags'] & 16)
            flow = FlowKey(str(network.src), source_port, str(network.dst), destination_port, transport)
            if tcp and not options.observations['malformed'] and not malformed and not capture_truncated:
                body = raw_transport[(raw_transport[12] >> 4) * 4:]
                measured.update(self.payload_features.observe(body, 'tcp'))
                # The payload parser cannot know a packet's direction, so it
                # reports both halves of the authentication view and the flow
                # decides which one applies (P15.4).
                measured.update(self.flows.observe(flow, measured['tcp_flags'], options.observations['sequence'],
                                                  options.observations['acknowledgment'], len(body),
                                                  auth=measured))
            elif udp and not malformed and not capture_truncated:
                udp_length = int.from_bytes(raw_transport[4:6], 'big')
                if 8 <= udp_length <= len(raw_transport):
                    measured.update(self.payload_features.observe(raw_transport[8:udp_length], 'udp'))
                else:
                    measured['malformed'] = True
            base = NetworkEvent(str(network.src), source_port, str(network.dst), destination_port, transport,
                                observations=measured, timestamp=datetime.fromtimestamp(stamp, timezone.utc),
                                limitations=['capture_or_wire_truncation_indistinguishable'] if capture_truncated else [])
            self.errors += int(measured['malformed'])
            if not self.pipeline.record(base):
                return
            fp = self.config.fingerprint
            self._result(base, ttl_fingerprint(ttl, fp.initial_ttls, fp.max_hops, ipv6=version == 6))
            if version == 4:
                self._result(base, self.ids.observe(flow, int.from_bytes(data[4:6], 'big'), df=bool(flags & 0x4000),
                    mf=bool(flags & 0x2000), fragment_offset=flags & 0x1fff, observed_at=stamp))
            else:
                self._result(base, v6)
                self._result(base, FingerprintResult('ip_id', 'unsupported', evidence=['ipv6_has_no_ipv4_id']))
            if options:
                self._result(base, options)
                ts = options.observations.get('timestamps') or {}
                self._result(base, FingerprintResult('tcp_timestamp', 'unsupported', evidence=['malformed_tcp_options'])
                    if options.observations['malformed'] else self.timestamps.observe(flow, ts.get('tsval'), stamp,
                        tsecr=ts.get('tsecr'), reset=bool(measured.get('syn_observed'))))
            p0f_result = (self.p0f.fingerprint(network) if tcp and not malformed and not capture_truncated and not options.observations['malformed']
                          else FingerprintResult('p0f', 'unsupported', evidence=['unsupported_packet']))
            self._result(base, p0f_result)
            if self.mode == 'nat':
                self._result(base, path_characteristics(ttl, ipv6=version == 6))
            if self.mode == 'nat' and self.path_service and self.config.active_probes.enabled:
                if allowed_address(base.src_ip, self.config.active_probes.allowed_cidrs) and self.path_rate.allow():
                    self.path_service.submit(base.event_id, base.src_ip, {'observed_ttl': ttl})
        except (ValueError, TypeError, AttributeError, IndexError, OverflowError, RecursionError, Scapy_Exception):
            self.errors += 1
            self.pipeline.sink.emit(NetworkEvent('unknown', event_type=EventType.PARSE_ERROR,
                                   observations={'reason': 'malformed_packet'}))


def run_capture(config, pipeline, mode, cancel, path_service=None):
    from scapy.error import Scapy_Exception
    try:
        return _capture(config, pipeline, mode, cancel, path_service)
    except Scapy_Exception as exc:
        raise RuntimeError('capture backend failed; check input PCAP, interface, BPF and capture permissions') from exc


def _capture(config, pipeline, mode, cancel, path_service=None):
    from scapy.all import PcapReader
    observer = PacketObserver(config, pipeline, mode=mode, path_service=path_service)
    if config.capture.pcap_path:
        with PcapReader(config.capture.pcap_path) as reader:
            for packet in reader:
                if cancel.is_set():
                    break
                observer.observe(packet)
        return
    _ipc_capture(config, observer, cancel)


def _ipc_capture(config, observer, cancel):
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
    if not sys.platform.startswith('linux') or not config.capture.ipc_socket:
        raise ValueError('live analysis requires the Linux capture-helper IPC; use --pcap offline')
    path = Path(config.capture.ipc_socket)
    parent = path.parent.stat()
    if parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
        raise PermissionError('IPC directory must be owned by analysis user, without group/other write')
    if path.exists() or path.is_symlink():
        current = path.lstat()
        if not stat.S_ISSOCK(current.st_mode) or current.st_uid != os.geteuid():
            raise PermissionError('refusing to replace foreign IPC path')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as check:
            check.settimeout(.2)
            try:
                check.connect(str(path))
            except ConnectionRefusedError:
                path.unlink()
            else:
                raise RuntimeError('IPC analysis listener is already running')
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    inode = None
    try:
        listener.bind(str(path))
        inode = path.stat().st_ino
        path.chmod(0o660)
        listener.listen(1)
        listener.settimeout(.2)
        while not cancel.is_set():
            try:
                peer, _ = listener.accept()
            except TimeoutError:
                continue
            with peer:
                try:
                    validate_peer(peer, config.capture.helper_uid)
                    while not cancel.is_set():
                        if not select.select([peer], [], [], .2)[0]:
                            continue
                        raw, stamp = receive_frame(peer, max_bytes=config.capture.max_frame_bytes)
                        packet = IP(raw) if raw[0] >> 4 == 4 else IPv6(raw)
                        packet.time = stamp
                        observer.ipc_status = 'healthy'
                        observer.observe(packet)
                except (OSError, EOFError, ValueError):
                    observer.errors += 1
                finally:
                    observer.ipc_status = 'degraded'
    finally:
        listener.close()
        if inode is not None and path.exists() and path.stat().st_ino == inode:
            path.unlink()
