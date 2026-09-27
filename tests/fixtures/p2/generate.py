"""Generate only small, synthetic local captures. No packet transmission."""
import hashlib
import json
from pathlib import Path
import struct


def write_pcap(path, rows):
    with Path(path).open('wb') as stream:
        stream.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65575, 101))
        for stamp, data in rows:
            stream.write(struct.pack('<IIII', int(stamp), int((stamp % 1) * 1000000), len(data), len(data)))
            stream.write(data)


def generate(directory):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    def packet(port=80):
        return bytes(IP(src='192.0.2.1', dst='198.51.100.1', ttl=51, id=1) / TCP(sport=1234, dport=port, seq=10, flags='S'))
    write_pcap(root / 'scan.pcap', [(index + 1, packet(1000 + index)) for index in range(32)])
    write_pcap(root / 'noise.pcap', [(1, packet())])
    malformed_tcp = bytearray(bytes(TCP(sport=1234, dport=80, flags='SF', options=[('MSS', 1460)])))
    malformed_tcp[21] = 0
    ipv6 = bytes(IPv6(src='2001:db8::1', dst='2001:db8::2', hlim=51, fl=123) / IPv6ExtHdrHopByHop() / TCP())
    write_pcap(root / 'malformed.pcap', [(1, packet()[:10]), (2, bytes(IP(src='192.0.2.1', dst='198.51.100.1', proto=6) / bytes(malformed_tcp))),
                                        (3, ipv6), (2.5, packet()), (2.5, packet())])
    samples = []
    for name, label in [('scan', 'scanner'), ('noise', 'noise')]:
        filename = name + '.pcap'
        samples.append({'id': name, 'pcap': filename, 'sha256': hashlib.sha256((root / filename).read_bytes()).hexdigest(),
            'expected_labels': [{'src_ip': '192.0.2.1', 'window_seconds': 60, 'label': label}],
            'metadata': {'description': 'small deterministic final-window contract fixture'},
            'source': {'kind': 'synthetic', 'generator': 'generate.py', 'external_capture': False}})
    (root / 'corpus.json').write_text(json.dumps({'schema_version': 1, 'samples': samples}, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    generate(Path(__file__).parent)
