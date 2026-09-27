"""Packet-level capture generator for the PCAP source.

The LAB generator describes behaviour; this one describes packets. It varies TTL, IP ID, TCP
options, window size, segmentation, retransmission and delivery order, and it can emit IPv6
flows and truncated captures. Those are exactly the properties the packet parser and the
fingerprint modules read and the behaviour generator never exercises, which is what makes PCAP
a different source rather than the same source in a different file.

Still synthetic. It is written to disk and read back offline; nothing is transmitted.
"""
from dataclasses import dataclass, field
from ..safety import Budget, SafetyLimits, validate_synthetic_address
from .base import AUTH_OUTCOMES, rng
from .packets import auth_banner, write_pcap

CAPTURE_LIMITS = SafetyLimits(max_duration_seconds=600, max_connections=1500, max_packets=12000,
                              max_bytes=4_194_304, max_destinations=16)
# Deliberately varied so no single stack signature marks a class or a capture.
TTLS = (48, 52, 56, 64, 116, 128, 255)
WINDOWS = (4096, 8192, 16384, 29200, 64240, 65535)
OPTION_SETS = (
    [('MSS', 1460)],
    [('MSS', 1460), ('SAckOK', b''), ('NOP', None), ('WScale', 7)],
    [('MSS', 1360), ('NOP', None), ('NOP', None), ('Timestamp', (0, 0)), ('SAckOK', b'')],
    [('MSS', 536)],
    [],
)
BANNERS = {80: b'HTTP/1.1 200 OK\r\nServer: lab\r\nContent-Length: 5\r\n\r\nok!\r\n',
           8080: b'HTTP/1.1 200 OK\r\nServer: lab\r\nContent-Length: 5\r\n\r\nok!\r\n',
           22: b'SSH-2.0-lab-server\r\n', 21: b'220 lab ftp ready\r\n'}
DEFAULT_BANNER = b'+OK lab\r\n'


@dataclass(slots=True)
class Flow:
    """One client conversation with packet-level detail."""
    time: float
    source: str
    destination: str
    port: int
    shape: str = 'exchange'
    request: bytes = b''
    ttl: int = 64
    window: int = 64240
    options: list = field(default_factory=list)
    retransmit: bool = False
    reorder: bool = False
    segments: int = 1
    version: int = 4
    #: P15.4, as in `base.Contact`. The outcome the server reported, rendered as
    #: a real reply. Kept here as well so a packet-detail scenario is not the one
    #: corner of the corpus that still cannot express an authentication failure.
    auth: str = ''

    def __post_init__(self):
        if self.auth not in AUTH_OUTCOMES:
            raise ValueError('unknown authentication outcome')


def _packet(flow, *, src, dst, sport, dport, flags, seq, ack, payload=b'', options=None, ttl=None,
            window=None, identifier=0):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6
    segment = TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack,
                  window=window if window is not None else flow.window,
                  options=options if options is not None else [])
    if flow.version == 6:
        network = IPv6(src=src, dst=dst, hlim=ttl if ttl is not None else flow.ttl)
    else:
        network = IP(src=src, dst=dst, ttl=ttl if ttl is not None else flow.ttl, id=identifier & 0xffff)
    return bytes(network / segment / payload)


def render(flows, *, seed, base_epoch=1767225600.0, limits=CAPTURE_LIMITS):
    """Flows -> [(timestamp, raw IP bytes)]. Deterministic for a given seed and flow list."""
    stream = rng(f'{seed}:capture')
    budget = Budget(limits)
    rows = []
    for index, flow in enumerate(flows):
        validate_synthetic_address(flow.source)
        validate_synthetic_address(flow.destination)
        budget.connection(flow.destination)
        budget.advance(flow.time)
        sport = stream.randrange(32768, 61000)
        client_seq = stream.randrange(1, 0x7fffffff)
        server_seq = stream.randrange(1, 0x7fffffff)
        identifier = stream.randrange(1, 0xffff)
        moment = flow.time
        banner = auth_banner(flow.auth, flow.port, BANNERS.get(flow.port, DEFAULT_BANNER))

        def emit(stamp, data):
            budget.packet(len(data))
            rows.append((base_epoch + stamp, data))

        syn = _packet(flow, src=flow.source, dst=flow.destination, sport=sport, dport=flow.port,
                      flags='S', seq=client_seq, ack=0, options=flow.options, identifier=identifier)
        emit(moment, syn)
        if flow.retransmit and stream.random() < .7:
            moment += stream.uniform(.2, 1.1)
            emit(moment, syn)  # identical retransmission: same sequence, same options
        if flow.shape == 'syn_only':
            continue
        if flow.shape == 'syn_reset':
            moment += stream.uniform(.0004, .004)
            emit(moment, _packet(flow, src=flow.destination, dst=flow.source, sport=flow.port,
                                 dport=sport, flags='RA', seq=0, ack=client_seq + 1, ttl=64,
                                 identifier=identifier + 1))
            continue
        moment += stream.uniform(.0004, .006)
        emit(moment, _packet(flow, src=flow.destination, dst=flow.source, sport=flow.port, dport=sport,
                             flags='SA', seq=server_seq, ack=client_seq + 1, options=flow.options,
                             ttl=64, identifier=identifier + 1))
        moment += stream.uniform(.0004, .006)
        emit(moment, _packet(flow, src=flow.source, dst=flow.destination, sport=sport, dport=flow.port,
                             flags='A', seq=client_seq + 1, ack=server_seq + 1, identifier=identifier + 2))
        if flow.shape == 'handshake':
            continue
        client_next, server_next = client_seq + 1, server_seq + 1
        moment += stream.uniform(.0006, .01)
        emit(moment, _packet(flow, src=flow.source, dst=flow.destination, sport=sport, dport=flow.port,
                             flags='PA', seq=client_next, ack=server_next, payload=flow.request,
                             identifier=identifier + 3))
        client_next += max(1, len(flow.request))
        if flow.shape in ('exchange', 'session'):
            # Segment the response the way a real stack would at this MSS.
            size = max(1, len(banner) // max(1, flow.segments))
            pieces = [banner[position:position + size] for position in range(0, len(banner), size)] or [banner]
            stamps = []
            for piece in pieces:
                moment += stream.uniform(.0004, .008)
                stamps.append((moment, piece))
            if flow.reorder and len(stamps) > 1:
                stamps[0], stamps[1] = (stamps[1][0], stamps[0][1]), (stamps[0][0], stamps[1][1])
            for stamp, piece in stamps:
                emit(stamp, _packet(flow, src=flow.destination, dst=flow.source, sport=flow.port,
                                    dport=sport, flags='PA', seq=server_next, ack=client_next,
                                    payload=piece, ttl=64, identifier=identifier + 4))
                server_next += len(piece)
        if flow.shape == 'session':
            for _ in range(2):
                moment += stream.uniform(.02, .3)
                emit(moment, _packet(flow, src=flow.source, dst=flow.destination, sport=sport,
                                     dport=flow.port, flags='PA', seq=client_next, ack=server_next,
                                     payload=flow.request, identifier=identifier + 5))
                client_next += max(1, len(flow.request))
                moment += stream.uniform(.0004, .008)
                emit(moment, _packet(flow, src=flow.destination, dst=flow.source, sport=flow.port,
                                     dport=sport, flags='PA', seq=server_next, ack=client_next,
                                     payload=banner, ttl=64, identifier=identifier + 6))
                server_next += len(banner)
        _ = index
    rows.sort(key=lambda row: row[0])
    return rows, budget.snapshot()


def write(path, flows, *, seed, snaplen=65535):
    rows, budget = render(flows, seed=seed)
    write_pcap(path, rows, snaplen=snaplen)
    return rows, budget


def stack(stream):
    """One consistent client stack signature per source, varied across sources."""
    return {'ttl': stream.choice(TTLS), 'window': stream.choice(WINDOWS),
            'options': list(stream.choice(OPTION_SETS))}


def sources(stream, count, network='203.0.113'):
    chosen = stream.sample(range(2, 250), k=count)
    return [f'{network}.{octet}' for octet in chosen]


def targets(stream, count, network='198.51.100'):
    chosen = stream.sample(range(1, 30), k=count)
    return [f'{network}.{octet}' for octet in chosen]
