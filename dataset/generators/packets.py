"""Render a behaviour plan into a small deterministic classic PCAP file.

Nothing is transmitted. The file is written to disk and later read back through the
production packet parser, so windowing, aggregation and feature extraction are exercised by
the same code that runs in production.
"""
from pathlib import Path
import struct
from ..safety import Budget
from .base import rng

BASE_EPOCH = 1767225600.0  # 2026-01-01T00:00:00Z, fixed so captures are byte-reproducible
LINKTYPE_RAW_IP = 101
SERVER_BANNER = {
    80: b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok',
    8080: b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok',
    9090: b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nup\n',
    22: b'SSH-2.0-lab-server\r\n',
    21: b'220 lab ftp ready\r\n',
}
DEFAULT_BANNER = b'+OK lab\r\n'

#: P15.4. What the server says when an authentication step succeeds or fails.
#:
#: These exist because a passive sensor on the protected host sees that host's
#: own replies, and for a cleartext protocol the outcome is right there in one:
#: `530 Login incorrect`, `HTTP/1.1 401`. Without them a synthetic corpus can
#: only ever exercise credential *presence* — precisely the quantity P15.3
#: proved says nothing. A corpus unable to express failure could not have caught
#: that defect and cannot demonstrate the fix either.
#:
#: Nothing here is a credential. They are server status lines, read by the same
#: `decision/auth.py` classifier that reads a real one.
AUTH_REPLY = {
    'success': {
        80: b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok',
        443: b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok',
        8080: b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok',
        8443: b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok',
        21: b'230 User logged in\r\n',
        22: b'SSH-2.0-lab-server\r\nauthentication succeeded\r\n',
    },
    'failure': {
        80: b'HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n',
        443: b'HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n',
        8080: b'HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n',
        8443: b'HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n',
        21: b'530 Login incorrect\r\n',
        22: b'SSH-2.0-lab-server\r\nauthentication failed\r\n',
    },
    'denied': {
        80: b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n',
        443: b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n',
        8080: b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n',
        8443: b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n',
        21: b'550 Permission denied\r\n',
        22: b'SSH-2.0-lab-server\r\npermission denied\r\n',
    },
}
#: The reply for a service with no entry above. Line-protocol shaped, and each
#: one is deliberately a string `decision.auth.classify_response` recognises: a
#: fallback that classified as UNKNOWN would silently turn every scenario on an
#: unlisted port into an unobservable outcome, and a corpus would then be
#: claiming to test a path it never reaches.
DEFAULT_AUTH_REPLY = {'success': b'+OK user logged in\r\n',
                      'failure': b'-ERR authentication failed\r\n',
                      'denied': b'-ERR access denied\r\n'}


def auth_banner(outcome, port, fallback):
    """The reply for an authentication outcome, or the ordinary banner."""
    if not outcome:
        return fallback
    table = AUTH_REPLY.get(outcome)
    if table is None:
        return fallback
    return table.get(port) or DEFAULT_AUTH_REPLY[outcome]


def write_pcap(path, rows, *, snaplen=65535):
    """Classic PCAP v2.4, raw IP link type. Same input, same bytes.

    A small `snaplen` records a truncated capture, which is how a real sensor loses payload
    visibility. Those windows produce missing payload features rather than observed zeros.
    """
    if not 24 <= snaplen <= 65535:
        raise ValueError('snaplen out of range')
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('wb') as stream:
        stream.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, LINKTYPE_RAW_IP))
        for stamp, data in rows:
            captured = data[:snaplen]
            seconds = int(stamp)
            # The microsecond field must be strictly below one million, and
            # rounding can push it there: a fractional part of 0.9999996 rounds
            # to exactly 1000000 and writes a record the production reader
            # refuses with "invalid or oversized PCAP record". Latent since this
            # function was written, and it took roughly a quarter of a million
            # records before one landed on the boundary — a corpus build that
            # fails outright is the friendly version of this bug, since the same
            # value in a capture from a real sensor would be a file nothing can
            # read. Carrying into the seconds is what a PCAP writer is supposed
            # to do, and it cannot change any record that was already valid.
            micros = int(round((stamp - seconds) * 1000000))
            if micros >= 1000000:
                seconds, micros = seconds + 1, micros - 1000000
            stream.write(struct.pack('<IIII', seconds, micros, len(captured), len(data)))
            stream.write(captured)
    return target


def _packet(source, destination, sport, dport, flags, seq, ack, payload=b''):
    from scapy.layers.inet import IP, TCP
    segment = TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=64240)
    return bytes(IP(src=source, dst=destination, ttl=64, id=(seq + sport) & 0xffff) / segment / payload)


def render(plan, *, base_epoch=BASE_EPOCH):
    """Plan -> [(timestamp, raw IP bytes)], with a fresh flow per contact."""
    stream = rng(plan.seed + ':packets')
    budget = Budget(plan.limits)
    rows = []

    def emit(stamp, data):
        budget.packet(len(data))
        rows.append((base_epoch + stamp, data))

    for index, contact in enumerate(plan.contacts):
        budget.connection(contact.destination)
        budget.advance(contact.time)
        sport = stream.randrange(49152, 65535)
        client_seq = stream.randrange(1, 0x7fffffff)
        server_seq = stream.randrange(1, 0x7fffffff)
        moment = contact.time
        step = lambda: stream.uniform(0.0004, 0.003)  # noqa: E731  short, local and deliberate
        banner = auth_banner(contact.auth, contact.port,
                             SERVER_BANNER.get(contact.port, DEFAULT_BANNER))
        emit(moment, _packet(plan.source, contact.destination, sport, contact.port, 'S', client_seq, 0))
        if contact.shape == 'syn_only':
            continue
        if contact.shape == 'syn_reset':
            moment += step()
            emit(moment, _packet(contact.destination, plan.source, contact.port, sport, 'RA', 0, client_seq + 1))
            continue
        if contact.shape == 'retry_then_request':
            moment += step() + 0.25
            emit(moment, _packet(plan.source, contact.destination, sport, contact.port, 'S', client_seq, 0))
        moment += step()
        emit(moment, _packet(contact.destination, plan.source, contact.port, sport, 'SA', server_seq, client_seq + 1))
        moment += step()
        emit(moment, _packet(plan.source, contact.destination, sport, contact.port, 'A', client_seq + 1, server_seq + 1))
        if contact.shape == 'handshake':
            continue
        client_next, server_next = client_seq + 1, server_seq + 1
        moment += step()
        emit(moment, _packet(plan.source, contact.destination, sport, contact.port, 'PA', client_next,
                             server_next, contact.request))
        client_next += max(1, len(contact.request))
        if contact.shape in ('exchange', 'session'):
            moment += step()
            emit(moment, _packet(contact.destination, plan.source, contact.port, sport, 'PA', server_next,
                                 client_next, banner))
            server_next += len(banner)
        for _ in range(contact.follow_ups if contact.shape == 'session' else 0):
            moment += step() + stream.uniform(0.01, 0.12)
            emit(moment, _packet(plan.source, contact.destination, sport, contact.port, 'PA', client_next,
                                 server_next, contact.request))
            client_next += max(1, len(contact.request))
            moment += step()
            emit(moment, _packet(contact.destination, plan.source, contact.port, sport, 'PA', server_next,
                                 client_next, banner))
            server_next += len(banner)
        _ = index
    rows.sort(key=lambda row: row[0])
    return rows, budget.snapshot()
