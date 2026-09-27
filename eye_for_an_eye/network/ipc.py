"""Length-prefixed JSON packet snapshots with deadlines and Linux peer credentials."""
import json
import math
import socket
import struct
import sys
import time


def validate_peer(sock, expected_uid):
    if not sys.platform.startswith('linux') or not hasattr(socket, 'SO_PEERCRED'):
        raise PermissionError('IPC peer validation requires Linux SO_PEERCRED')
    pid, uid, gid = struct.unpack('3i', sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if uid != expected_uid or pid <= 0:
        raise PermissionError('IPC peer UID rejected')
    return pid, uid, gid


def encode_frame(record, max_bytes=8192):
    payload = json.dumps(record, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode('ascii')
    if not 1 <= len(payload) <= max_bytes:
        raise ValueError('IPC frame exceeds budget')
    return struct.pack('!I', len(payload)) + payload


def receive_frame(sock, *, max_bytes=8192, timeout=.5):
    deadline = time.monotonic() + timeout
    def exact(size):
        data = bytearray()
        while len(data) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('IPC frame deadline')
            sock.settimeout(remaining)
            part = sock.recv(size - len(data))
            if not part:
                raise EOFError('IPC peer disconnected')
            data.extend(part)
        return bytes(data)
    size = struct.unpack('!I', exact(4))[0]
    if not 1 <= size <= max_bytes:
        raise ValueError('IPC frame size rejected')
    try:
        record = json.loads(exact(size))
        if not isinstance(record, dict) or set(record) != {'schema_version', 'packet_hex', 'captured_at'}:
            raise ValueError('invalid IPC fields')
        if type(record['schema_version']) is not int or record['schema_version'] != 1:
            raise ValueError('unsupported IPC schema')
        stamp, encoded = record['captured_at'], record['packet_hex']
        if type(stamp) not in (int, float) or not math.isfinite(stamp):
            raise ValueError('invalid capture time')
        if not isinstance(encoded, str) or not 2 <= len(encoded) <= 4096:
            raise ValueError('invalid packet snapshot')
        packet = bytes.fromhex(encoded)
        if packet[0] >> 4 not in (4, 6):
            raise ValueError('unsupported IP version')
        return packet, stamp
    except (TypeError, KeyError, RecursionError) as exc:
        raise ValueError('invalid IPC record') from exc
