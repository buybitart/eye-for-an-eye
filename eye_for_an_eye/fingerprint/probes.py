"""Bounded Nmap Probe reader. Scores describe byte similarity, not identity."""
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProbeKey:
    protocol: str
    name: str


@dataclass(frozen=True)
class ProbeLimits:
    max_entries: int = 4096
    max_probe_bytes: int = 65536
    max_input_bytes: int = 8_388_608
    max_payload_bytes: int = 1_048_576


@dataclass(frozen=True)
class ProbeMatch:
    probe_name: str | None
    transport: str
    score: float = 0.0
    evidence_bytes: int = 0
    confidence: str = "UNKNOWN"


class ProbeParseError(ValueError):
    pass


def _bytes(text):
    out = bytearray()
    escapes = dict(zip('0abfnrtv\\', (0, 7, 8, 12, 10, 13, 9, 11, 92)))
    i = 0
    while i < len(text):
        character = text[i]
        i += 1
        if character != '\\':
            if ord(character) > 255:
                raise ValueError('non-byte character')
            out.append(ord(character))
            continue
        if i == len(text):
            raise ValueError('incomplete escape')
        escape = text[i]
        i += 1
        if escape == 'x':
            pair = text[i:i + 2]
            if len(pair) != 2 or any(c not in '0123456789abcdefABCDEF' for c in pair):
                raise ValueError('invalid hex escape')
            out.append(int(pair, 16))
            i += 2
        elif escape in escapes:
            out.append(escapes[escape])
        else:
            raise ValueError('unsupported escape')
    return bytes(out)


def parse_probes(lines, *, limits=ProbeLimits()):
    if any(type(x) is not int or x < 1 for x in vars(limits).values()):
        raise ValueError('invalid probe limits')
    result = {}
    input_bytes = payload_bytes = 0
    for number, line in enumerate(lines, 1):
        input_bytes += len(line)
        if input_bytes > limits.max_input_bytes:
            raise ProbeParseError(f'line {number}: input limit exceeded')
        line = line.strip()
        if not line or not (line == 'Probe' or line.startswith('Probe ')):
            continue
        try:
            _, protocol, name, expression = line.split(None, 3)
            if protocol not in ('TCP', 'UDP') or len(name) > 128:
                raise ValueError('invalid transport or name')
            if len(expression) < 3 or expression[0] != 'q':
                raise ValueError('expected q delimiter')
            delimiter = expression[1]
            if not 33 <= ord(delimiter) <= 126:
                raise ValueError('invalid delimiter')
            end = expression.index(delimiter, 2)
            if expression[end + 1:].strip() not in ('', 'no-payload'):
                raise ValueError('invalid suffix')
            data = _bytes(expression[2:end])
            key = ProbeKey(protocol.lower(), name)
            if key in result:
                raise ValueError('duplicate probe identity')
            if len(data) > limits.max_probe_bytes:
                raise ValueError('payload limit exceeded')
            if len(result) >= limits.max_entries:
                raise ValueError('entries limit exceeded')
            payload_bytes += len(data)
            if payload_bytes > limits.max_payload_bytes:
                raise ValueError('aggregate payload limit exceeded')
            result[key] = data
        except ValueError as exc:
            raise ProbeParseError(f'line {number}: {exc}') from exc
    return result


def load_probes(path, *, limits=ProbeLimits()):
    path = Path(path)
    with path.open('rb') as stream:
        raw = stream.read(limits.max_input_bytes + 1)
    if len(raw) > limits.max_input_bytes:
        raise ProbeParseError('input limit exceeded')
    # Latin-1 is the reversible byte mapping, never UTF-8 re-encoding.
    # str.splitlines also treats raw 0x85 as a line break, corrupting binary probes.
    return parse_probes(raw.decode('latin-1').split('\n'), limits=limits)


def match_probe(payload, transport, probes, min_evidence=8):
    transport = transport.lower()
    if transport not in ('tcp', 'udp') or not isinstance(payload, bytes):
        raise ValueError('invalid payload/transport')
    if len(payload) > 65536 or not 1 <= min_evidence <= 65536 or len(probes) > 4096:
        raise ValueError('matching budget exceeded')
    best = ProbeMatch(None, transport)
    if len(payload) < min_evidence:
        return best
    # Only exact/prefix candidates: linear bounded work instead of quadratic diff.
    for key, data in probes.items():
        if len(data) > 65536:
            raise ValueError('probe exceeds matching budget')
        if key.protocol != transport or len(data) < min_evidence:
            continue
        evidence = min(len(data), len(payload))
        if not (payload.startswith(data) or data.startswith(payload)):
            continue
        score = evidence / max(len(data), len(payload))
        if score > best.score:
            best = ProbeMatch(key.name, transport, score, evidence, 'LOW')
    return best
