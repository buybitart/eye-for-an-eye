"""Finite in-memory HTTP/FTP/SSH parsers. No IO, file paths, execution or callbacks."""
from dataclasses import dataclass
import re
from .privacy import Privacy


@dataclass(frozen=True, slots=True)
class Step:
    command: str
    request_length: int
    response: bytes = b''
    close: bool = False
    anomaly: bool = False
    credential: bool = False
    username: str | None = None
    safe_preview: str | None = None
    probe_digest: str = ''
    probe_name: str = ''


class ProtocolSession:
    def __init__(self, profile, limits, privacy: Privacy, *, max_messages=12, max_transitions=40, features=None):
        self.profile, self.privacy = profile, privacy
        self.features = features
        self.max_request = min(profile.max_request_bytes, limits.max_request_bytes)
        self.max_response = min(profile.max_response_bytes, limits.max_response_bytes)
        self.idle_timeout = min(profile.idle_timeout, limits.idle_timeout)
        self.total_timeout = min(profile.total_timeout, limits.total_timeout)
        self.max_messages = min(profile.max_messages, max_messages)
        self.max_transitions = min(profile.max_transitions, max_transitions)
        self.buffer = bytearray()
        self.request_bytes = self.response_bytes = self.messages = self.transitions = 0
        self.state = 'CONNECTED'
        self.user = None
        self.closed = False

    def _step(self, command, data=b'', response=b'', *, close=False, anomaly=False, credential=False, username=None):
        if self.transitions + 2 > self.max_transitions or self.response_bytes + len(response) > self.max_response:
            response, close = b'', True
        self.transitions = min(self.max_transitions, self.transitions + 2)
        self.response_bytes += len(response)
        projection = self.privacy.projection(data, command)
        credential = credential or projection['credential_like_attempt']
        features = self.features.observe(data, 'tcp') if self.features and data and not credential else {}
        self.closed = close or self.messages >= self.max_messages or self.transitions >= self.max_transitions
        if self.closed:
            self.buffer.clear()
            self.state = 'CLOSED'
            self.user = None
        return Step(command, len(data), response, self.closed, anomaly,
                    credential, username, projection.get('safe_preview'), features.get('probe_digest', ''), features.get('probe_name', ''))

    def start(self):
        if self.state != 'CONNECTED':
            return []
        self.state = 'COMMAND'
        if self.profile.service_family == 'http':
            return []
        return [self._step('GREETING', response=self.profile.banner)]

    def feed(self, data):
        if self.closed or self.state == 'CONNECTED':
            return []
        if not isinstance(data, bytes) or self.request_bytes + len(data) > self.max_request:
            return [self._step('REQUEST_LIMIT', close=True)]
        self.request_bytes += len(data)
        self.buffer.extend(data)
        steps = []
        # At most max_messages iterations over at most max_request bytes.
        while self.buffer and not self.closed and self.messages < self.max_messages:
            if self.profile.service_family == 'http':
                end = self.buffer.find(b'\r\n\r\n')
                if end < 0:
                    break
                length = end + 4
            else:
                end = self.buffer.find(b'\n')
                if end < 0:
                    break
                length = end + 1
            frame = bytes(self.buffer[:length])
            del self.buffer[:length]
            self.messages += 1
            if self.profile.service_family == 'http':
                steps.append(self._http(frame))
            elif self.profile.service_family == 'ftp':
                steps.append(self._ftp(frame))
            else:
                steps.append(self._ssh(frame))
        if not self.closed and self.request_bytes >= self.max_request:
            steps.append(self._step('REQUEST_LIMIT', close=True))
        return steps

    def _http(self, frame):
        lines = frame[:-4].split(b'\r\n')
        first = lines[0].split(b' ')
        valid = (len(first) == 3 and first[2] in (b'HTTP/1.0', b'HTTP/1.1') and
                 all(32 <= value <= 126 for value in lines[0]) and
                 (first[1].startswith(b'/') or first[:2] == [b'OPTIONS', b'*']))
        headers = {}
        for line in lines[1:]:
            key, sep, value = line.partition(b':')
            if (not sep or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key) or
                    any(byte < 32 or byte > 126 for byte in value) or key.lower() in headers):
                valid = False
            headers[key.lower()] = value.strip()
        if len(first) == 3 and first[2] == b'HTTP/1.1' and not headers.get(b'host'):
            valid = False
        # No body, transfer coding or upgrade. Reject framing ambiguities; close once.
        if (b'transfer-encoding' in headers or headers.get(b'content-length', b'0') != b'0' or
                b'upgrade' in headers or b'expect' in headers):
            valid = False
        method = first[0] if first else b''
        command = method.decode('ascii') if method in (b'GET', b'HEAD', b'OPTIONS') else 'UNSUPPORTED'
        if not valid:
            response = b'HTTP/1.0 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
        elif command == 'UNSUPPORTED':
            response = b'HTTP/1.0 405 Method Not Allowed\r\nAllow: GET, HEAD, OPTIONS\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
        elif method == b'OPTIONS':
            response = b'HTTP/1.0 204 No Content\r\nServer: Apache\r\nAllow: GET, HEAD, OPTIONS\r\nConnection: close\r\n\r\n'
        else:
            response = self.profile.banner
            if method == b'HEAD':
                response = response.split(b'\r\n\r\n', 1)[0] + b'\r\n\r\n'
        return self._step(command, frame, response, close=True, anomaly=not valid)

    def _ftp(self, frame):
        if not frame.endswith(b'\r\n') or len(frame) > 512 or any(b < 32 or b > 126 for b in frame[:-2]):
            return self._step('INVALID', frame, b'500 Invalid command\r\n', close=True, anomaly=True)
        verb, _, argument = frame[:-2].partition(b' ')
        verb = verb.upper()
        command = verb.decode('ascii') if verb in (b'USER', b'PASS', b'SYST', b'FEAT', b'PWD', b'QUIT') else 'UNSUPPORTED'
        if verb == b'USER' and argument:
            self.user = self.privacy.username(argument)
            self.state = 'USER_SEEN'
            return self._step(command, frame, b'331 Password required\r\n', credential=True, username=self.user)
        if verb == b'PASS':
            user = self.user
            response = b'530 Login incorrect\r\n' if self.state == 'USER_SEEN' else b'503 Send USER first\r\n'
            self.state, self.user = 'COMMAND', None
            return self._step(command, frame, response, credential=True, username=user)
        responses = {b'SYST': b'215 UNIX Type: L8\r\n', b'FEAT': b'211 End\r\n',
                     b'PWD': b'530 Not logged in\r\n', b'QUIT': b'221 Goodbye\r\n'}
        if verb in responses and not argument:
            return self._step(command, frame, responses[verb], close=verb == b'QUIT')
        return self._step(command, frame, b'502 Command not implemented\r\n')

    def _ssh(self, frame):
        valid = (len(frame) <= 255 and frame.endswith(b'\r\n') and
                 re.fullmatch(rb'SSH-2\.0-[\x21-\x2c\x2e-\x7e]+(?: [ -~]*)?\r\n', frame) is not None)
        return self._step('SSH_IDENTIFICATION' if valid else 'INVALID', frame, close=True, anomaly=not valid)

    def close(self):
        self.closed, self.state, self.user = True, 'CLOSED', None
        self.buffer.clear()
