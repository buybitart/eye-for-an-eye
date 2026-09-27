from dataclasses import dataclass


CATALOGUE_VERSION = 2


@dataclass(frozen=True, slots=True)
class ServiceProfile:
    profile_id: str
    profile_version: int
    transport: str
    service_family: str
    product_hint: str | None
    version_hint: str | None
    handler: str
    max_request_bytes: int
    max_response_bytes: int
    idle_timeout: float
    total_timeout: float
    capabilities: frozenset[str]
    banner: bytes
    max_messages: int = 12
    max_transitions: int = 40

    def __post_init__(self):
        if (type(self.profile_version) is not int or self.profile_version < 1 or
                self.transport != 'tcp' or self.handler != self.service_family or
                self.service_family not in ('http', 'ssh', 'ftp') or
                not isinstance(self.capabilities, frozenset)):
            raise ValueError('invalid profile identity/capabilities')
        if not isinstance(self.banner, bytes) or len(self.banner) > self.max_response_bytes:
            raise ValueError('invalid banner or response budget')
        if (not 1 <= self.max_request_bytes <= 4096 or not 1 <= self.max_response_bytes <= 1024 or
                not 0 < self.idle_timeout <= self.total_timeout <= 10 or
                not 1 <= self.max_messages <= 16 or not 3 <= self.max_transitions <= 64):
            raise ValueError('invalid profile budget')

    # Read compatibility; new callers use the explicit model above.
    @property
    def id(self):
        return self.profile_id

    @property
    def protocol(self):
        return self.transport

    @property
    def service(self):
        return self.service_family

    @property
    def max_request(self):
        return self.max_request_bytes

    @property
    def max_response(self):
        return self.max_response_bytes


# Versioned catalog: changing ordering/contents requires a mapping-version bump.
PROFILES = (
    ServiceProfile('ssh-banner-v2', 2, 'tcp', 'ssh', 'OpenSSH', '9.6', 'ssh',
        1024, 1024, 2.0, 5.0, frozenset({'identification'}),
        b'SSH-2.0-OpenSSH_9.6\r\n', max_messages=1, max_transitions=6),
    ServiceProfile('ftp-control-v2', 2, 'tcp', 'ftp', None, None, 'ftp',
        4096, 1024, 3.0, 10.0, frozenset({'USER', 'PASS', 'SYST', 'FEAT', 'PWD', 'QUIT'}),
        b'220 FTP service ready\r\n'),
    ServiceProfile('http-static-v2', 2, 'tcp', 'http', 'Apache', None, 'http',
        4096, 1024, 3.0, 5.0, frozenset({'GET', 'HEAD', 'OPTIONS'}),
        b'HTTP/1.0 200 OK\r\nServer: Apache\r\nContent-Length: 3\r\nConnection: close\r\n\r\nOK\n',
        max_messages=1, max_transitions=6),
)


def response_for(profile, request):
    if not isinstance(request, bytes) or len(request) > profile.max_request:
        return b''
    if profile.service != 'http':
        return profile.banner
    if not request.endswith(b'\r\n\r\n'):
        return b''
    lines = request[:-4].split(b'\r\n')
    first = lines[0].split(b' ')
    if len(first) != 3 or first[0] not in (b'GET', b'HEAD') or first[2] not in (b'HTTP/1.0', b'HTTP/1.1'):
        return b''
    if not first[1].startswith(b'/') or any(b < 32 or b > 126 for b in lines[0]):
        return b''
    if any(b':' not in line or any(b < 32 or b > 126 for b in line) for line in lines[1:]):
        return b''
    response = profile.banner
    if first[0] == b'HEAD':
        response = response.split(b'\r\n\r\n', 1)[0] + b'\r\n\r\n'
    return response[:profile.max_response]
