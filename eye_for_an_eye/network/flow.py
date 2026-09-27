"""Directed flow scope; missing ports are explicit, never invented as port zero."""
from dataclasses import dataclass
import ipaddress


@dataclass(frozen=True, slots=True)
class FlowKey:
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    transport: str = 'tcp'

    def __post_init__(self):
        for name in ('src_ip', 'dst_ip'):
            object.__setattr__(self, name, str(ipaddress.ip_address(getattr(self, name))))
        if self.transport not in ('tcp', 'udp', 'icmp', 'icmpv6', 'other', 'unknown'):
            raise ValueError('invalid flow transport')
        for port in (self.src_port, self.dst_port):
            if port is not None and (type(port) is not int or not 0 <= port <= 65535):
                raise ValueError('invalid flow port')
        if self.transport not in ('tcp', 'udp') and (self.src_port is not None or self.dst_port is not None):
            raise ValueError('portless protocols require None ports')

    @property
    def protocol(self):
        return self.transport

    def tuple(self):
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.transport)
