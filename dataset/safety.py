"""Hard safety boundary for dataset generation.

Two rules that are checked, not assumed:

1. Nothing this package does may leave the machine. A scenario that opens a socket may
   only target loopback or an address explicitly listed as an isolated lab address, and the
   check is made with `ipaddress`, never by matching a config string.
2. Every scenario carries hard upper bounds. A scenario without limits does not run.

No exploitation, no destructive payload, no credential material and no retransmission of a
captured packet exists anywhere in this package by design.
"""
from contextlib import contextmanager
from dataclasses import dataclass, replace
import ipaddress

# Written into synthetic traces only. RFC 5737 / RFC 3849 documentation ranges are used so a
# generated capture can never be confused with, or replayed against, a real host.
DOCUMENTATION_V4 = (ipaddress.ip_network('192.0.2.0/24'), ipaddress.ip_network('198.51.100.0/24'),
                    ipaddress.ip_network('203.0.113.0/24'))
DOCUMENTATION_V6 = (ipaddress.ip_network('2001:db8::/32'),)
DEFAULT_LAB_ALLOWLIST = ('127.0.0.0/8', '::1/128')


class UnsafeTarget(ValueError):
    """Raised when a scenario target is not provably local."""


class BudgetExceeded(RuntimeError):
    """Raised when a scenario hits one of its hard bounds."""


def _address(value):
    try:
        return ipaddress.ip_address(value)
    except (ValueError, TypeError) as error:
        raise UnsafeTarget(f'not an IP address: {value!r}') from error


def validate_live_target(value, allowlist=DEFAULT_LAB_ALLOWLIST):
    """Target for a real socket. Loopback, or an address inside the explicit lab allowlist.

    Documentation ranges are deliberately rejected here: they are globally assigned, so a
    connection to one leaves this machine even though nothing answers.
    """
    address = _address(value)
    if address.is_loopback:
        return address
    networks = [ipaddress.ip_network(entry, strict=False) for entry in allowlist]
    if any(address.version == network.version and address in network for network in networks):
        if address.is_global or any(address in net for net in DOCUMENTATION_V4 + DOCUMENTATION_V6):
            raise UnsafeTarget(f'{value} is routable or a documentation address; lab allowlist refused')
        return address
    raise UnsafeTarget(f'{value} is not loopback and not in the isolated lab allowlist')


def validate_synthetic_address(value):
    """Address written into a synthetic trace. Never transmitted, still never globally routable."""
    address = _address(value)
    if address.is_global or address.is_multicast or address.is_reserved or address.is_unspecified:
        raise UnsafeTarget(f'{value} is not usable in a synthetic trace')
    return address


def is_documentation(value):
    address = _address(value)
    return any(address.version == network.version and address in network
               for network in DOCUMENTATION_V4 + DOCUMENTATION_V6)


@dataclass(frozen=True, slots=True)
class SafetyLimits:
    """Hard upper bounds. A generator refuses to run without them."""
    max_duration_seconds: float = 120.0
    max_connections: int = 2000
    max_packets: int = 20000
    max_bytes: int = 4_194_304
    max_concurrency: int = 8
    max_destinations: int = 64
    max_samples: int = 400
    max_request_bytes: int = 512

    def __post_init__(self):
        for name in ('max_duration_seconds', 'max_connections', 'max_packets', 'max_bytes',
                     'max_concurrency', 'max_destinations', 'max_samples', 'max_request_bytes'):
            value = getattr(self, name)
            if type(value) not in (int, float) or value <= 0:
                raise ValueError(f'{name} must be a positive bound')
        if self.max_duration_seconds > 600 or self.max_connections > 20000 or self.max_bytes > 67_108_864:
            raise ValueError('scenario bounds exceed the dataset generation ceiling')

    def tightened(self, **overrides):
        merged = {name: min(getattr(self, name), value) for name, value in overrides.items()}
        return replace(self, **merged)


class Budget:
    """Runtime counter. Every generator increments it; exceeding a bound stops the scenario."""

    def __init__(self, limits):
        if not isinstance(limits, SafetyLimits):
            raise ValueError('a scenario without explicit limits does not run')
        self.limits = limits
        self.connections = self.packets = self.bytes = self.samples = 0
        self.destinations = set()
        self.elapsed = 0.0
        self.stopped = None

    def connection(self, destination=None, count=1):
        self.connections += count
        if destination is not None:
            self.destinations.add(destination)
        self._check()

    def packet(self, size=0):
        self.packets += 1
        self.bytes += max(0, int(size))
        self._check()

    def sample(self):
        self.samples += 1
        self._check()

    def advance(self, seconds):
        self.elapsed = max(self.elapsed, float(seconds))
        self._check()

    def _check(self):
        limits = self.limits
        for name, value, bound in (('connections', self.connections, limits.max_connections),
                                   ('packets', self.packets, limits.max_packets),
                                   ('bytes', self.bytes, limits.max_bytes),
                                   ('samples', self.samples, limits.max_samples),
                                   ('destinations', len(self.destinations), limits.max_destinations),
                                   ('duration', self.elapsed, limits.max_duration_seconds)):
            if value > bound:
                self.stopped = name
                raise BudgetExceeded(f'scenario exceeded max_{name}: {value} > {bound}')

    def snapshot(self):
        return {'connections': self.connections, 'packets': self.packets, 'bytes': self.bytes,
                'samples': self.samples, 'destinations': len(self.destinations),
                'elapsed_seconds': round(self.elapsed, 3), 'stopped_by': self.stopped}


class DiskBudget:
    """Stops a build cleanly at a configured size instead of filling the disk."""

    def __init__(self, max_output_bytes=134_217_728):
        if type(max_output_bytes) is not int or not 4096 <= max_output_bytes <= 4_294_967_296:
            raise ValueError('invalid dataset.max_output_bytes')
        self.max_output_bytes = max_output_bytes
        self.written = 0
        self.truncated = False

    def would_exceed(self, size):
        return self.written + size > self.max_output_bytes

    def add(self, size):
        if self.would_exceed(size):
            self.truncated = True
            return False
        self.written += size
        return True


@contextmanager
def interruption_safe(on_stop=None):
    """Ctrl+C stops collection and lets the caller flush a valid partial dataset."""
    try:
        yield
    except KeyboardInterrupt:
        if on_stop is not None:
            on_stop()


def describe(scenario_id, target, limits, label):
    """Printed before any lab scenario runs, so the operator sees the boundary."""
    return {'scenario': scenario_id, 'target': str(target), 'target_policy': 'isolated lab (loopback only)',
            'expected_label': label, 'max_duration_seconds': limits.max_duration_seconds,
            'max_connections': limits.max_connections, 'max_packets': limits.max_packets,
            'max_bytes': limits.max_bytes, 'max_destinations': limits.max_destinations,
            'transmits_to_internet': False, 'exploitation': False, 'destructive_payloads': False}
