"""Response admission and monotone degradation; no classification increases budgets."""
from dataclasses import dataclass
import ipaddress
import time
from ..limits import TokenBucket

COMMON = frozenset({21, 80, 2222, 8080})
EXTENDED = COMMON | {2121, 2200, 8000, 8888}
PORT_FAMILIES = {21: 'ftp', 2121: 'ftp', 2222: 'ssh', 2200: 'ssh',
                 80: 'http', 8000: 'http', 8080: 'http', 8888: 'http'}


def decoy_ports(config):
    dec = config.deception
    if dec.port_set == 'common':
        return set(COMMON)
    if dec.port_set == 'extended':
        return set(EXTENDED)
    return set(dec.decoy_ports or [config.network.port])


@dataclass(frozen=True, slots=True)
class Decision:
    action: str
    profile_id: str | None
    reason: str
    load_mode: str


class LoadController:
    def __init__(self, config, clock=time.monotonic):
        self.config, self.clock = config, clock
        self.mode = 'NORMAL'
        self.low_since = None

    def update(self, pressure, failed=False):
        now = self.clock()
        wanted = ('OBSERVE_ONLY' if failed or pressure >= self.config.overload_observe_only else
                  'DEGRADED' if pressure >= self.config.overload_degraded else 'NORMAL')
        ranks = {'NORMAL': 0, 'DEGRADED': 1, 'OBSERVE_ONLY': 2}
        if ranks[wanted] > ranks[self.mode]:
            self.mode, self.low_since = wanted, None
        elif pressure < self.config.overload_recover and not failed:
            if self.low_since is None:
                self.low_since = now
            if now - self.low_since >= self.config.recovery_seconds:
                self.mode = 'NORMAL'
        else:
            self.low_since = None
        return self.mode


class ResponsePolicy:
    def __init__(self, config):
        self.config = config
        self.ports = decoy_ports(config)
        self.networks = tuple(ipaddress.ip_network(value) for value in config.deception.source_allowlist)
        self.load = LoadController(config.deception)
        self.rate = TokenBucket(config.limits.connections_per_second)

    def decide(self, source, destination, *, pressure=0.0, failed=False, profile_id=None, charge=True):
        mode = self.load.update(pressure, failed)
        reason = 'decoy_port_profile'
        address = ipaddress.ip_address(source)
        if not self.config.deception.enabled:
            reason = 'disabled'
        elif not destination:
            reason = 'unknown_original_destination'
        elif (destination[1] not in self.ports or
              destination[1] in self.config.firewall.real_service_ports + self.config.firewall.management_ports):
            reason = 'protected_or_unconfigured_port'
        elif address.is_unspecified or address.is_multicast or not any(address in network for network in self.networks):
            reason = 'source_not_eligible'
        elif mode == 'OBSERVE_ONLY':
            reason = 'overload'
        elif charge and not self.rate.allow():
            reason = 'response_rate_limit'
        return Decision('respond' if reason == 'decoy_port_profile' else 'observe_only', profile_id, reason, mode)
