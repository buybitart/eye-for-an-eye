"""Lab-scoped path observations. Neither NAT detection nor identity attribution."""
import ipaddress
from ..enrichment.cache import TTLCache
from ..limits import TokenBucket
from .result import FingerprintResult


def path_characteristics(observed_ttl, active=None, *, reason='disabled', ipv6=False):
    return FingerprintResult('path_characteristics', 'passive_only' if active is None else 'measured',
        {'observed_inbound_hop_limit' if ipv6 else 'observed_inbound_ttl': observed_ttl, 'active_measurement': active},
        {'nat_hypothesis': 'UNKNOWN'}, 'UNKNOWN', [reason],
        ['asymmetric_routing', 'icmp_filtering', 'tunneling', 'different_initial_ttl',
         'load_balancer', 'proxy', 'cgnat', 'no_nat_or_vpn_proof'])


def allowed_address(ip, cidrs):
    address = ipaddress.ip_address(ip)
    if address.version != 4 or address.is_multicast or address.is_unspecified or address.is_reserved:
        return False
    for cidr in cidrs:
        network = ipaddress.ip_network(cidr, strict=True)
        if network.version != 4 or network.prefixlen < 24:
            raise ValueError('lab policy requires IPv4 /24 or narrower')
        if address in network and (network.prefixlen >= 31 or address not in (network.network_address, network.broadcast_address)):
            return True
    return False


def scapy_sender(ip, timeout):
    # Called only by explicit policy-approved lab jobs, outside capture hot path.
    from scapy.all import IP, ICMP, sr1
    reply = sr1(IP(dst=ip) / ICMP(), timeout=timeout, verbose=0)
    if reply is None:
        return None
    if IP not in reply or ICMP not in reply or reply[ICMP].type != 0:
        return {}
    return {'src_ip': reply[IP].src, 'ttl': int(reply[IP].ttl)}


class PathProbe:
    def __init__(self, enabled=False, allowed_cidrs=(), sender=None, timeout=1,
                 negative_ttl_seconds=60, max_entries=10000):
        self.enabled = enabled
        self.allowed_cidrs = tuple(allowed_cidrs)
        self.sender = sender or scapy_sender
        self.timeout = timeout
        self.cache = TTLCache(max_entries, negative_ttl_seconds, max_bytes=4_194_304)
        self.rate = TokenBucket(1, burst=1)

    def measure(self, ip, observed_ttl):
        if not self.enabled:
            return path_characteristics(observed_ttl)
        if not allowed_address(ip, self.allowed_cidrs):
            return path_characteristics(observed_ttl, reason='not_allowed')
        cached = self.cache.get(ip)
        if cached is not None:
            return path_characteristics(observed_ttl, cached.observations['active_measurement'], reason=cached.reason)
        if not self.rate.allow():
            return path_characteristics(observed_ttl, reason='rate_limited')
        try:
            reply = self.sender(ip, self.timeout)
            if reply is None:
                result = path_characteristics(observed_ttl, reason='timeout')
            elif reply.get('src_ip') != ip or type(reply.get('ttl')) is not int or not 1 <= reply['ttl'] <= 255:
                result = path_characteristics(observed_ttl, reason='invalid_response')
            else:
                result = path_characteristics(observed_ttl, {'reply_ttl': reply['ttl']}, reason='two_incoming_ttl_observations')
        except (TimeoutError, OSError, ValueError, ImportError):
            result = path_characteristics(observed_ttl, reason='probe_unavailable')
        self.cache.set(ip, result)
        return result


def path_provider(ip, options):
    """Spawn-worker entry; revalidates policy before any raw packet operation."""
    from dataclasses import asdict
    probe = PathProbe(enabled=True, allowed_cidrs=options.get('allowed_cidrs', ()),
                      timeout=options.get('timeout', 1))
    result = asdict(probe.measure(ip, options.get('observed_ttl', 0)))
    # The worker cache is per address: never reuse a flow-specific derived delta.
    result.pop('estimated_hop_difference', None)
    return result
