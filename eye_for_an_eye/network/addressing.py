"""Canonical network metadata, with no DNS resolution."""
import ipaddress


def canonical_address(value):
    return str(ipaddress.ip_address(value))


def outer_ip(packet):
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
    layer = packet
    for _ in range(16):
        if isinstance(layer, (IP, IPv6)):
            return layer
        layer = getattr(layer, 'payload', None)
        if layer is None:
            break
    return None
