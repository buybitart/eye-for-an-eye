import hashlib
import hmac
import ipaddress
import struct
from .profiles import CATALOGUE_VERSION, PROFILES


def profile_seed(secret, dst_ip, dst_port, transport, catalogue_version=CATALOGUE_VERSION):
    if not isinstance(secret, bytes) or not 32 <= len(secret) <= 4096:
        raise ValueError('persistent secret must contain 32..4096 bytes')
    address = ipaddress.ip_address(dst_ip)
    transport = transport.lower()
    if type(dst_port) is not int or not 1 <= dst_port <= 65535 or transport not in ('tcp', 'udp'):
        raise ValueError('invalid destination/transport')
    if type(catalogue_version) is not int or catalogue_version != CATALOGUE_VERSION:
        raise ValueError('unsupported catalogue version; migration must be explicit')
    message = b'EFAE-DECEPTION-V1\0' + struct.pack('!I', catalogue_version)
    message += bytes([address.version]) + address.packed
    message += struct.pack('!HB', dst_port, 6 if transport == 'tcp' else 17)
    return hmac.digest(secret, message, hashlib.sha256)


def select_profile(secret, dst_ip, dst_port, transport, catalogue_version=CATALOGUE_VERSION, family=None):
    seed = profile_seed(secret, dst_ip, dst_port, transport, catalogue_version)
    if transport.lower() != 'tcp':
        raise ValueError('no UDP response profiles')
    candidates = tuple(profile for profile in PROFILES if family is None or profile.service_family == family)
    if not candidates:
        raise ValueError('unsupported service family')
    return candidates[int.from_bytes(seed, 'big') % len(candidates)]
