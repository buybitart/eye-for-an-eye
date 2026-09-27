"""IPv6 base/extension fields, separate from IPv4 ID/fragment semantics."""
from .result import FingerprintResult


def ipv6_observation(data):
    obs = {'malformed': False, 'capture_truncated': False, 'extension_headers': [], 'fragment_header': None}
    if not isinstance(data, bytes) or len(data) < 40 or data[0] >> 4 != 6:
        obs['malformed'] = True
        return FingerprintResult('ipv6', 'partial', obs, evidence=['truncated_or_invalid_ipv6'])
    obs.update(hop_limit=data[7], flow_label=int.from_bytes(data[:4], 'big') & 0xfffff,
               declared_payload_length=int.from_bytes(data[4:6], 'big'))
    end = min(len(data), 40 + obs['declared_payload_length'])
    obs['capture_truncated'] = len(data) < 40 + obs['declared_payload_length']
    obs['malformed'] = obs['capture_truncated']
    kind, offset = data[6], 40
    for _ in range(8):
        if kind not in (0, 43, 44, 51, 60):
            break
        obs['extension_headers'].append(kind)
        if offset + 2 > end:
            obs['malformed'] = True
            break
        length = 8 if kind == 44 else ((data[offset + 1] + 2) * 4 if kind == 51 else (data[offset + 1] + 1) * 8)
        if offset + length > end:
            obs['malformed'] = True
            break
        if kind == 44:
            fragment = int.from_bytes(data[offset + 2:offset + 4], 'big')
            obs['fragment_header'] = {'offset': fragment >> 3, 'more': bool(fragment & 1),
                                      'identification': int.from_bytes(data[offset + 4:offset + 8], 'big')}
        kind, offset = data[offset], offset + length
    else:
        obs['malformed'] = True
    obs.update(upper_protocol=kind, upper_offset=offset)
    limitations = ['no_ipv4_id_semantics', 'no_fragment_reassembly']
    if kind == 50 or not obs['declared_payload_length']:
        limitations.append('esp_or_jumbogram_unsupported')
    return FingerprintResult('ipv6', 'partial' if obs['malformed'] else 'observed', obs,
                             evidence=['ipv6_header_bytes'], limitations=limitations)
