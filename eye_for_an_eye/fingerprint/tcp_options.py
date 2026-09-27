"""Bounded parser of the TCP header only; no reassembly or payload retention."""
import struct
from .result import FingerprintResult


def tcp_options(data):
    observed = {'malformed': False, 'option_order': [], 'mss': None, 'window_scale': None,
                'sack_permitted': None, 'timestamps': None, 'quirks': []}
    errors = []
    if not isinstance(data, bytes) or len(data) < 20:
        observed['malformed'] = True
        return FingerprintResult('tcp_options', 'partial', observed, evidence=['truncated_tcp_header'],
                                 limitations=['no_missing_field_inference'])
    observed.update(window_size=int.from_bytes(data[14:16], 'big'), flags=((data[12] & 1) << 8) | data[13],
                    sequence=int.from_bytes(data[4:8], 'big'), acknowledgment=int.from_bytes(data[8:12], 'big'))
    size = (data[12] >> 4) * 4
    if size < 20 or size > len(data):
        errors.append('invalid_or_truncated_data_offset')
    if data[12] & 14:
        observed['quirks'].append('reserved_bits_set')
    if data[13] & 2 and data[13] & 5:
        observed['quirks'].append('syn_with_fin_or_rst')
    if not observed['flags']:
        observed['quirks'].append('no_flags')
    end, index, seen = min(max(size, 20), len(data), 60), 20, set()
    while index < end:
        kind = data[index]
        observed['option_order'].append(kind)
        if kind == 0:
            if any(data[index + 1:end]):
                observed['quirks'].append('nonzero_padding_after_eol')
            break
        if kind == 1:
            index += 1
            continue
        if index + 1 >= end:
            errors.append('truncated_option_length')
            break
        length = data[index + 1]
        if length < 2 or index + length > end:
            errors.append('invalid_option_length')
            break
        value = data[index + 2:index + length]
        if kind in seen:
            observed['quirks'].append('duplicate_option')
            if kind in (2, 3, 4, 8):
                errors.append('duplicate_singleton_option')
        seen.add(kind)
        if kind == 2 and length == 4:
            observed['mss'] = int.from_bytes(value, 'big')
        elif kind == 3 and length == 3:
            observed['window_scale'] = value[0]
            if value[0] > 14:
                errors.append('invalid_window_scale')
        elif kind == 4 and length == 2:
            observed['sack_permitted'] = True
        elif kind == 8 and length == 10:
            observed['timestamps'] = dict(zip(('tsval', 'tsecr'), struct.unpack('!II', value)))
        elif kind in (2, 3, 4, 8):
            errors.append('invalid_known_option_length')
        elif kind == 5:
            observed['sack_blocks'] = (length - 2) // 8
            if length < 10 or (length - 2) % 8:
                errors.append('invalid_sack_length')
        index += length
    observed['malformed'] = bool(errors)
    observed['option_order_codes'] = ','.join(map(str, observed['option_order']))
    observed['quirks'] = observed['quirks'][:8]
    return FingerprintResult('tcp_options', 'partial' if errors else 'observed', observed,
                             evidence=errors or ['tcp_header_bytes'], limitations=['header_only', 'no_os_attribution',
                                 'option_order_codes_preserves_full_order_if_json_list_is_capped'])
