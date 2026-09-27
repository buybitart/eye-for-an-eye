from .result import FingerprintResult


def ttl_fingerprint(ttl, candidates=(32, 64, 128, 255), max_hops=32, *, ipv6=False):
    feature, field = ('hop_limit', 'observed_hop_limit') if ipv6 else ('ttl', 'observed_ttl')
    if type(ttl) is not int or not 1 <= ttl <= 255:
        return FingerprintResult(feature, 'unknown', evidence=['invalid_ttl'])
    if (not candidates or len(candidates) > 16 or any(type(value) is not int or not 1 <= value <= 255 for value in candidates)
            or type(max_hops) is not int or not 0 <= max_hops <= 254):
        raise ValueError('invalid initial TTL candidate policy')
    plausible = sorted({value for value in candidates if 0 <= value - ttl <= max_hops})
    return FingerprintResult(feature, 'observed', {field: ttl},
        {'initial_ttl_candidates': plausible, 'estimated_hops': [value - ttl for value in plausible],
         'ambiguity': len(plausible) != 1, 'os_hint': None},
        'LOW' if plausible else 'UNKNOWN', ['observed_header_lifetime'],
        ['initial_values_are_configured_assumptions', 'hop_bound_is_a_prior', 'no_os_attribution'])


def ttl_observation(ttl):
    """P0 compatibility view; P2 runtime uses the separated ttl_fingerprint."""
    result = ttl_fingerprint(ttl)
    if result.confidence == 'UNKNOWN':
        return {'status': result.status, 'confidence': result.confidence, 'reason': result.reason}
    hypothesis = result.hypothesis
    return {'status': result.status, 'observed_ttl': ttl, 'candidate_initial_ttl': hypothesis['initial_ttl_candidates'][0],
            'candidate_initial_ttls': hypothesis['initial_ttl_candidates'], 'estimated_hops': hypothesis['estimated_hops'][0],
            'os_hint': None, 'confidence': result.confidence}
