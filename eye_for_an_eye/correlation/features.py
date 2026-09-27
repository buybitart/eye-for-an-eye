"""Only bounded metadata survives intake; keyed digests cannot expose credentials.

P15.4 adds the authentication half. `credential_like_attempt` is unchanged — it
is a true statement about the payload and several components still read it — but
it is no longer the only thing said about authentication, because on its own it
cannot tell a backup script from a brute-forcer. `decision/auth.py` records what
believing otherwise cost.

What is added is the *shape* of an authentication step and, for a server reply,
the *outcome* the server reported. Neither reads a secret: the argument of a
`PASS`-style command is never touched, and an `Authorization` header is
recognised by its scheme without its value being parsed, hashed or stored. The
principal pseudonym uses this object's own process-local key, the same one that
already keys probe digests and is never persisted.
"""
import hashlib
import hmac
import secrets
from ..decision import auth as auth_module
from ..fingerprint.probes import match_probe


class PayloadFeatures:
    def __init__(self, probes=None, min_evidence=8, *, key=None):
        self.probes = probes or {}
        self.min_evidence = min_evidence
        self.key = key if key is not None else secrets.token_bytes(32)
        if len(self.key) < 32:
            raise ValueError('digest key must be >=32 bytes')

    def observe(self, data, transport):
        if not isinstance(data, bytes) or len(data) > 65536:
            raise ValueError('invalid bounded payload')
        lower = data[:4096].lower()
        credential = (any(word in lower for word in (b'authorization:', b'cookie:', b'password', b'passwd', b'token=', b'secret='))
                      or lower.startswith((b'user ', b'pass ', b'auth ', b'login ')))
        family = 'http' if lower.startswith((b'get ', b'head ', b'post ', b'options ')) else (
            'ssh' if lower.startswith(b'ssh-') else ('ftp' if lower.startswith((b'user ', b'pass ', b'feat', b'quit')) else 'unknown'))
        result = {'payload_length': len(data), 'credential_like_attempt': credential, 'protocol_family': family,
                  'protocol_anomaly': family == 'http' and (b'\r\n' not in data or b'HTTP/' not in data[:256]),
                  'inspection_limited': len(data) > 4096}
        # The authentication view. Both halves are computed for every payload
        # because this object does not know the direction; `FlowEvidence` does,
        # and it is what decides which half applies.
        attempted = auth_module.attempted(data)
        result['auth_attempted'] = attempted
        if attempted:
            result['auth_mechanism'] = auth_module.mechanism_of(data)
            principal = auth_module.principal_pseudonym(self.key, auth_module.identifier_of(data))
            if principal:
                result['auth_principal'] = principal
        outcome = auth_module.classify_response(data)
        if outcome != auth_module.UNKNOWN:
            result['auth_response_result'] = outcome
        # No digest of recognized credentials. All remaining digests are HMACs
        # scoped to this sensor process, and the random key is never persisted.
        if data and not credential:
            result['probe_digest'] = hmac.new(self.key, data, hashlib.sha256).hexdigest()
            match = match_probe(data, transport, self.probes, self.min_evidence)
            if match.probe_name:
                result.update(probe_name=match.probe_name, probe_evidence_bytes=match.evidence_bytes,
                              probe_description='Nmap-compatible probe; tool identity unknown')
        return result
