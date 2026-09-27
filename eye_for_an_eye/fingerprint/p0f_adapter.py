from pathlib import Path
import hashlib
from .result import FingerprintResult


class P0fAdapter:
    def __init__(self, database=None, *, backend=None):
        self.backend = backend
        self.reason = 'database_missing'
        self.version = None
        self.signature_version = 'p0f-v3'
        if backend is None and database and Path(database).is_file():
            try:
                from scapy.modules import p0f
                with Path(database).open('rb') as stream:
                    content = stream.read(8_388_609)
                if len(content) > 8_388_608:
                    raise ValueError('p0f database exceeds 8 MiB')
                self.version = hashlib.sha256(content).hexdigest()
                knowledge = p0f.p0fKnowledgeBase(str(database))
                base = knowledge.get_base()
                if not base or not base.get('tcp'):
                    self.reason = 'database_empty'
                    return
                def tcp_match(packet):
                    signature, direction = p0f.packet2p0f(packet)
                    if not isinstance(signature, p0f.TCP_Signature) or not base['tcp'].get(direction):
                        return None
                    return knowledge.tcp_find_match(signature, direction)
                self.backend = tcp_match
            except Exception:
                self.reason = 'backend_unavailable'

    def fingerprint(self, packet):
        obs = {'database_version': self.version, 'signature_version': self.signature_version, 'fuzzy': None}
        limits = ['signature_compatibility_not_os_certainty', 'middleboxes_and_stack_configuration', 'uncalibrated_match']
        if self.backend is None:
            return FingerprintResult('p0f', 'error' if self.reason == 'backend_unavailable' else 'unavailable',
                                     obs, evidence=[self.reason], limitations=limits)
        try:
            match = self.backend(packet)
            if match is None:
                return FingerprintResult('p0f', 'unmatched', obs, evidence=['no_match'], limitations=limits)
            if not isinstance(match, tuple) or len(match) != 3:
                return FingerprintResult('p0f', 'error', obs, evidence=['unsupported_result'], limitations=limits)
            label, distance, fuzzy = match
            if (not isinstance(label, (tuple, list)) or len(label) != 4 or
                    not all(isinstance(value, str) for value in label) or
                    type(distance) is not int or not 0 <= distance <= 255 or type(fuzzy) is not bool):
                return FingerprintResult('p0f', 'error', obs, evidence=['unsupported_result'], limitations=limits)
            obs.update(fuzzy=fuzzy, signature_label=':'.join(label)[:256])
            return FingerprintResult('p0f', 'matched', obs,
                {'class': label[1][:128], 'name': label[2][:128], 'flavor': label[3][:128], 'distance': distance},
                'LOW' if fuzzy else 'MEDIUM', ['signature_match'], limits)
        except Exception:
            return FingerprintResult('p0f', 'error', obs, evidence=['backend_error'], limitations=limits)
