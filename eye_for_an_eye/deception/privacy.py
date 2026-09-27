"""Conservative telemetry projection; arbitrary client strings never become log fields."""
import hashlib
import hmac
import re

SECRET_PATTERN = re.compile(rb'authorization|cookie|password|passwd|token|api[-_]?key|secret|(?:^|\r\n)(?:USER|PASS|AUTH|LOGIN)\s', re.I)
COMMANDS = frozenset({'GET', 'HEAD', 'OPTIONS', 'USER', 'PASS', 'SYST', 'FEAT', 'PWD', 'QUIT', 'SSH_IDENTIFICATION'})


class Privacy:
    def __init__(self, secret, *, usernames='redact', preview=False):
        if usernames not in ('redact', 'hash') or not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError('invalid privacy policy')
        self.key = hmac.digest(secret, b'EFAE-USERNAME-V1', hashlib.sha256)
        self.usernames, self.preview = usernames, preview

    def username(self, value):
        if self.usernames == 'redact':
            return '[redacted]'
        return hmac.digest(self.key, value[:512], hashlib.sha256).hex()

    def projection(self, data, command):
        # Regex is a signal, never permission to retain an unrecognized secret.
        result = {'credential_like_attempt': bool(SECRET_PATTERN.search(data[:4096]))}
        if self.preview:
            safe = command if command in COMMANDS else 'UNKNOWN'
            result['safe_preview'] = safe + ' [arguments, headers and body omitted]'
        return result
