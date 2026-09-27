"""One bounded, binary-safe redaction boundary for persistence, logs and API."""
from itertools import islice
from functools import lru_cache
import math
import re

REDACT_KEYS = ('payload', 'password', 'passwd', 'credential', 'authorization', 'cookie', 'secret',
               'token', 'raw', 'text', 'api_key', 'api-key', 'session')
SECRET_VALUE = re.compile(r'(?i)(?:authorization|(?:set-)?cookie|password|passwd|api[_-]?key|secret|token|session)\s*(?:[:=]|\s)\s*\S')
JWT = re.compile(r'\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b')


def safe_metadata(key, value):
    return ((key in ('payload_length', 'credential_attempts') and type(value) is int and 0 <= value <= 2**31 - 1)
            or (key == 'credential_like_attempt' and type(value) is bool))


def safe_string(value, maximum=256):
    prefix = value[:maximum]
    if SECRET_VALUE.search(prefix) or JWT.search(prefix):
        return '[redacted]'
    return prefix[:maximum - 14] + ' [truncated]' if len(value) > maximum else prefix


@lru_cache(maxsize=1024)
def _short_sensitive_key(lowered):
    """Only bounded key names are cached; values/credentials never enter this cache."""
    return any(word in lowered for word in REDACT_KEYS)


def sensitive_key(key):
    lowered = str(key).lower()
    if len(lowered) <= 64:
        return _short_sensitive_key(lowered)
    return any(word in lowered for word in REDACT_KEYS)


def bounded_value(value, depth=0):
    if depth >= 5:
        return '[depth limit]'
    if isinstance(value, dict):
        return {safe_string(str(key), 64): bounded_value(item, depth + 1) for key, item in islice(value.items(), 24)
                if safe_metadata(key, item) or not sensitive_key(key)}
    if isinstance(value, (list, tuple)):
        return [bounded_value(item, depth + 1) for item in value[:24]]
    if isinstance(value, str):
        return safe_string(value)
    if isinstance(value, bytes):
        return '[bytes omitted]'
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is float:
        return value if math.isfinite(value) else None
    return type(value).__name__
