import os
import stat
from pathlib import Path


def load_secret(config):
    if config.deception.secret_file:
        path = Path(config.deception.secret_file)
        if os.name == 'posix' and stat.S_IMODE(path.stat().st_mode) & 0o007:
            raise PermissionError('deception.secret_file must not be accessible to other users; use 0600 or a restricted service group')
        with path.open('rb') as stream:
            secret = stream.read(4097)
    else:
        encoded = os.environ.get(config.deception.secret_env, '')
        if len(encoded) > 8192:
            raise ValueError('secret too large')
        try:
            secret = bytes.fromhex(encoded)
        except ValueError as exc:
            raise ValueError('secret environment variable must contain hex bytes') from exc
    if not 32 <= len(secret) <= 4096:
        raise ValueError('services require a persistent 32..4096 byte secret file or hex environment variable')
    return secret
