"""Linux privilege preflight. No capabilities are granted or system state changed."""
import os
from pathlib import Path
import sys

CAP_NET_RAW = 1 << 13


def effective_capabilities():
    for line in Path('/proc/self/status').read_text(encoding='ascii').splitlines():
        if line.startswith('CapEff:'):
            return int(line.split()[1], 16)
    raise RuntimeError('cannot determine effective Linux capabilities')


def ensure_analysis_user(enforce=True):
    if enforce and sys.platform.startswith('linux'):
        if os.geteuid() == 0 or effective_capabilities():
            raise PermissionError('analysis must run as non-root with no effective capabilities')


def ensure_capture_user():
    if not sys.platform.startswith('linux'):
        raise RuntimeError('capture helper is Linux-only: NOT VERIFIED IN CURRENT ENVIRONMENT')
    capabilities = effective_capabilities()
    if os.geteuid() == 0 or capabilities != CAP_NET_RAW:
        raise PermissionError('capture helper requires non-root with only effective CAP_NET_RAW')


def unit_settings(role):
    if role not in ('analysis', 'capture'):
        raise ValueError('unknown privilege role')
    return {'NoNewPrivileges': 'true', 'PrivateTmp': 'true', 'ProtectSystem': 'strict', 'ProtectHome': 'true',
        'ProtectKernelTunables': 'true', 'ProtectKernelModules': 'true', 'ProtectControlGroups': 'true',
        'RestrictSUIDSGID': 'true', 'LockPersonality': 'true', 'MemoryDenyWriteExecute': 'true',
        'CapabilityBoundingSet': 'CAP_NET_RAW' if role == 'capture' else '',
        'AmbientCapabilities': 'CAP_NET_RAW' if role == 'capture' else '',
        'RestrictAddressFamilies': 'AF_UNIX AF_PACKET AF_INET AF_INET6 AF_NETLINK' if role == 'capture' else 'AF_UNIX AF_INET AF_INET6 AF_NETLINK',
        'LimitNOFILE': '1024', 'TasksMax': '32', 'MemoryMax': '128M' if role == 'capture' else '256M'}
