"""Operator-only nftables manager, always executed in a named isolated lab namespace."""
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

TABLE = 'eye_for_an_eye'
OWNER = 'e4e:p1:'
READINESS = '''import socket,sys
with socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=.5):
    pass
'''


def fingerprint(config):
    return hashlib.sha256(json.dumps(asdict(config.firewall), sort_keys=True).encode()).hexdigest()[:24]


def render(config, *, replace=False):
    config.validate()
    f = config.firewall
    if not f.enabled:
        raise ValueError('firewall.enabled and explicit lab policy are required')
    addresses = ', '.join(sorted(set(f.destination_addresses)))
    ports = ', '.join(f'{port} timeout {f.lease_seconds}s' for port in sorted(set(f.decoy_ports)))
    protected = ', '.join(map(str, sorted(set(f.real_service_ports + f.management_ports + [f.listener_port]))))
    prefix = f'delete table ip {TABLE}\n' if replace else ''
    return prefix + f'''table ip {TABLE} {{
    comment "{OWNER}{fingerprint(config)}"
    set leased_ports {{
        type inet_service
        flags timeout
        timeout {f.lease_seconds}s
        elements = {{ {ports} }}
    }}
    chain prerouting {{
        type nat hook prerouting priority dstnat; policy accept;
        tcp dport {{ {protected} }} return
        ip daddr {{ {addresses} }} tcp dport @leased_ports redirect to :{f.listener_port}
    }}
}}
'''


class NamespaceBackend:
    def __init__(self, config):
        self.config = config.validate()

    def _guard(self):
        if not sys.platform.startswith('linux'):
            raise RuntimeError('firewall apply/verify/rollback are Linux lab-only: NOT VERIFIED IN CURRENT ENVIRONMENT')
        namespace = self.config.firewall.lab_namespace
        if not (self.config.firewall.enabled or self.config.enforcement.enabled) or not namespace:
            raise PermissionError('explicit enabled namespace policy required')
        path = Path('/run/netns') / namespace
        target = path.stat()
        initial = Path('/proc/1/ns/net').stat()
        if (target.st_dev, target.st_ino) == (initial.st_dev, initial.st_ino):
            raise PermissionError('refusing the initial/host network namespace')
        return namespace

    def _run(self, args, data=None):
        namespace = self._guard()
        executable = shutil.which('ip')
        if not executable:
            raise RuntimeError('iproute2 is required in the isolated Linux lab')
        # No shell, no event fields, no unscoped nft subprocess, no host ruleset reads.
        result = subprocess.run([executable, 'netns', 'exec', namespace, *args], input=data,
                                text=True, capture_output=True, timeout=3, check=False)
        if len(result.stdout) > 131072 or len(result.stderr) > 8192:
            raise RuntimeError('namespace command output exceeded budget')
        return result

    def read(self):
        nft = shutil.which('nft')
        if not nft:
            raise RuntimeError('nft is required in the isolated Linux lab')
        result = self._run([nft, '-j', 'list', 'tables', 'ip'])
        if result.returncode:
            raise RuntimeError('cannot read namespace tables')
        tables = json.loads(result.stdout).get('nftables', [])
        if not any(item.get('table', {}).get('name') == TABLE for item in tables):
            return None
        result = self._run([nft, '-j', 'list', 'table', 'ip', TABLE])
        if result.returncode:
            raise RuntimeError('cannot read owned namespace table')
        return json.loads(result.stdout)

    def ready(self):
        return self._run([sys.executable, '-B', '-c', READINESS, self.config.firewall.listener_address,
                          str(self.config.firewall.listener_port)]).returncode == 0

    def transaction(self, script):
        nft = shutil.which('nft')
        if not nft:
            raise RuntimeError('nft is required')
        for args in ([nft, '-c', '-f', '-'], [nft, '-f', '-']):
            result = self._run(args, script)
            if result.returncode:
                raise RuntimeError('namespace nft validation/apply failed')


def _owned(state):
    tables = [item['table'] for item in state.get('nftables', []) if 'table' in item]
    if len(tables) != 1 or tables[0].get('name') != TABLE or tables[0].get('family') != 'ip':
        return False
    return str(tables[0].get('comment', '')).startswith(OWNER)


def _values(value):
    if isinstance(value, dict) and 'set' in value:
        value = value['set']
    if not isinstance(value, list):
        value = [value]
    return {str(item.get('elem', {}).get('val')) if isinstance(item, dict) else str(item) for item in value}


def verify_structure(state, config):
    if not _owned(state):
        return False
    items = state['nftables']
    table = next(item['table'] for item in items if 'table' in item)
    chains = [item['chain'] for item in items if 'chain' in item]
    sets = [item['set'] for item in items if 'set' in item]
    rules = [item['rule'] for item in items if 'rule' in item]
    f = config.firewall
    if table.get('comment') != OWNER + fingerprint(config) or len(chains) != 1 or len(sets) != 1 or len(rules) != 2:
        return False
    chain, ports = chains[0], sets[0]
    if (chain.get('name'), chain.get('type'), chain.get('hook'), chain.get('prio'), chain.get('policy')) != ('prerouting', 'nat', 'prerouting', -100, 'accept'):
        return False
    if ports.get('name') != 'leased_ports' or ports.get('type') != 'inet_service' or 'timeout' not in ports.get('flags', []):
        return False
    if _values(ports.get('elem', [])) != set(map(str, f.decoy_ports)):
        return False
    # libnftables JSON uses seconds; netlink's millisecond units do not apply here.
    if ports.get('timeout') != f.lease_seconds:
        return False
    for item in ports.get('elem', []):
        value = item.get('elem', {}) if isinstance(item, dict) else {}
        if not 0 < value.get('expires', 0) <= f.lease_seconds:
            return False
        if value.get('timeout', f.lease_seconds) > f.lease_seconds:
            return False
    protected = set(map(str, f.real_service_ports + f.management_ports + [f.listener_port]))
    expected = [([('tcp', 'dport', protected)], {'return': None}),
                ([('ip', 'daddr', set(f.destination_addresses)), ('tcp', 'dport', {'@leased_ports'})],
                 {'redirect': {'port': f.listener_port}})]
    for rule, (matches, verdict) in zip(rules, expected):
        if rule.get('chain') != 'prerouting':
            return False
        expressions = rule.get('expr', [])
        if not expressions or expressions[-1] != verdict:
            return False
        actual = []
        for expression in expressions[:-1]:
            match = expression.get('match', {})
            if match.get('op') not in ('==', 'in'):
                return False
            left = match.get('left', {})
            if left == {'meta': {'key': 'l4proto'}} and match.get('right') in ('tcp', 6):
                continue
            payload = left.get('payload', {})
            actual.append((payload.get('protocol'), payload.get('field'), _values(match.get('right'))))
        if actual != matches:
            return False
    return True


class FirewallManager:
    def __init__(self, config, *, backend=None):
        self.config = config.validate()
        self.backend = backend or NamespaceBackend(config)

    def dry_run(self):
        return {'namespace': self.config.firewall.lab_namespace, 'family': 'ip', 'ipv6': 'unsupported',
                'lease_seconds': self.config.firewall.lease_seconds, 'script': render(self.config)}

    def apply(self):
        render(self.config)
        previous = self.backend.read()
        if previous is not None and not _owned(previous):
            raise PermissionError('table collision: refusing to replace foreign rules')
        if not self.backend.ready():
            raise RuntimeError('listener readiness failed; no redirect was applied')
        self.backend.transaction(render(self.config, replace=previous is not None))
        result = self.verify()
        if result['status'] != 'healthy':
            self.rollback()
            raise RuntimeError('firewall verification failed; owned table rolled back to no redirect')
        return result

    def verify(self):
        state = self.backend.read()
        if state is None:
            return {'status': 'unavailable', 'reason': 'not_applied'}
        if not verify_structure(state, self.config):
            return {'status': 'degraded', 'reason': 'policy_mismatch_or_expired_lease'}
        ready = self.backend.ready()
        return {'status': 'healthy' if ready else 'degraded',
                'reason': 'verified_lease' if ready else 'listener_unavailable', 'ipv6': 'unsupported'}

    def rollback(self):
        state = self.backend.read()
        if state is None:
            return {'status': 'healthy', 'reason': 'already_absent'}
        if not _owned(state):
            raise PermissionError('refusing to remove foreign table')
        self.backend.transaction(f'delete table ip {TABLE}\n')
        if self.backend.read() is not None:
            raise RuntimeError('rollback verification failed')
        return {'status': 'healthy', 'reason': 'owned_redirect_removed'}
