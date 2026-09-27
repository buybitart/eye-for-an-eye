"""P7 temporary sets in an explicitly named disposable namespace, using the P1 backend."""
import ipaddress
import json
import shutil
import time
import uuid
from .firewall import NamespaceBackend
from ..decision.policy import PolicyGuard


class TemporaryBlocks:
    def __init__(self, config, *, backend=None, clock=time.monotonic):
        self.config = config.validate()
        if not config.enforcement.enabled:
            raise PermissionError('temporary enforcement explicitly disabled')
        self.backend = backend or NamespaceBackend(config)
        self.guard = PolicyGuard(config)
        self.clock = clock
        self.table = 'e4e_decision_' + uuid.uuid4().hex[:16]
        self.owner = 'e4e:p7:' + uuid.uuid4().hex
        self.created = False
        self.entries = {}

    def _nft(self, args):
        nft = shutil.which('nft')
        if not nft:
            raise RuntimeError('nft unavailable')
        result = self.backend._run([nft, *args])
        if result.returncode:
            raise RuntimeError('cannot verify owned temporary table')
        return json.loads(result.stdout)

    def _verify(self):
        state = self._nft(['-j', 'list', 'table', 'inet', self.table])
        tables = [v['table'] for v in state['nftables'] if 'table' in v]
        if len(tables) != 1 or tables[0].get('comment') != self.owner or tables[0].get('name') != self.table:
            raise PermissionError('owned table verification failed')
        return state

    def block(self, source, seconds):
        # Revalidate mode and protected/local addresses at the final side-effect boundary.
        self.config.validate()
        if not self.config.enforcement.enabled or self.config.decision.mode != 'enforce':
            return False
        if type(seconds) is not int or not 1 <= seconds <= max(self.config.enforcement.block_seconds):
            raise ValueError('temporary block duration rejected')
        address = ipaddress.ip_address(source)
        if getattr(address, 'ipv4_mapped', None):
            address = address.ipv4_mapped
        result = self.backend._run(['ip', '-j', 'address', 'show'])
        if result.returncode:
            raise RuntimeError('cannot verify local interface addresses')
        local = [item['local'] for interface in json.loads(result.stdout) for item in interface.get('addr_info', [])]
        if self.guard.protected(str(address), local):
            return False
        now = self.clock()
        self.entries = {ip: expiry for ip, expiry in self.entries.items() if expiry > now}
        if str(address) in self.entries or len(self.entries) >= self.config.enforcement.max_entries:
            return False
        if not self.created:
            # add table fails on collision; never delete/replace an existing table to make room.
            size = self.config.enforcement.max_entries
            self.backend.transaction(f'''add table inet {self.table} {{ comment "{self.owner}"; }}
add set inet {self.table} blocked_ipv4 {{ type ipv4_addr; flags timeout; size {size}; }}
add set inet {self.table} blocked_ipv6 {{ type ipv6_addr; flags timeout; size {size}; }}
add chain inet {self.table} input {{ type filter hook input priority 10; policy accept; }}
add rule inet {self.table} input ip saddr @blocked_ipv4 drop
add rule inet {self.table} input ip6 saddr @blocked_ipv6 drop
''')
            self.created = True
        self._verify()
        set_name = 'blocked_ipv4' if address.version == 4 else 'blocked_ipv6'
        self.backend.transaction(f'add element inet {self.table} {set_name} {{ {address} timeout {seconds}s }}\n')
        # A successful transaction is confirmed against the kernel, not merely attempted.
        state = self._verify()
        found = False
        for record in state['nftables']:
            block_set = record.get('set', {})
            if block_set.get('name') == set_name:
                for item in block_set.get('elem', []):
                    elem = item.get('elem', {}) if isinstance(item, dict) else {}
                    if (str(elem.get('val')) == str(address) and 0 < elem.get('expires', 0) <= seconds and
                            0 < elem.get('timeout', seconds) <= seconds):
                        found = True
        if not found:
            raise RuntimeError('temporary entry verification failed')
        self.entries[str(address)] = now + seconds
        return True

    def close(self):
        if self.created:
            self._verify()
            self.backend.transaction(f'delete table inet {self.table}\n')
            self.created = False
            self.entries.clear()
