"""Temporary defensive blocks on the real host, in one table this project owns.

This is the module P15 refused to write, and the reason it refused is worth
repeating before the reason it now exists. P15 would have had to call test
coverage "deployment evidence" — the substitution P13 explicitly rejected. What
changed in P15.1 is not the argument, it is the evidence: this code has been
exercised against a real kernel, on a disposable machine, and the safety
properties below were tested rather than asserted.

### What it may touch

One table: `inet e4e_autonomous`, carrying an owner comment. Two timeout sets,
one per address family. One chain, `input`, at filter priority 10 with policy
accept, holding two rules that drop traffic from an address in the matching set.

Nothing else. There is no flush anywhere in this file, no `delete ruleset`, no
read of another table, and no code path that names a table it did not create.
Docker's tables, firewalld's tables, the operator's own rules: this module
cannot see them and cannot remove them. `verify()` refuses to proceed if the
table it finds does not carry our owner comment, which is what stops it adopting
somebody else's table of the same name.

### Why the table name is stable and the lab one is not

`security/firewall.py` names its table with a per-process UUID so a restart can
never inherit a lease. That is right for a lab, where the process is the only
thing keeping state, and wrong here: a sensor that crashes with live blocks must
be able to find them again, and a table nobody can name is a table nobody can
clean up. So the name is fixed, ownership is proved by a comment containing an
installation identifier, and safety comes from somewhere better than obscurity —
**every element carries a kernel timeout**. If this process dies and never
returns, the kernel expires the blocks on schedule with nobody's help. That is
§25: a crash cannot produce a permanent block, because a permanent block cannot
be expressed.

### Apply, then verify

`apply()` is not finished when `nft` exits zero. It re-reads the set from the
kernel and confirms the element is present with a timeout inside the requested
bound. A failed verification is a failed block, recorded as such and reported to
the caller, because the alternative is a system that believes it is defending
something it is not.
"""
from dataclasses import dataclass
import json
import os
import re
import shutil
import subprocess
import sys
import time

from .enforcement import EnforcementError, EnforcementRequest, MAX_TTL_SECONDS

HOST_FIREWALL_SCHEMA_VERSION = 1

#: Table-name prefix. The full name carries the installation identifier, so the
#: name is stable across restarts (a crash can be reconciled) and distinct per
#: installation (two sensors on one host own separate tables instead of one of
#: them silently refusing to enforce because the other got there first).
TABLE_PREFIX = 'e4e_'
#: The default installation's table, kept as a module constant because tests and
#: operators need something to name.
TABLE = 'e4e_default'
FAMILY = 'inet'
#: Prefix of the owner comment. The suffix is an installation identifier, so two
#: installations on one host cannot adopt each other's table.
OWNER_PREFIX = 'e4e:p15.1:'
SET_IPV4 = 'blocked_ipv4'
SET_IPV6 = 'blocked_ipv6'
CHAIN = 'input'

#: Hard ceiling on concurrently held blocks. A set that can grow without bound is
#: a memory problem an attacker chooses the size of.
DEFAULT_MAX_ENTRIES = 4096
#: Every nft invocation is bounded. A firewall helper that can hang is a sensor
#: that stops defending while it waits.
COMMAND_TIMEOUT_SECONDS = 5
MAX_OUTPUT_BYTES = 262_144


class HostFirewallError(RuntimeError):
    """The host firewall could not do what was asked, and did nothing instead."""


class HostFirewallUnavailable(HostFirewallError):
    """The platform cannot support host enforcement at all."""


@dataclass(frozen=True, slots=True)
class ApplyResult:
    """What actually happened, including the case where nothing did."""

    applied: bool
    verified: bool
    address: str
    ttl_seconds: int
    decision_id: str
    detail: str = ''
    expires_in: int | None = None

    @property
    def succeeded(self):
        """A block is a block only when the kernel confirms it. §24."""
        return self.applied and self.verified

    def explain(self):
        return {'applied': self.applied, 'verified': self.verified,
                'succeeded': self.succeeded, 'address': self.address,
                'ttl_seconds': self.ttl_seconds, 'decision_id': self.decision_id,
                'expires_in_seconds': self.expires_in, 'detail': self.detail}


#: Installation identifiers become part of an nftables object name, so they are
#: constrained rather than escaped. A name built from a validated alphabet cannot
#: carry a quote, a semicolon or a newline into a script.
_SLUG = re.compile(r'[^a-z0-9_]+')


def slug(installation):
    """A safe nftables identifier for one installation."""
    cleaned = _SLUG.sub('_', str(installation).lower()).strip('_')[:40]
    return cleaned or 'default'


def table_name(installation):
    return TABLE_PREFIX + slug(installation)


def owner_comment(installation):
    return OWNER_PREFIX + slug(installation)


class HostBackend:
    """`nft` on this host, scoped to one table, with no shell anywhere.

    Every argument list is built from constants and validated values. Nothing
    reaching `subprocess` comes from a request unparsed: an address is rendered
    from an `ipaddress` object and a TTL from an `int`, so there is no string a
    caller controls that ends up as a command token.
    """

    def __init__(self, installation, *, max_entries=DEFAULT_MAX_ENTRIES,
                 nft_path=None, clock=time.monotonic):
        self.installation = str(installation)
        self.table = table_name(installation)
        self.owner = owner_comment(installation)
        self.max_entries = max(1, int(max_entries))
        self.clock = clock
        self._nft = nft_path
        self.created = False

    # -- process boundary ---------------------------------------------------

    def executable(self):
        path = self._nft or shutil.which('nft')
        if not path:
            raise HostFirewallUnavailable('nft is not installed')
        return path

    def available(self):
        """Whether this host can support enforcement at all. Never raises.

        Three separate reasons it might not: the wrong platform, no `nft`, or no
        privilege. They are reported apart because they need different answers
        from an operator.
        """
        if not sys.platform.startswith('linux'):
            return False, 'host enforcement requires Linux'
        path = self._nft or shutil.which('nft')
        if not path or not os.path.isfile(path):
            return False, 'nft is not installed'
        if os.geteuid() != 0:
            return False, 'host enforcement requires privilege the sensor does not have'
        return True, ''

    def _run(self, args, *, data=None):
        result = subprocess.run([self.executable(), *args], input=data, text=True,
                                capture_output=True, timeout=COMMAND_TIMEOUT_SECONDS,
                                check=False)
        if len(result.stdout) > MAX_OUTPUT_BYTES or len(result.stderr) > 8192:
            raise HostFirewallError('nft output exceeded its budget')
        return result

    # -- reading ------------------------------------------------------------

    def _table_json(self):
        """Our table as the kernel has it, or None. Never reads another table."""
        result = self._run(['-j', 'list', 'table', FAMILY, self.table])
        if result.returncode:
            return None
        try:
            return json.loads(result.stdout)
        except ValueError as exc:
            raise HostFirewallError('nft returned output that is not JSON') from exc

    def owns_table(self):
        """Whether a table named ours exists *and* carries our owner comment.

        The second half is the whole point. A table with the right name and
        somebody else's comment is somebody else's table, and the correct
        response is to refuse rather than to take it over.
        """
        body = self._table_json()
        if body is None:
            return False, 'no table'
        for item in body.get('nftables', []):
            table = item.get('table')
            if table and table.get('name') == self.table and table.get('family') == FAMILY:
                comment = table.get('comment', '')
                if comment == self.owner:
                    return True, ''
                return False, f'a table named {self.table} exists and is not ours'
        return False, 'no table'

    def entries(self):
        """Live blocks, from the kernel rather than from memory.

        In-process bookkeeping and the kernel disagree after a crash, a manual
        change or an expiry, and the kernel is the one enforcing anything.
        """
        owned, reason = self.owns_table()
        if not owned:
            if reason == 'no table':
                return []
            raise HostFirewallError(reason)
        body = self._table_json() or {}
        found = []
        for item in body.get('nftables', []):
            block_set = item.get('set') or {}
            if block_set.get('name') not in (SET_IPV4, SET_IPV6):
                continue
            for element in block_set.get('elem', []) or []:
                value = element.get('elem', element) if isinstance(element, dict) else {}
                address = value.get('val') if isinstance(value, dict) else element
                if not isinstance(address, str):
                    continue
                found.append({'address': address,
                              'family': 'ipv4' if block_set['name'] == SET_IPV4 else 'ipv6',
                              'timeout': value.get('timeout'),
                              'expires': value.get('expires')})
        return found

    # -- writing ------------------------------------------------------------

    def _ensure_table(self):
        """Create our table if it is absent. Never replaces one that exists.

        `add table` is idempotent in nftables, which would silently adopt a table
        of the same name that somebody else made — so ownership is checked first
        and a foreign table is a refusal, not a takeover.
        """
        owned, reason = self.owns_table()
        if owned:
            self.created = True
            return
        if reason != 'no table':
            raise HostFirewallError(reason)
        script = (
            f'add table {FAMILY} {self.table} {{ comment "{self.owner}"; }}\n'
            f'add set {FAMILY} {self.table} {SET_IPV4} {{ type ipv4_addr; flags timeout; '
            f'size {self.max_entries}; }}\n'
            f'add set {FAMILY} {self.table} {SET_IPV6} {{ type ipv6_addr; flags timeout; '
            f'size {self.max_entries}; }}\n'
            f'add chain {FAMILY} {self.table} {CHAIN} {{ type filter hook input priority 10; '
            f'policy accept; }}\n'
            f'add rule {FAMILY} {self.table} {CHAIN} ip saddr @{SET_IPV4} drop\n'
            f'add rule {FAMILY} {self.table} {CHAIN} ip6 saddr @{SET_IPV6} drop\n')
        check = self._run(['-c', '-f', '-'], data=script)
        if check.returncode:
            raise HostFirewallError('the owned table script did not validate: '
                                    + check.stderr.strip()[:200])
        result = self._run(['-f', '-'], data=script)
        if result.returncode:
            raise HostFirewallError('could not create the owned table: '
                                    + result.stderr.strip()[:200])
        owned, reason = self.owns_table()
        if not owned:
            raise HostFirewallError('the owned table did not appear after creation')
        self.created = True

    def _element_script(self, request, *, delete=False):
        address = request.parsed
        name = SET_IPV4 if address.version == 4 else SET_IPV6
        verb = 'delete' if delete else 'add'
        suffix = '' if delete else f' timeout {request.ttl_seconds}s'
        return f'{verb} element {FAMILY} {self.table} {name} {{ {address}{suffix} }}\n'

    def dry_run(self, request):
        """§27. What would be written, checked by nft, applied by nobody.

        Uses `nft -c`, which parses and validates against the live ruleset
        without committing. A dry run that only printed a string would tell an
        operator what this module intended, not what the kernel would accept.
        """
        owned, reason = self.owns_table()
        script = self._element_script(request)
        if not owned and reason == 'no table':
            return {'would_create_table': True, 'script': script, 'validated': None,
                    'detail': 'the owned table does not exist yet; it would be created first'}
        if not owned:
            return {'would_create_table': False, 'script': script, 'validated': False,
                    'detail': reason}
        check = self._run(['-c', '-f', '-'], data=script)
        return {'would_create_table': False, 'script': script,
                'validated': check.returncode == 0,
                'detail': check.stderr.strip()[:200]}

    def apply(self, request):
        """Write one block and confirm the kernel has it. §24."""
        if not isinstance(request, EnforcementRequest):
            raise EnforcementError('apply requires a validated EnforcementRequest')
        self._ensure_table()
        live = self.entries()
        if len(live) >= self.max_entries:
            return ApplyResult(applied=False, verified=False, address=str(request.parsed),
                               ttl_seconds=request.ttl_seconds,
                               decision_id=request.decision_id,
                               detail='the owned set is at its entry ceiling')
        script = self._element_script(request)
        result = self._run(['-f', '-'], data=script)
        if result.returncode:
            return ApplyResult(applied=False, verified=False, address=str(request.parsed),
                               ttl_seconds=request.ttl_seconds,
                               decision_id=request.decision_id,
                               detail='nft refused the element: '
                                      + result.stderr.strip()[:160])
        verified, expires, detail = self._verify_element(request)
        return ApplyResult(applied=True, verified=verified, address=str(request.parsed),
                           ttl_seconds=request.ttl_seconds,
                           decision_id=request.decision_id, expires_in=expires,
                           detail=detail)

    def _verify_element(self, request):
        """Read back what was written. An unverified element is not a block."""
        address = str(request.parsed)
        for entry in self.entries():
            if entry['address'] != address:
                continue
            timeout = entry.get('timeout')
            expires = entry.get('expires')
            if not isinstance(timeout, int) or not 0 < timeout <= request.ttl_seconds:
                return False, expires, 'the kernel holds a timeout outside the requested bound'
            if not isinstance(expires, int) or not 0 < expires <= timeout:
                return False, expires, 'the kernel holds an element with no live expiry'
            return True, expires, ''
        return False, None, 'the element is not in the owned set after a successful write'

    def release(self, request):
        """Remove one block early. Expiry needs no help; this is for an operator."""
        owned, reason = self.owns_table()
        if not owned:
            return False
        result = self._run(['-f', '-'], data=self._element_script(request, delete=True))
        return result.returncode == 0

    def cleanup(self):
        """§27. Delete our table and nothing else.

        Refuses when the table is not ours. `delete table` names one table, so
        there is no path from here to another one, and no flush anywhere.
        """
        owned, reason = self.owns_table()
        if not owned:
            return {'deleted': False, 'detail': reason}
        result = self._run(['delete', 'table', FAMILY, self.table])
        self.created = False
        return {'deleted': result.returncode == 0,
                'detail': result.stderr.strip()[:200] if result.returncode else ''}

    def reconcile(self):
        """§25. After a restart, adopt our own table and nothing else.

        Every element found is reported with the expiry the kernel is already
        counting down, so a sensor that comes back after a crash knows what it is
        still enforcing without having to remember it.
        """
        owned, reason = self.owns_table()
        if not owned:
            return {'adopted': False, 'entries': [], 'detail': reason}
        live = self.entries()
        unbounded = [entry for entry in live
                     if not isinstance(entry.get('timeout'), int)
                     or not 0 < entry['timeout'] <= MAX_TTL_SECONDS]
        return {'adopted': True, 'entries': live, 'unbounded': unbounded,
                'detail': ('every adopted element carries a kernel timeout'
                           if not unbounded else
                           'adopted elements without a bounded timeout were found')}

    def status(self):
        """§27. What exists, what is live, and whether this host can enforce."""
        usable, reason = self.available()
        body = {'host_firewall_schema_version': HOST_FIREWALL_SCHEMA_VERSION,
                'table': f'{FAMILY} {self.table}', 'owner': self.owner,
                'available': usable, 'unavailable_reason': reason,
                'max_entries': self.max_entries}
        if not usable:
            return body
        owned, detail = self.owns_table()
        body['owned_table_present'] = owned
        body['detail'] = detail
        body['entries'] = self.entries() if owned else []
        body['active_blocks'] = len(body['entries'])
        return body
