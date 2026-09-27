"""The unprivileged side: turn a decision into a request, and hand it over.

`AutonomousDecisionAuthority` decides. This turns a decision into an
`EnforcementRequest` and gives it to the privileged helper. It holds no
privilege of its own, imports nothing that can reach `nft`, and would be unable
to change a firewall if it tried — which is the point of §16, and is asserted by
`tests/test_p15_1_enforcement.py` reading this module's imports.

The sequence is §24, and each step can refuse:

    decision -> validate -> apply -> verify -> monitor -> expire -> verify removal

`execute()` returns what happened rather than what was attempted. A request the
helper refused, a write `nft` rejected, an element the kernel does not hold: all
three are failures, all three are reported, and none of them is a block.

### On counting

The block budget and the mass-block breaker are spent on *successful* blocks
only. A refusal is not an autonomous action, and charging the budget for one
would let a broken helper silently exhaust the system's willingness to act —
turning a firewall problem into a detection outage, quietly.
"""
from dataclasses import dataclass, field
import json
import subprocess
import sys

from .enforcement import EnforcementError, EnforcementRequest, HOST_NETWORK

HOST_ENFORCER_SCHEMA_VERSION = 1

#: The helper is invoked as a module of this same interpreter. No shell, no PATH
#: lookup, no configurable executable: a settable helper path is a settable
#: privileged program, and there is no reason for an operator to need one.
HELPER_MODULE = 'eye_for_an_eye.security.firewall_helper'
HELPER_TIMEOUT_SECONDS = 10


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """What the enforcement path did with one decision."""

    requested: bool
    succeeded: bool
    refused: bool
    reason: str = ''
    address: str = ''
    ttl_seconds: int = 0
    decision_id: str = ''
    helper_exit: int | None = None
    document: dict = field(default_factory=dict)

    def explain(self):
        return {'requested': self.requested, 'succeeded': self.succeeded,
                'refused': self.refused, 'reason': self.reason,
                'address': self.address, 'ttl_seconds': self.ttl_seconds,
                'decision_id': self.decision_id, 'helper_exit': self.helper_exit,
                'helper': dict(self.document)}


def request_from_record(record):
    """Build the request one decision record authorises, or refuse to.

    Reads the record rather than being told what to do, so the address, the TTL
    and the reasons in the firewall all come from the decision that was actually
    taken. A caller cannot ask for a different address or a longer block than the
    record supports, because it does not get to supply either.
    """
    if not record.blocked:
        raise EnforcementError('only a TEMP_BLOCK record authorises enforcement')
    if not record.network_enforceable or record.enforcement_scope != 'NETWORK_SOURCE':
        # §22. A client known only through somebody else's proxy is not a host
        # this filter can reach, and the address in the record belongs to the
        # proxy carrying everyone else.
        raise EnforcementError('this source is not network-enforceable; a network '
                               'block would hit a proxy rather than this client')
    if record.shadow:
        raise EnforcementError('a shadow decision is a record, not an instruction')
    return EnforcementRequest(address=record.source, ttl_seconds=record.block_ttl_seconds,
                              decision_id=record.decision_id,
                              reasons=tuple(record.reason_codes)[:8],
                              scope=HOST_NETWORK)


class HostEnforcer:
    """Hands validated requests to the privileged helper. Holds no privilege.

    `panel` is the P15 breaker panel, charged only when a block actually lands.
    """

    #: Structural, and asserted by the P15.1 enforcement tests.
    has_firewall_privilege = False

    def __init__(self, config_path, *, panel=None, python=None,
                 timeout=HELPER_TIMEOUT_SECONDS):
        self.config_path = str(config_path)
        self.panel = panel
        self.python = python or sys.executable
        self.timeout = timeout
        self.counters = {'requested': 0, 'succeeded': 0, 'refused': 0, 'failed': 0}

    def _invoke(self, verb, payload=None):
        try:
            completed = subprocess.run(
                [self.python, '-m', HELPER_MODULE, '--config', self.config_path, verb],
                input=payload, text=True, capture_output=True,
                timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired:
            return None, {'ok': False, 'refused': True,
                          'reason': 'the firewall helper did not answer in time'}
        except OSError as exc:
            return None, {'ok': False, 'refused': True,
                          'reason': f'the firewall helper could not be started: '
                                    f'{type(exc).__name__}'}
        try:
            document = json.loads(completed.stdout or '{}')
        except ValueError:
            # A helper that printed something unparseable has failed, whatever
            # its exit code said. Treating a zero exit with unreadable output as
            # success is how a silent failure becomes a believed block.
            document = {'ok': False, 'refused': True,
                        'reason': 'the firewall helper produced unreadable output'}
        return completed.returncode, document

    def execute(self, record):
        """One decision record, all the way to a verified kernel element or a refusal."""
        try:
            request = request_from_record(record)
        except EnforcementError as exc:
            self.counters['refused'] += 1
            return ExecutionResult(requested=False, succeeded=False, refused=True,
                                   reason=str(exc), decision_id=record.decision_id)
        self.counters['requested'] += 1
        code, document = self._invoke('apply', request.to_json())
        succeeded = bool(document.get('ok')) and code == 0
        if succeeded:
            self.counters['succeeded'] += 1
            if self.panel is not None:
                self.panel.record_block()
        elif document.get('refused'):
            self.counters['refused'] += 1
        else:
            self.counters['failed'] += 1
        return ExecutionResult(
            requested=True, succeeded=succeeded, refused=bool(document.get('refused')),
            reason=str(document.get('reason', ''))[:200],
            address=str(request.parsed), ttl_seconds=request.ttl_seconds,
            decision_id=request.decision_id, helper_exit=code, document=document)

    def dry_run(self, record):
        """§27. Everything except the write."""
        request = request_from_record(record)
        code, document = self._invoke('dry-run', request.to_json())
        return {'helper_exit': code, 'helper': document}

    def verify(self):
        code, document = self._invoke('verify')
        return {'helper_exit': code, 'helper': document}

    def status(self):
        code, document = self._invoke('status')
        return {'host_enforcer_schema_version': HOST_ENFORCER_SCHEMA_VERSION,
                'helper_exit': code, 'counters': dict(self.counters),
                'has_firewall_privilege': self.has_firewall_privilege,
                'helper': document}

    def reconcile(self):
        """§25. After a restart, find out what we are still enforcing."""
        code, document = self._invoke('reconcile')
        return {'helper_exit': code, 'helper': document}

    def cleanup(self):
        code, document = self._invoke('cleanup')
        return {'helper_exit': code, 'helper': document}
