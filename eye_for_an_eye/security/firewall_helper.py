"""The small privileged component. One request in, one result out, no shell.

    python -m eye_for_an_eye.security.firewall_helper --config <file> <verb>

This is the only part of Eye for an Eye that is allowed to change a host
firewall, and it is deliberately the smallest part. It reads one JSON
`EnforcementRequest` from stdin, validates it, checks it against the protected
networks *it* loads from configuration, and either writes one bounded element to
one owned table or refuses and says why.

### What it will not do

It has **no command field**. The request vocabulary is an address, a family, a
TTL, a decision id and reason codes; there is no field whose value becomes a
command, a path, a table name or a chain. An unprivileged process that is wholly
compromised can, at most, ask this helper to block an address that its own
configuration does not protect, for at most twelve hours — which is the same
thing the system does when it is working correctly, and is why the block budget
and the mass-block breaker sit upstream of here.

It does not trust the caller's protection decision. `PolicyGuard` refuses
protected sources before a request is ever built, and this helper refuses them
again from its own copy of the configuration. Duplicated work, deliberately:
the upstream check can be stale, skipped or wrong, and this one is the last one
before a packet filter changes.

It does not read the host ruleset. It reads one table, by name, and refuses to
touch it unless it carries this installation's owner comment.

### Why a separate process at all

So that the sentence "the decision engine has no firewall privilege" is a fact
about the process table rather than a claim about a call graph. The sensor runs
unprivileged; this runs with what it needs and nothing else; the boundary
between them carries a validated value object and no code.
"""
import argparse
import json
import sys

from ..config import load_config
from .enforcement import EnforcementError, EnforcementRequest, ProtectedNetworks
from .host_firewall import HostBackend, HostFirewallError

HELPER_SCHEMA_VERSION = 1

#: stdin is read with a hard cap. A privileged process that reads until EOF is a
#: privileged process an unprivileged one can make run out of memory.
MAX_REQUEST_BYTES = 4096

VERBS = ('apply', 'release', 'dry-run', 'verify', 'status', 'cleanup', 'reconcile')


def _refuse(reason, code=2):
    print(json.dumps({'helper_schema_version': HELPER_SCHEMA_VERSION,
                      'ok': False, 'refused': True, 'reason': reason}))
    return code


def _installation(config):
    """A stable identifier for this installation's owned table.

    Derived from configuration rather than generated, so a restart produces the
    same owner comment and can recognise its own table. Two installations on one
    host get different comments and therefore refuse to touch each other's work.
    """
    name = getattr(config.runtime, 'sensor_id', '') or getattr(config.deployment, 'profile', '')
    return str(name or 'default')[:48]


def _enabled(config):
    enforcement = config.enforcement
    if not getattr(enforcement, 'host_enabled', False):
        return False, ('enforcement.host_enabled is false; host enforcement is off '
                       'on a fresh installation and stays off until an operator '
                       'turns it on deliberately')
    if not enforcement.management_networks and not enforcement.allowlist:
        return False, ('no protected network is configured; a host that can be '
                       'locked out of itself is not one this may act on')
    return True, ''


def _backend(config):
    return HostBackend(_installation(config),
                       max_entries=config.enforcement.max_entries)


def _protection(config):
    return ProtectedNetworks.from_config(config)


def handle(verb, config, payload=''):
    """Run one verb. Returns `(exit_code, document)` and never raises for input."""
    backend = _backend(config)
    usable, reason = backend.available()
    if verb == 'status':
        return 0, backend.status()
    if not usable:
        return 3, {'ok': False, 'refused': True, 'reason': reason}

    if verb == 'cleanup':
        return 0, backend.cleanup()
    if verb == 'reconcile':
        return 0, backend.reconcile()
    if verb == 'verify':
        owned, detail = backend.owns_table()
        return (0 if owned else 4), {'ok': owned, 'detail': detail,
                                     'entries': backend.entries() if owned else []}

    permitted, why = _enabled(config)
    if not permitted:
        return 5, {'ok': False, 'refused': True, 'reason': why}

    request = EnforcementRequest.from_json(payload)
    protection = _protection(config)
    blocked_because = protection.protects(request.parsed)
    if blocked_because:
        # §23. The refusal that matters most, checked here because here is the
        # last place it can still be checked.
        return 6, {'ok': False, 'refused': True,
                   'reason': f'refusing a protected source: {blocked_because}',
                   'request': request.explain()}

    if verb == 'dry-run':
        return 0, {'ok': True, 'dry_run': backend.dry_run(request),
                   'request': request.explain()}
    if verb == 'release':
        return 0, {'ok': backend.release(request), 'request': request.explain()}
    result = backend.apply(request)
    return (0 if result.succeeded else 7), {'ok': result.succeeded,
                                            'result': result.explain(),
                                            'request': request.explain()}


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='eye-for-an-eye-firewall-helper',
        description='Apply one bounded temporary block to one owned nftables table.')
    parser.add_argument('verb', choices=VERBS)
    parser.add_argument('--config', required=True)
    args = parser.parse_args(argv)

    payload = ''
    if args.verb in ('apply', 'release', 'dry-run'):
        payload = sys.stdin.read(MAX_REQUEST_BYTES + 1)
        if len(payload) > MAX_REQUEST_BYTES:
            return _refuse('enforcement request exceeds its byte budget')
    try:
        config = load_config(args.config, require_version=True)
    except (OSError, ValueError) as exc:
        return _refuse(f'configuration refused: {type(exc).__name__}')
    try:
        code, document = handle(args.verb, config, payload)
    except EnforcementError as exc:
        return _refuse(f'invalid enforcement request: {exc}')
    except HostFirewallError as exc:
        return _refuse(f'host firewall: {exc}', code=8)
    except Exception as exc:                                  # noqa: BLE001
        # A privileged process must not print an arbitrary exception message: it
        # can carry a path, a hostname or a fragment of configuration. The class
        # name is enough to act on and carries nothing.
        return _refuse(f'unexpected failure: {type(exc).__name__}', code=9)
    document.setdefault('helper_schema_version', HELPER_SCHEMA_VERSION)
    print(json.dumps(document))
    return code


if __name__ == '__main__':
    sys.exit(main())
