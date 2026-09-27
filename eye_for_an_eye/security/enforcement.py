"""The request that crosses the privilege boundary, and everything it must satisfy.

Until P15.1 there was nothing to cross. The decision half and the enforcement
half both existed and the only thing between them was a namespace the enforcement
half refused to leave. Host enforcement changes that, and the thing that makes it
safe is not the nftables code — it is this file: one small, validated, immutable
value, and a boundary that accepts nothing else.

**No command field, ever.** An `EnforcementRequest` says *which address, which
family, for how long, why, and under which decision*. It does not say what to
run. A privileged helper that accepted a command from an unprivileged process
would be a remote shell with extra steps, however carefully the caller was
written, and the P15 invariants would be one bug away from meaningless.

**Validation happens on both sides.** The unprivileged side validates so a bad
request never leaves; the privileged side validates again because it cannot
assume the caller is the one that was written. That is not belt and braces, it
is the only assumption a privileged process is allowed to make about its input.

**Protection is re-checked at the side-effect boundary.** `PolicyGuard` already
refused protected sources upstream. The helper checks again against its own
configuration immediately before writing, because the interesting failure is not
"the guard was wrong" — it is "the guard ran five minutes ago and the
configuration changed", or "something skipped the guard".
"""
from dataclasses import dataclass
import ipaddress
import json
import re

ENFORCEMENT_REQUEST_VERSION = 1

#: The only scope a host firewall can honestly enforce. A website behind a CDN is
#: a client of somebody else's infrastructure, and no packet filter on this
#: machine can tell two of them apart (§98, §32).
HOST_NETWORK = 'HOST_NETWORK'
SCOPES = (HOST_NETWORK,)

#: The same ceiling `config.py` and `autonomy/record.py` already enforce. Stated
#: again here because this is the last place the number can still be wrong, and
#: §19 says P15.1 does not raise it.
MAX_TTL_SECONDS = 43_200

#: A decision identifier as `autonomy/record.py` mints them.
DECISION_ID = re.compile(r'^dec-[0-9a-f]{18}$')
#: Reason codes are a bounded enum upstream; this is the shape check, not the
#: membership check, because the helper must not need to import the decision code.
REASON_CODE = re.compile(r'^[A-Z][A-Z_]{3,39}$')

MAX_REASONS = 8


class EnforcementError(ValueError):
    """A request that must not cross the privilege boundary."""


@dataclass(frozen=True, slots=True)
class EnforcementRequest:
    """One temporary, bounded, defensive block of one source of this host.

    Immutable on purpose: a request that could be edited after validation is a
    request that was never validated.
    """

    address: str
    ttl_seconds: int
    decision_id: str
    reasons: tuple = ()
    scope: str = HOST_NETWORK
    version: int = ENFORCEMENT_REQUEST_VERSION

    def __post_init__(self):
        if self.version != ENFORCEMENT_REQUEST_VERSION:
            raise EnforcementError('unsupported enforcement request version')
        if self.scope not in SCOPES:
            raise EnforcementError(f'unsupported enforcement scope {self.scope!r}')
        parsed = self.parsed
        if parsed.is_loopback or parsed.is_multicast or parsed.is_unspecified:
            raise EnforcementError('refusing loopback, multicast or unspecified')
        if parsed.is_link_local:
            raise EnforcementError('refusing link-local')
        if type(self.ttl_seconds) is not int:
            raise EnforcementError('TTL must be a whole number of seconds')
        if not 0 < self.ttl_seconds <= MAX_TTL_SECONDS:
            raise EnforcementError(
                f'TTL must be between 1 and {MAX_TTL_SECONDS} seconds; there is no '
                'permanent block')
        if not DECISION_ID.match(str(self.decision_id)):
            raise EnforcementError('a block must name the decision that produced it')
        if not self.reasons or len(self.reasons) > MAX_REASONS:
            raise EnforcementError(f'between 1 and {MAX_REASONS} reason codes required')
        for reason in self.reasons:
            if not REASON_CODE.match(str(reason)):
                raise EnforcementError(f'malformed reason code {reason!r}')

    @property
    def parsed(self):
        try:
            address = ipaddress.ip_address(self.address)
        except ValueError as exc:
            raise EnforcementError(f'not an address: {self.address!r}') from exc
        # An IPv4-mapped IPv6 address is the same machine wearing a different
        # spelling. Normalising here means the set membership check and the
        # protected-network check cannot disagree about who this is.
        return getattr(address, 'ipv4_mapped', None) or address

    @property
    def family(self):
        return 'ipv4' if self.parsed.version == 4 else 'ipv6'

    def to_json(self):
        return json.dumps({'version': self.version, 'scope': self.scope,
                           'address': str(self.parsed), 'ttl_seconds': self.ttl_seconds,
                           'decision_id': self.decision_id,
                           'reasons': list(self.reasons)},
                          sort_keys=True, separators=(',', ':'))

    @classmethod
    def from_json(cls, payload):
        """Parse one request from the privilege boundary. Strict by construction.

        Rejects unknown fields rather than ignoring them: a field the helper does
        not understand is either a newer version it must not guess at, or an
        attempt to smuggle one in.
        """
        if len(payload) > 4096:
            raise EnforcementError('enforcement request exceeds its byte budget')
        try:
            body = json.loads(payload)
        except ValueError as exc:
            raise EnforcementError('enforcement request is not valid JSON') from exc
        if not isinstance(body, dict):
            raise EnforcementError('enforcement request must be an object')
        allowed = {'version', 'scope', 'address', 'ttl_seconds', 'decision_id', 'reasons'}
        unknown = set(body) - allowed
        if unknown:
            raise EnforcementError(f'unknown enforcement request fields: {sorted(unknown)}')
        reasons = body.get('reasons')
        if not isinstance(reasons, list) or any(not isinstance(r, str) for r in reasons):
            raise EnforcementError('reasons must be a list of strings')
        return cls(address=str(body.get('address', '')),
                   ttl_seconds=body.get('ttl_seconds'),
                   decision_id=str(body.get('decision_id', '')),
                   reasons=tuple(reasons),
                   scope=str(body.get('scope', '')),
                   version=body.get('version'))

    def explain(self):
        return {'scope': self.scope, 'address': str(self.parsed), 'family': self.family,
                'ttl_seconds': self.ttl_seconds, 'decision_id': self.decision_id,
                'reasons': list(self.reasons)}


@dataclass(frozen=True, slots=True)
class ProtectedNetworks:
    """What may never be blocked, resolved once and checked at every write.

    Loopback, unspecified, multicast and link-local are refused by the request
    itself. This adds what only the installation knows: its management networks,
    its allowlist, its trusted proxies, and the addresses of the host itself.
    """

    networks: tuple = ()
    local_addresses: tuple = ()

    @classmethod
    def from_config(cls, config):
        entries = []
        enforcement = config.enforcement
        for value in (*enforcement.management_networks, *enforcement.allowlist,
                      *enforcement.trusted_proxies):
            entries.append(ipaddress.ip_network(str(value), strict=True))
        return cls(networks=tuple(entries))

    def with_local(self, addresses):
        parsed = []
        for value in addresses:
            try:
                parsed.append(ipaddress.ip_address(str(value)))
            except ValueError:
                continue
        return ProtectedNetworks(networks=self.networks, local_addresses=tuple(parsed))

    def protects(self, address):
        """Whether this address may never be blocked, and why.

        Returns a reason string, or an empty string when the address is not
        protected. A string rather than a boolean because the refusal has to be
        recordable: "refused" with no reason is how an operator ends up
        believing the system is broken when it is working.
        """
        parsed = getattr(address, 'ipv4_mapped', None) or address
        if parsed.is_loopback:
            return 'loopback'
        if parsed.is_unspecified or parsed.is_multicast or parsed.is_link_local:
            return 'reserved address range'
        if parsed in self.local_addresses:
            return 'an address of this host'
        for network in self.networks:
            if parsed.version == network.version and parsed in network:
                return f'protected network {network}'
        return ''

    def explain(self):
        return {'protected_networks': [str(n) for n in self.networks],
                'local_addresses': [str(a) for a in self.local_addresses],
                'always_protected': ['loopback', 'unspecified', 'multicast', 'link-local']}
