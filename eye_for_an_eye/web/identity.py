"""Who sent this request? The security-critical question in the whole web layer.

Everything downstream — features, risk, and above all enforcement — depends on
answering it correctly, and the answer is easy to get wrong in a way that hands
an attacker a weapon. `X-Forwarded-For` is a string the client controls. Take it
at face value and anyone on the Internet can make the system believe a request
came from any address they like, which means framing somebody else, or hiding
behind an address the system trusts.

So this module holds one rule:

    A forwarded address is evidence only when the machine that sent it to us is
    one we were explicitly told to trust.

And one consequence that matters more than it looks:

    When the client is only known at the HTTP layer and reached us through a
    proxy, the proxy's address must never be blocked. Blocking it takes the site
    off the air for every other user behind it.

The resolver therefore returns not only an address but how much that address can
be trusted and what may be done with it.
"""
from dataclasses import dataclass
import ipaddress

IDENTITY_SCHEMA_VERSION = 1

#: How much the resolved client address can be relied on.
HIGH = 'HIGH'
MEDIUM = 'MEDIUM'
LOW = 'LOW'
CONFIDENCES = (HIGH, MEDIUM, LOW)

#: Where the address came from.
DIRECT_PEER = 'direct_peer'
TRUSTED_PROXY_CHAIN = 'trusted_proxy_chain'
PARTIAL_PROXY_CHAIN = 'partial_proxy_chain'
UNTRUSTED_FORWARDED = 'untrusted_forwarded'
ORIGINS = (DIRECT_PEER, TRUSTED_PROXY_CHAIN, PARTIAL_PROXY_CHAIN, UNTRUSTED_FORWARDED)

#: A forwarded header longer than this is truncated before parsing. A header is
#: attacker-controlled, so its length is a resource decision, not a courtesy.
MAX_FORWARDED_CHARS = 2048
#: Addresses parsed from one chain. Beyond this the chain is treated as hostile
#: noise rather than as a routing record.
MAX_CHAIN_ENTRIES = 16


class IdentityError(ValueError):
    """A resolver could not be built. Never raised while resolving a request."""


@dataclass(frozen=True)
class ClientIdentity:
    """The resolved client, and what the system is allowed to do about it.

    `network_enforceable` is the field that keeps a site online. It is False
    whenever acting on `address` at the network layer would hit a proxy rather
    than the client, or whenever the address is not trustworthy enough to act on
    at all.
    """

    address: str
    peer_address: str
    origin: str
    confidence: str
    network_enforceable: bool
    reason: str
    chain_length: int = 0
    forwarded_ignored: bool = False

    @property
    def uncertain(self):
        return self.confidence == LOW

    def explain(self):
        return {'identity_schema_version': IDENTITY_SCHEMA_VERSION,
                'client': self.address, 'peer': self.peer_address,
                'origin': self.origin, 'confidence': self.confidence,
                'network_enforceable': self.network_enforceable,
                'reason': self.reason, 'chain_length': self.chain_length,
                'forwarded_ignored': self.forwarded_ignored}


def _address(text):
    """Parse one address, tolerating the shapes real proxies emit.

    Accepts a bare address, a bracketed IPv6 address, and either with a port.
    Returns None for anything else — including `unknown`, `_hidden`, and the
    obfuscated identifiers RFC 7239 allows, which are not addresses and must not
    be treated as one.
    """
    if not text:
        return None
    value = str(text).strip().strip('"')
    if not value or len(value) > 64:
        return None
    if value.startswith('['):
        # [2001:db8::1] or [2001:db8::1]:443
        end = value.find(']')
        if end < 0:
            return None
        inner, rest = value[1:end], value[end + 1:]
        if rest and not rest.startswith(':'):
            return None
        value = inner
    elif value.count(':') == 1:
        # host:port for IPv4. A bare IPv6 address has more than one colon.
        value = value.rsplit(':', 1)[0]
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def parse_chain(header):
    """Addresses from a forwarded header, left to right, bounded.

    Entries that are not addresses are dropped rather than guessed at. Order is
    preserved because it is the only thing that makes the chain meaningful, and
    the walk that uses it goes right to left for a reason: the right-hand end is
    the part our own infrastructure wrote.
    """
    if not header:
        return ()
    text = str(header)[:MAX_FORWARDED_CHARS]
    found = []
    for part in text.split(',')[:MAX_CHAIN_ENTRIES]:
        part = part.strip()
        if '=' in part:
            # RFC 7239 style: for=192.0.2.1;proto=https
            for token in part.split(';'):
                key, _, value = token.partition('=')
                if key.strip().lower() == 'for':
                    part = value.strip()
                    break
            else:
                continue
        address = _address(part)
        if address is not None:
            found.append(address)
    return tuple(found)


class ClientResolver:
    """Resolves the client address for one deployment's proxy topology.

    Built once from configuration. `resolve` is pure and never raises: a request
    that cannot be understood produces a low-confidence identity that cannot
    drive enforcement, which is the safe reading of "we do not know".
    """

    def __init__(self, trusted_proxy_networks=(), *, trust_forwarded=True):
        self.networks = []
        for entry in trusted_proxy_networks or ():
            try:
                self.networks.append(ipaddress.ip_network(str(entry), strict=False))
            except ValueError as exc:
                raise IdentityError(f'invalid trusted proxy network: {entry!r}') from exc
        self.networks = tuple(self.networks)
        self.trust_forwarded = bool(trust_forwarded)

    @property
    def configured(self):
        return bool(self.networks)

    def is_trusted_proxy(self, address):
        if address is None:
            return False
        return any(address in network for network in self.networks)

    def resolve(self, peer, forwarded=None, *, real_ip=None):
        """Resolve one request's client. Returns a `ClientIdentity`.

        The peer is the only address we observed ourselves, so it is the anchor.
        Everything else is a claim, and a claim is only worth something when the
        machine that made it is trusted.
        """
        peer_address = _address(peer)
        if peer_address is None:
            return ClientIdentity(address='', peer_address=str(peer or '')[:64],
                                  origin=UNTRUSTED_FORWARDED, confidence=LOW,
                                  network_enforceable=False,
                                  reason='the peer address could not be parsed')

        peer_text = str(peer_address)
        chain = parse_chain(forwarded) if self.trust_forwarded else ()
        if not chain and real_ip and self.trust_forwarded:
            single = _address(real_ip)
            chain = (single,) if single is not None else ()

        # The peer is not a proxy we know. Whatever it claims about other
        # addresses is unverifiable, so the peer itself is the client.
        if not self.is_trusted_proxy(peer_address):
            if chain:
                return ClientIdentity(
                    address=peer_text, peer_address=peer_text, origin=DIRECT_PEER,
                    confidence=HIGH, network_enforceable=True, chain_length=len(chain),
                    forwarded_ignored=True,
                    reason=('a forwarded header was present but the peer is not a configured '
                            'trusted proxy, so the header was ignored'))
            return ClientIdentity(
                address=peer_text, peer_address=peer_text, origin=DIRECT_PEER,
                confidence=HIGH, network_enforceable=True,
                reason='the client connected to this server directly')

        # The peer is a trusted proxy. Walk the chain from the right, stepping
        # over addresses that are themselves trusted proxies. The first address
        # that is not one of ours is the closest thing to a real client that our
        # own infrastructure vouched for.
        if not chain:
            return ClientIdentity(
                address=peer_text, peer_address=peer_text, origin=TRUSTED_PROXY_CHAIN,
                confidence=LOW, network_enforceable=False,
                reason=('the request came from a trusted proxy but carried no forwarded '
                        'address, so the real client is unknown'))

        index = len(chain) - 1
        hops = 0
        while index >= 0 and self.is_trusted_proxy(chain[index]):
            index -= 1
            hops += 1
        if index < 0:
            # Every address in the chain is one of our own proxies. There is no
            # client address here, only our infrastructure talking to itself.
            return ClientIdentity(
                address=peer_text, peer_address=peer_text, origin=TRUSTED_PROXY_CHAIN,
                confidence=LOW, network_enforceable=False, chain_length=len(chain),
                reason=('every address in the forwarded chain is a trusted proxy, so no '
                        'client address was learned'))

        client = chain[index]
        remaining_untrusted = index  # addresses to the left, all client-controlled
        if remaining_untrusted:
            # The client appended addresses of its own before ours. The one we
            # picked is still the address our proxy saw, so it is usable, but the
            # chain is not clean and that is worth recording.
            return ClientIdentity(
                address=str(client), peer_address=peer_text, origin=PARTIAL_PROXY_CHAIN,
                confidence=MEDIUM, network_enforceable=False, chain_length=len(chain),
                reason=(f'{remaining_untrusted} address(es) in the forwarded chain came from '
                        'the client and cannot be verified; the address our proxy observed '
                        'was used'))
        return ClientIdentity(
            address=str(client), peer_address=peer_text, origin=TRUSTED_PROXY_CHAIN,
            confidence=HIGH, network_enforceable=False, chain_length=len(chain),
            reason=(f'a trusted proxy chain of {hops} hop(s) reported this client; the proxy '
                    'address itself is never blocked'))


def source_scope(identity):
    """What an action against this identity may act on.

    `NETWORK_SOURCE` means the address is the machine that connected to us, so a
    network-level action reaches it and nobody else. Anything else means the
    address belongs to a client behind somebody else's infrastructure, where a
    network block would hit the wrong machine.
    """
    if identity.network_enforceable and identity.confidence == HIGH:
        return 'NETWORK_SOURCE'
    if identity.origin in (TRUSTED_PROXY_CHAIN, PARTIAL_PROXY_CHAIN):
        return 'WEB_CLIENT'
    return 'UNKNOWN'
