"""Which site did this request belong to? Resolved from configuration only.

This module answers one question and refuses to guess at it. Getting it wrong in
either direction is serious:

* Map a request to the **wrong** site and its behaviour pollutes another site's
  baseline, its policy is applied to traffic it was not written for, and — worst
  — a challenge token minted for one site could be presented to another.
* Let a request **create** a site and an attacker with a `Host:` header loop can
  fill memory with a million site profiles.

So the resolver is a lookup into a fixed table built at startup from
configuration, and nothing a client sends can add an entry to it.

## Why the Host header cannot be trusted

`Host` is a string the client writes. Nginx passes it through as `$host`. If a
SiteID were derived from it, then a client could:

* choose which site's policy applies to it — pick the most permissive one;
* choose which site's challenge key signs its token — and a token is scoped by
  the key that signed it, so this would collapse the isolation in P11;
* invent a new site per request.

The header is therefore used for exactly one thing: as a lookup key into the
operator's table. A miss is a miss — it becomes `UNKNOWN_SITE`, which is a single
bounded bucket, not a new site.

## Why an imperfect normaliser is still safe

Host normalisation has genuinely hard corners: ports, IPv6 literals, trailing
dots, and internationalised names where two different strings can look identical
to a person. This module does not claim to have solved that.

What makes it safe anyway is that **the configured domain and the observed host
go through the same function**, and the result is only ever compared for exact
equality against a bounded configured set. An imperfect normaliser can therefore
fail to match — which sends the request to `UNKNOWN_SITE`, the conservative
answer — but it cannot make host A match site B's entry unless the operator
configured them as the same string. The failure direction is the safe one, and
that is a property of the design rather than of the normaliser's cleverness.
"""
from dataclasses import dataclass
import ipaddress

#: The bucket every unresolvable host lands in. One bucket, not one per host:
#: this is what makes a `Host:` cardinality attack bounded.
UNKNOWN_SITE = 'unknown-site'

#: A SiteID is an operator-chosen name, so it is short by construction. The
#: bound exists so that a long one cannot become a long metric label or a long
#: filesystem path.
MAX_SITE_CHARS = 64

#: The DNS maximum. A longer value is not a hostname.
MAX_HOST_CHARS = 253
MAX_LABEL_CHARS = 63

#: Characters allowed in a SiteID. Deliberately narrow: a SiteID becomes a
#: directory name in the model registry, a metric label, and an HKDF info
#: string, and none of those want surprises.
_SITE_CHARACTERS = frozenset('abcdefghijklmnopqrstuvwxyz0123456789.-_')

#: Characters allowed in one hostname label. Underscore is permitted because
#: internal service names use it and exact matching makes it harmless.
_LABEL_CHARACTERS = frozenset('abcdefghijklmnopqrstuvwxyz0123456789-_')

#: Names that would collide with the reserved bucket or read as a placeholder.
RESERVED_SITE_IDS = (UNKNOWN_SITE, 'global', 'all', 'none', '')


class SiteResolverError(ValueError):
    """The site configuration cannot be used. Raised at startup, never per request."""


def normalise_site_id(site):
    """An operator-configured site identifier, bounded and predictable.

    This is the canonical definition for the whole project. The challenge layer
    had its own copy first (P11's `challenge.token.normalise_site`); that one now
    delegates here, because two functions that both decide what a site is called
    is exactly the "second competing abstraction" worth avoiding — they would
    drift, and the day they disagreed a token would be signed under one spelling
    and verified under another.
    """
    text = str(site or '').strip().lower()[:MAX_SITE_CHARS]
    cleaned = ''.join(character for character in text if character in _SITE_CHARACTERS)
    return cleaned


def _strip_port(text):
    """Remove an optional `:port`, handling bracketed IPv6 authority syntax.

    `example.org:443` and `[2001:db8::1]:443` both carry a port; a bare
    `2001:db8::1` carries several colons and no port at all. Splitting on the
    last colon without knowing which case applies is how an IPv6 address becomes
    a truncated hostname, so the bracket form is handled separately.
    """
    if text.startswith('['):
        closing = text.find(']')
        if closing < 0:
            return None
        authority, remainder = text[:closing + 1], text[closing + 1:]
        if remainder and not (remainder.startswith(':') and remainder[1:].isdigit()):
            return None
        return authority
    if text.count(':') > 1:
        # Several colons and no brackets: an unbracketed IPv6 address, which is
        # not valid in a Host header, or something malformed. Either way it is
        # not something to guess at.
        return None
    host, separator, port = text.partition(':')
    if separator and not port.isdigit():
        return None
    return host


def _valid_labels(host):
    if not host or len(host) > MAX_HOST_CHARS:
        return False
    for label in host.split('.'):
        if not 1 <= len(label) <= MAX_LABEL_CHARS:
            return False
        if label.startswith('-') or label.endswith('-'):
            return False
        if not _LABEL_CHARACTERS.issuperset(label):
            return False
    return True


def normalise_host(host):
    """A hostname in one canonical form, or `''` when it is not usable.

    Handles case, an optional port, a trailing dot, IPv4 and bracketed IPv6
    literals, and internationalised names. Returns `''` rather than raising:
    every caller's answer to a bad host is the same (`UNKNOWN_SITE`), and an
    exception on the request path would be a way to turn a malformed header into
    an error page.

    Returning `''` for anything doubtful is deliberate. The cost of refusing a
    host that was really valid is that its traffic is analysed as
    `UNKNOWN_SITE`; the cost of accepting one that was really two different
    things is cross-site contamination.
    """
    if not host:
        return ''
    # Only spaces and tabs are stripped, and only from the ends: those are
    # ordinary padding. A carriage return or newline is not padding — it is the
    # shape of header injection — so it must survive to be refused below rather
    # than be quietly tidied away by a broader `strip()`.
    text = str(host).strip(' \t')
    if len(text) > MAX_HOST_CHARS + 8:  # room for ':65535' and brackets
        return ''
    # A comma or remaining whitespace means several values arrived in one field
    # — two Host headers, or a forwarded list. Which was meant is not knowable.
    if any(character in text for character in ' \t\r\n,;'):
        return ''
    if any(ord(character) < 0x20 or ord(character) == 0x7f for character in text):
        return ''

    if not text.isascii():
        # An internationalised name. Encode to punycode so that the configured
        # domain and the observed host reduce to the same ASCII form. Python's
        # `idna` codec is IDNA2003 and is stricter and older than UTS-46, so
        # some valid names are refused here; refusing sends them to
        # UNKNOWN_SITE, which is the safe direction, and the same function
        # normalises the configuration, so a mismatch cannot become a mismatched
        # *site*.
        try:
            text = text.encode('idna').decode('ascii')
        except (UnicodeError, UnicodeDecodeError):
            return ''

    text = text.lower()
    stripped = _strip_port(text)
    if stripped is None:
        return ''
    stripped = stripped.rstrip('.')  # `example.org.` is the same name as `example.org`
    if not stripped:
        return ''

    if stripped.startswith('['):
        try:
            address = ipaddress.IPv6Address(stripped[1:-1])
        except ValueError:
            return ''
        # `[2001:DB8::0:1]` and `[2001:db8::1]` are one address with two
        # spellings; the library's compressed form is the canonical one.
        return f'[{address.compressed}]'

    try:
        return ipaddress.IPv4Address(stripped).compressed
    except ValueError:
        pass

    return stripped if _valid_labels(stripped) else ''


#: How a request's site was decided. Recorded on the decision so an operator can
#: tell "this is site main" from "nothing matched, so it went to the bucket".
CONFIGURED = 'configured'
DEFAULT_SITE = 'default_site'
UNKNOWN = 'unknown'
MALFORMED = 'malformed'
ORIGINS = (CONFIGURED, DEFAULT_SITE, UNKNOWN, MALFORMED)


@dataclass(frozen=True)
class SiteMatch:
    """Which site a request belongs to, and how that was decided."""

    site_id: str
    origin: str
    host: str = ''
    reason: str = ''

    @property
    def known(self):
        return self.site_id != UNKNOWN_SITE

    def explain(self):
        return {'site_id': self.site_id, 'origin': self.origin,
                'host_matched': bool(self.host) and self.origin == CONFIGURED,
                'reason': self.reason}


class SiteResolver:
    """Maps a normalised host to a configured SiteID. Nothing else can.

    Built once at startup from configuration and then read-only: there is no
    method that adds a site, which is the structural reason a `Host:` header
    cannot create one.
    """

    def __init__(self, sites=None, *, default_site='', max_sites=64):
        """`sites` maps SiteID to its domains.

        A duplicate domain across two sites is refused rather than resolved by
        precedence. Whichever site won would be a silent decision about where a
        real website's traffic goes, and the operator would have no way to know
        it had been made.
        """
        self.max_sites = max(1, int(max_sites))
        self._domains = {}
        self._sites = []

        for raw_site, domains in (sites or {}).items():
            site_id = normalise_site_id(raw_site)
            if not site_id:
                raise SiteResolverError(
                    f'{raw_site!r} is not a usable site name; use letters, digits, '
                    'dot, dash or underscore')
            if site_id in RESERVED_SITE_IDS:
                raise SiteResolverError(f'{site_id!r} is a reserved site name')
            if site_id in self._sites:
                raise SiteResolverError(f'site {site_id!r} is configured twice')
            self._sites.append(site_id)
            for raw_domain in domains or ():
                domain = normalise_host(raw_domain)
                if not domain:
                    raise SiteResolverError(
                        f'site {site_id!r}: {raw_domain!r} is not a usable domain')
                owner = self._domains.get(domain)
                if owner is not None and owner != site_id:
                    raise SiteResolverError(
                        f'domain {domain!r} is mapped to both {owner!r} and '
                        f'{site_id!r}; one domain belongs to one site')
                self._domains[domain] = site_id

        if len(self._sites) > self.max_sites:
            raise SiteResolverError(
                f'{len(self._sites)} sites are configured; the limit is '
                f'{self.max_sites}')

        self.default_site = normalise_site_id(default_site)
        if self.default_site and self.default_site not in self._sites:
            raise SiteResolverError(
                f'the default site {self.default_site!r} is not one of the '
                'configured sites')

    @property
    def sites(self):
        return tuple(self._sites)

    @property
    def domains(self):
        return dict(self._domains)

    def __len__(self):
        return len(self._sites)

    def resolve(self, host):
        """Which site is this request for? Never raises, never adds a site."""
        if not self._sites:
            # Single-site deployments configure no sites at all, and everything
            # they serve is theirs. Saying so plainly beats inventing a site.
            return SiteMatch(UNKNOWN_SITE, UNKNOWN, reason='no sites are configured')

        normalised = normalise_host(host)
        if not normalised:
            return SiteMatch(UNKNOWN_SITE, MALFORMED,
                             reason='the host could not be read as a hostname')

        site_id = self._domains.get(normalised)
        if site_id is not None:
            return SiteMatch(site_id, CONFIGURED, host=normalised,
                             reason='the host matches a configured domain')

        if self.default_site:
            return SiteMatch(self.default_site, DEFAULT_SITE, host=normalised,
                             reason='no domain matched; the configured default site '
                                    'applies')

        return SiteMatch(UNKNOWN_SITE, UNKNOWN, host=normalised,
                         reason='no configured domain matches this host')

    def health(self):
        return {'sites': len(self._sites), 'domains': len(self._domains),
                'max_sites': self.max_sites,
                'default_site': self.default_site or None,
                'unknown_site': UNKNOWN_SITE,
                'note': ('sites come from configuration; a Host header can only '
                         'select one, never create one')}
