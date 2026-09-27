"""Multi-site support: one engine, several websites, kept apart.

The reason this package exists is one sentence: **different websites have
different normal behaviour.** A blog full of anonymous GETs and crawler traffic,
an API doing five hundred requests a minute to four endpoints, and an admin panel
that sees forty requests a day are all behaving normally, and no single baseline
describes all three.

What is shared and what is separate is the whole design:

    shared      the engine, the base model, the network-layer evidence about a
                host, the global safety limits
    separate    web behaviour, per-site state, baselines, policy, challenge
                keys, drift, out-of-distribution reference, dataset scope

The rule that everything else rests on: **a SiteID comes from local
configuration, never from the request.** A client chooses its own `Host` header,
so a system that derives identity from it lets a client pick which site's policy
and which site's cryptographic key apply to it.
"""
from .identity import (MAX_SITE_CHARS, SiteMatch, SiteResolver, SiteResolverError,
                       UNKNOWN_SITE, normalise_host, normalise_site_id)

__all__ = ['MAX_SITE_CHARS', 'SiteMatch', 'SiteResolver', 'SiteResolverError',
           'UNKNOWN_SITE', 'normalise_host', 'normalise_site_id']
