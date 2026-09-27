"""The multi-site engine: resolve, isolate, decide, explain.

One object holds the pieces — the resolver, the profiles, the per-site state,
the baselines, the model resolution and the per-site challenge services — and
answers the questions the rest of the system asks about a site.

Two things here are worth reading closely.

## Host network evidence is deliberately not isolated

Everything web-shaped is per site. Network-layer evidence is not, and that is a
decision rather than an oversight.

A source that scans ports 22, 80, 443 and 3306 has told you something about the
*host*, and that fact does not stop being true when you look at it from site B.
Throwing it away in the name of isolation would make multi-site deployments
worse at detection than single-site ones, for no privacy or safety benefit.

So evidence is separated by kind rather than thrown away:

    HOST_NETWORK_EVIDENCE   about the machine — shared, and legitimately so
    SITE_WEB_EVIDENCE       about one site's HTTP traffic — never shared

Site A's path enumeration never touches site B's counters. The port scan both of
them can see is a different observation about a different layer.

## A network block is not a site-local action

`TEMP_BLOCK` at the network layer removes a source's access to *every* site on
the machine. Calling that a site-local action would be a lie with an outage
attached — site B's visitors would disappear because of something site A saw.

So the two are named separately (`SITE_WEB_ACTION`, `NETWORK_HOST_BLOCK`), a
site must be explicitly configured to be allowed to ask for the host-wide one,
and the decision record says which was chosen and who it reaches.
"""
from collections import Counter
from dataclasses import dataclass, field

from .baseline import missing as missing_baseline
from .identity import SiteResolver, UNKNOWN_SITE
from .models import ModelResolver
from .profile import SiteProfile, build_all, build_settings
from .state import SiteStateRegistry

SITE_ENGINE_SCHEMA_VERSION = 1

#: What an action reaches (§97).
SITE_WEB_ACTION = 'SITE_WEB_ACTION'
NETWORK_HOST_BLOCK = 'NETWORK_HOST_BLOCK'


@dataclass(frozen=True)
class SiteContext:
    """Everything decided about one site, gathered once per request."""

    site_id: str
    profile: SiteProfile
    origin: str
    known: bool = True
    reason: str = ''

    @property
    def settings(self):
        return self.profile.settings

    def explain(self):
        return {'site_id': self.site_id, 'profile': self.profile.profile_type,
                'site_origin': self.origin, 'site_known': self.known,
                'site_reason': self.reason}


#: The profile the unknown bucket runs under. Deliberately the most cautious
#: settings available: traffic that matched no configured domain is usually a
#: misconfiguration or a scanner, and neither is a reason to act on a site
#: nobody configured.
def _unknown_profile():
    return SiteProfile(
        site_id=UNKNOWN_SITE, profile_type='custom', enabled=True, domains=(),
        settings=build_settings('custom', {'mode': 'shadow',
                                           'challenge_enabled': False,
                                           'rate_limit_enabled': False,
                                           'allow_host_network_block': False,
                                           'collect_dataset': False}))


@dataclass
class CrossSiteEvidence:
    """What one source did across several sites (§100, §101).

    Host-level evidence, and bounded: counts and a small set of site names, all
    of which are configured values rather than anything a client chose. A source
    probing `/admin` on one site, `/.env` on another and `/wp-login.php` on a
    third is doing something a single site cannot see.

    It is deliberately not per-site HTTP state leaking sideways. Site A's path
    counters stay site A's; what crosses is the much smaller fact that the same
    source appeared on several sites and looked odd on more than one.
    """

    sites_touched: set = field(default_factory=set)
    sites_probing: set = field(default_factory=set)
    sites_with_sensitive: set = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0

    def record(self, site_id, *, probing=False, sensitive=False, now=0.0):
        if not self.first_seen:
            self.first_seen = now
        self.last_seen = now
        # Bounded by the configured site count, which is itself bounded.
        self.sites_touched.add(site_id)
        if probing:
            self.sites_probing.add(site_id)
        if sensitive:
            self.sites_with_sensitive.add(site_id)

    def features(self):
        """Bounded host-level features. None of these is a site identifier."""
        return {'sites_touched': float(len(self.sites_touched)),
                'sites_with_probing': float(len(self.sites_probing)),
                'sites_with_sensitive_paths': float(len(self.sites_with_sensitive)),
                'cross_site_probe_diversity': (
                    len(self.sites_probing) / len(self.sites_touched)
                    if self.sites_touched else 0.0)}


class SiteEngine:
    """Resolves sites and holds everything that is per site.

    Built once from a validated configuration. Nothing here creates a site.
    """

    def __init__(self, profiles=None, *, default_site='', max_sites=32,
                 max_sources_global=8192, max_sources_per_site=2048,
                 reserved_per_site=64, model_registry=None):
        self.profiles = dict(profiles or {})
        self.unknown_profile = _unknown_profile()
        self.resolver = SiteResolver(
            {site: profile.domains for site, profile in self.profiles.items()},
            default_site=default_site, max_sites=max_sites)
        self.state = SiteStateRegistry(
            list(self.profiles),
            max_sources_global=max_sources_global,
            max_sources_per_site=max_sources_per_site,
            reserved_per_site=reserved_per_site)
        self.models = ModelResolver(model_registry) if model_registry else None
        self.baselines = {site: missing_baseline(site) for site in self.profiles}
        self.baselines[UNKNOWN_SITE] = missing_baseline(UNKNOWN_SITE)
        self._challenges = {}
        self._cross_site = {}
        self._max_cross_site = 4096
        self.metrics = Counter()

    # --- resolution ------------------------------------------------------

    def context(self, host):
        """Which site is this request for, with its profile attached."""
        match = self.resolver.resolve(host)
        profile = self.profiles.get(match.site_id)
        if profile is None or not profile.enabled:
            reason = (match.reason if profile is None
                      else f'site {match.site_id} is configured but disabled')
            self.metrics[f'site_unknown:{match.origin}'] += 1
            return SiteContext(UNKNOWN_SITE, self.unknown_profile, match.origin,
                               known=False, reason=reason)
        self.metrics[f'site_resolved:{match.site_id}'] += 1
        return SiteContext(match.site_id, profile, match.origin, known=True,
                           reason=match.reason)

    def baseline(self, site_id):
        return self.baselines.get(site_id, self.baselines[UNKNOWN_SITE])

    def set_baseline(self, site_id, baseline):
        """Install an activated baseline for one site. Never for another."""
        if site_id not in self.baselines:
            raise KeyError(f'{site_id} is not a configured site')
        if baseline.site_id != site_id:
            raise ValueError(
                f'baseline is for {baseline.site_id!r}, not {site_id!r}; a '
                'baseline describes one site and must not be installed elsewhere')
        self.baselines[site_id] = baseline

    # --- challenge -------------------------------------------------------

    def challenge_for(self, site_id, factory):
        """One challenge service per site, built on demand and cached.

        Each site's tokens are signed with a key derived from the master secret
        and that site's identifier, so a token minted for one site does not
        verify for another. That isolation is P11's HKDF derivation doing its
        job — nothing new is invented here, which is the reason it can be
        trusted.
        """
        site = site_id if site_id in self.profiles else UNKNOWN_SITE
        existing = self._challenges.get(site)
        if existing is None:
            existing = factory(site)
            self._challenges[site] = existing
        return existing

    # --- evidence --------------------------------------------------------

    def observe(self, context, event, now, *, probing=False, sensitive=False):
        """Record one request against one site, and note the cross-site fact."""
        state = self.state.observe(context.site_id, event, now)
        source = event.client or event.peer
        if source and (probing or sensitive or context.known):
            self._record_cross_site(source, context.site_id, probing=probing,
                                    sensitive=sensitive, now=now)
        return state

    def _record_cross_site(self, source, site_id, *, probing, sensitive, now):
        evidence = self._cross_site.get(source)
        if evidence is None:
            if len(self._cross_site) >= self._max_cross_site:
                # Drop the least *recently used* entry. Insertion order alone
                # would be first-seen order, which is the wrong thing to evict:
                # an attacker rotating through more than `_max_cross_site`
                # addresses would push out the evidence for the source that is
                # actively probing, which is precisely the entry worth keeping.
                # `WebSourceTable` avoids this the same way, and for the same
                # reason.
                self._cross_site.pop(next(iter(self._cross_site)), None)
                self.metrics['cross_site_evictions_total'] += 1
            evidence = CrossSiteEvidence()
        else:
            # Re-insert so that dictionary order really is least-recently-used.
            self._cross_site.pop(source)
        self._cross_site[source] = evidence
        evidence.record(site_id, probing=probing, sensitive=sensitive, now=now)

    def cross_site(self, source):
        return self._cross_site.get(source) or CrossSiteEvidence()

    # --- action scope ----------------------------------------------------

    def action_scope(self, context, action):
        """What an action reaches, and whether this site may ask for it.

        Returns `(scope, allowed, reason)`. A site that has not been configured
        to allow host-wide blocking gets its TEMP_BLOCK reduced to a site-local
        action, with the reason recorded — because the alternative is site B's
        visitors losing access over something only site A saw.
        """
        if action != 'TEMP_BLOCK':
            return SITE_WEB_ACTION, True, 'this action affects only this site'
        if not context.settings.allow_host_network_block:
            return (SITE_WEB_ACTION, False,
                    f'a network block would remove this source from every site on '
                    f'this server; {context.site_id} is not configured to ask for '
                    'one, so the action stays site-local')
        return (NETWORK_HOST_BLOCK, True,
                'this is a host-wide network block: it removes this source from '
                'every site on this server, not only this one')

    # --- reporting -------------------------------------------------------

    def health(self):
        return {'site_engine_schema_version': SITE_ENGINE_SCHEMA_VERSION,
                'sites': len(self.profiles),
                'site_ids': sorted(self.profiles),
                'resolver': self.resolver.health(),
                'state': self.state.stats(),
                'baselines': {site: baseline.state
                              for site, baseline in self.baselines.items()},
                'cross_site_sources': len(self._cross_site),
                'note': ('web behaviour is per site; network-layer evidence is '
                         'about the host and is shared on purpose')}

    def site_status(self, site_id):
        profile = self.profiles.get(site_id)
        if profile is None:
            return {'site_id': site_id, 'configured': False}
        document = {'site_id': site_id, 'configured': True,
                    'profile': profile.explain(),
                    'state': self.state.site_stats(site_id),
                    'baseline': self.baseline(site_id).explain()}
        if self.models is not None:
            document['model'] = self.models.resolve(site_id).explain()
        return document


def from_config(config, *, model_registry=None):
    """Build an engine from configuration, validating the whole thing (§79).

    Raises on a bad configuration rather than starting partly configured. Some
    sites protected under new rules and others under old ones, with nothing that
    says which, is the worst outcome available here.
    """
    settings = getattr(config, 'sites', None)
    if settings is None or not settings.enabled:
        return None
    profiles = build_all(settings.profiles, max_sites=settings.max_sites)
    return SiteEngine(profiles,
                      default_site=settings.default_site,
                      max_sites=settings.max_sites,
                      max_sources_global=settings.max_sources_global,
                      max_sources_per_site=settings.max_sources_per_site,
                      reserved_per_site=settings.reserved_sources_per_site,
                      model_registry=model_registry)
