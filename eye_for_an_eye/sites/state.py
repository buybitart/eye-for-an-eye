"""Per-site web state, with budgets that keep one busy site from eating the rest.

Two requirements pull against each other here.

**Isolation.** A source scanning site A must not raise site B's path-enumeration
score. Web counters are per site, full stop.

**Bounded memory.** Multi-site support must not multiply memory by the number of
sites. One global ceiling, shared.

Sharing a fixed pool between sites is where the interesting failure lives.

## Why global least-recently-used eviction is unfair

The obvious design is one pool with LRU eviction across everything. It is
bounded, and it is wrong.

Consider a busy site A seeing thousands of fresh addresses a minute, and a quiet
site B seeing forty a day. Under global LRU, site A's churn is always the most
recent activity, so the least-recently-used entries are almost always site B's.
Site A evicts site B continuously. Site B ends up with no usable state at all,
and the only symptom is that site B never quite accumulates enough evidence to
decide anything — which reads as "the tool does not work for my small site"
rather than as a resource bug.

So eviction is **fair-share** instead:

* every site has a reserved floor it can always use, and a site at or below its
  floor is never evicted from to make room for another site;
* when the global pool is full, the entries taken are from whichever site is
  furthest **over** its fair share — the greedy one pays for its own growth;
* within a site, eviction stays least-recently-used, which is the right policy
  there for the reason it always was: it makes a flood of fresh addresses unable
  to push out a source that is actually being watched any faster than time
  already would.

The floors are not preallocated. An idle site holds no memory; its floor is a
claim it can make when it needs it, not a reservation sitting empty.
"""
from collections import Counter

from ..web.state import MAX_DISTINCT, SOURCE_TTL_SECONDS, WebSourceTable
from .identity import UNKNOWN_SITE

SITE_STATE_SCHEMA_VERSION = 1

#: Sources across every site. The one number that bounds this subsystem.
MAX_SOURCES_GLOBAL = 8192

#: What a site can always claim, however busy its neighbours are.
DEFAULT_RESERVED_PER_SITE = 64

#: The most any single site may hold, however quiet its neighbours are. Without
#: this, one site can occupy the whole pool while the others are idle and then
#: refuse to give it back quickly when they wake up.
DEFAULT_MAX_PER_SITE = 2048


class SiteStateError(ValueError):
    """The state registry cannot be built with these limits."""


class SiteStateRegistry:
    """One bounded `WebSourceTable` per site, under one global ceiling.

    The set of sites is fixed at construction. There is no path by which
    observing traffic adds a site: an unrecognised SiteID folds into
    `UNKNOWN_SITE`, so a `Host:` header loop produces one bucket rather than one
    table per invented host.
    """

    def __init__(self, sites=(), *, max_sources_global=MAX_SOURCES_GLOBAL,
                 max_sources_per_site=DEFAULT_MAX_PER_SITE,
                 reserved_per_site=DEFAULT_RESERVED_PER_SITE,
                 ttl_seconds=SOURCE_TTL_SECONDS, max_distinct_paths=MAX_DISTINCT):
        self.max_sources_global = max(1, int(max_sources_global))
        self.max_sources_per_site = max(1, int(max_sources_per_site))
        self.reserved_per_site = max(0, int(reserved_per_site))
        self.ttl_seconds = max(1.0, float(ttl_seconds))
        self.max_distinct_paths = max(1, int(max_distinct_paths))

        # UNKNOWN_SITE always exists. Traffic for an unconfigured host has to go
        # somewhere bounded, and inventing the bucket lazily would mean the
        # first hostile request creates state.
        known = [str(site) for site in sites if str(site)]
        self.sites = tuple(dict.fromkeys([*known, UNKNOWN_SITE]))

        if self.reserved_per_site * len(self.sites) > self.max_sources_global:
            raise SiteStateError(
                f'{len(self.sites)} sites reserving {self.reserved_per_site} sources '
                f'each exceeds the global limit of {self.max_sources_global}; '
                'lower the reservation or raise the global limit')

        self._tables = {site: WebSourceTable(
            max_sources=min(self.max_sources_per_site, self.max_sources_global),
            ttl_seconds=self.ttl_seconds,
            max_distinct_paths=self.max_distinct_paths) for site in self.sites}
        self.metrics = Counter()

    # --- lookup ---------------------------------------------------------

    def site_for(self, site_id):
        """The SiteID this registry will actually use. Never creates a site."""
        return site_id if site_id in self._tables else UNKNOWN_SITE

    def table(self, site_id):
        return self._tables[self.site_for(site_id)]

    def get(self, site_id, key):
        """One source's state *on one site*. Never another site's."""
        return self.table(site_id).get(key)

    def __len__(self):
        return sum(len(table) for table in self._tables.values())

    def __contains__(self, site_id):
        return site_id in self._tables

    # --- fair share -----------------------------------------------------

    def fair_share(self):
        """How many sources each site could hold if the pool were split evenly.

        Used only to decide who pays when the pool is full. It is not a cap: a
        site is welcome to exceed it while others are idle.
        """
        return max(1, self.max_sources_global // max(1, len(self._tables)))

    def _greediest(self, exclude):
        """The site furthest over its fair share, or None if nobody is over.

        A site at or below its reserved floor is never chosen, whatever the
        arithmetic says. That floor is the whole guarantee a small site has.
        """
        share = self.fair_share()
        worst, worst_excess = None, 0
        for site, table in self._tables.items():
            if site == exclude:
                continue
            held = len(table)
            if held <= self.reserved_per_site:
                continue
            excess = held - share
            if excess > worst_excess:
                worst, worst_excess = site, excess
        return worst

    def _make_room(self, site_id, now):
        """Free one slot in the global pool, charged to whoever is greediest."""
        if len(self) < self.max_sources_global:
            return True

        for table in self._tables.values():
            table.expire(now)
        if len(self) < self.max_sources_global:
            return True

        victim = self._greediest(exclude=None)
        if victim is not None and self._tables[victim].evict_oldest():
            self.metrics['site_state_evictions_total'] += 1
            self.metrics[f'evicted_from:{victim}'] += 1
            return True

        # Nobody is over their fair share and the pool is still full: every site
        # is within its rights, and the global ceiling is not negotiable. The
        # arriving site pays for its own arrival, which leaves every other site
        # exactly as it was — the cost lands on the site that wanted the room.
        self.metrics['site_state_pressure_total'] += 1
        if self._tables[site_id].evict_oldest():
            self.metrics[f'evicted_from:{site_id}'] += 1
            return True
        return False

    # --- observing -------------------------------------------------------

    def observe(self, site_id, event, now):
        """Record one request against one source *on one site*."""
        site = self.site_for(site_id)
        table = self._tables[site]
        if table.get(event.client or event.peer) is None:
            # A new source needs a slot in the global pool. If none can be
            # freed, this site does not get to grow past the ceiling: the
            # request is still analysed, it simply does not open new state.
            if not self._make_room(site, now):
                self.metrics['site_state_refused_total'] += 1
                return None
        state = table.observe(event, now)
        if state is not None:
            self.metrics[f'events:{site}'] += 1
        return state

    def expire(self, now):
        return sum(table.expire(now) for table in self._tables.values())

    # --- reporting -------------------------------------------------------

    def site_stats(self, site_id):
        site = self.site_for(site_id)
        table = self._tables[site]
        return {'site_id': site, 'sources': len(table),
                'max_sources': table.max_sources,
                'reserved': self.reserved_per_site,
                'fair_share': self.fair_share(),
                'evictions': table.evictions, 'expired': table.expired,
                'events': self.metrics.get(f'events:{site}', 0)}

    def stats(self):
        return {'site_state_schema_version': SITE_STATE_SCHEMA_VERSION,
                'sites': len(self._tables),
                'sources': len(self),
                'max_sources_global': self.max_sources_global,
                'max_sources_per_site': self.max_sources_per_site,
                'reserved_per_site': self.reserved_per_site,
                'fair_share': self.fair_share(),
                'cross_site_evictions': self.metrics.get('site_state_evictions_total', 0),
                'pressure_events': self.metrics.get('site_state_pressure_total', 0),
                'per_site': {site: self.site_stats(site) for site in self._tables},
                'bounded': ('one global ceiling shared between sites, a reserved '
                            'floor each, and eviction charged to whichever site is '
                            'furthest over its fair share')}
