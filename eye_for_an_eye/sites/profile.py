"""What one site is, and how its settings are decided.

A site's settings come from three layers, in this order:

    global defaults  →  profile template  →  site override

Each layer may narrow or adjust what the one before it set. The reason for the
middle layer is that most operators are not tuning thresholds from first
principles — they are saying "this one is an API" and expecting sensible things
to follow. A template turns that sentence into settings.

## The order that matters more than the inheritance

There is a second ordering, and it is the one that keeps a badly configured site
from becoming everybody's problem:

    GlobalSafetyPolicy  →  SitePolicy  →  Decision

A site override can raise its own thresholds, switch its own challenge off, or
ask for shorter retention. It **cannot** reach past the global safety limits:
memory bounds, protected networks, firewall ownership, or process limits. Those
are properties of the machine, not of a website, and a website does not get a
vote on them.

Every field on a `SiteProfile` is therefore about that site's own behaviour. The
global limits deliberately are not represented here at all — the safest way to
prevent a site from overriding them is to give it nothing to override.

## Profile types are configuration, never labels

`WEBSITE`, `API`, `ADMIN` are starting points an operator picks. They say what
kind of traffic to expect, which changes what counts as unusual. They are never
a training label and never an input to a model: "requests to the admin site are
malicious" is not a fact, and a model that learned it would have learned the
deployment's shape rather than anything about behaviour.
"""
from dataclasses import dataclass, field, replace

from .identity import RESERVED_SITE_IDS, SiteResolverError, normalise_host, normalise_site_id

SITE_PROFILE_SCHEMA_VERSION = 1

#: Profile types. Starting configurations, not ML labels, not a claim about how
#: dangerous a site is.
WEBSITE = 'website'
API = 'api'
ADMIN = 'admin'
MIXED = 'mixed'
CUSTOM = 'custom'
PROFILE_TYPES = (WEBSITE, API, ADMIN, MIXED, CUSTOM)


class SiteProfileError(ValueError):
    """A site's configuration cannot be used."""


@dataclass(frozen=True)
class SiteSettings:
    """The behaviour settings one site runs with. Frozen once built.

    Frozen because a decision records which settings produced it. A mutable
    settings object means an operator reading a decision record from an hour ago
    sees today's thresholds, and quietly draws the wrong conclusion about why
    something happened.
    """

    # --- what counts as busy here -------------------------------------
    #: Requests per minute from one source that this site considers ordinary.
    #: An API doing 500/min is working; an admin panel doing 500/min is not.
    expected_requests_per_minute: float = 240.0
    #: Distinct paths in a minute before breadth starts to look like searching.
    expected_unique_paths: float = 40.0
    #: Share of responses that are unsuccessful in ordinary use. A site serving
    #: a single-page app with client-side routing legitimately 404s more.
    expected_error_ratio: float = 0.10

    # --- the ladder ----------------------------------------------------
    watch_threshold: float = 0.40
    challenge_threshold: float = 0.45
    rate_limit_threshold: float = 0.70
    block_threshold: float = 0.88
    #: Below this many requests, nothing stronger than WATCH is available.
    minimum_requests_for_action: int = 20
    minimum_quality: float = 0.5

    # --- what this site is allowed to do -------------------------------
    #: Shadow by default, for every site, always. A new site never arrives
    #: enforcing.
    mode: str = 'shadow'
    challenge_enabled: bool = False
    rate_limit_enabled: bool = False
    #: Whether web evidence from this site may contribute to a host-wide network
    #: block. Off by default: a block reaches every site on the machine, so one
    #: site asking for one is a decision about all of them.
    allow_host_network_block: bool = False

    # --- routes and clients --------------------------------------------
    api_path_prefixes: tuple = ()
    no_challenge_path_prefixes: tuple = ()
    expected_methods: tuple = ('GET', 'HEAD', 'POST')
    #: Sources trusted for *this* site only. Never removes a global protection.
    allowlist: tuple = ()

    # --- housekeeping ---------------------------------------------------
    retention_days: int = 7
    collect_dataset: bool = False

    def explain(self):
        return {'expected_requests_per_minute': self.expected_requests_per_minute,
                'expected_unique_paths': self.expected_unique_paths,
                'expected_error_ratio': self.expected_error_ratio,
                'thresholds': {'watch': self.watch_threshold,
                               'challenge': self.challenge_threshold,
                               'rate_limit': self.rate_limit_threshold,
                               'block': self.block_threshold},
                'mode': self.mode,
                'challenge_enabled': self.challenge_enabled,
                'rate_limit_enabled': self.rate_limit_enabled,
                'allow_host_network_block': self.allow_host_network_block,
                'retention_days': self.retention_days}


#: Profile templates (§43). Starter configurations, documented as such. They are
#: not guaranteed-optimal security settings, and the numbers in them are
#: reasoned rather than calibrated — no traffic study stands behind them.
TEMPLATES = {
    # An ordinary website: browsers, static files, crawlers, sessions. Broad
    # path variety is normal here, so breadth alone means less than elsewhere.
    WEBSITE: {'expected_requests_per_minute': 240.0,
              'expected_unique_paths': 40.0,
              'expected_error_ratio': 0.10,
              'challenge_enabled': True,
              'expected_methods': ('GET', 'HEAD', 'POST')},

    # Machine clients: high rate, few endpoints, no cookies, no browser. A
    # browser challenge cannot be answered here, so it is off — and rate is a
    # weak signal because high rate is the normal case.
    API: {'expected_requests_per_minute': 1200.0,
          'expected_unique_paths': 12.0,
          'expected_error_ratio': 0.05,
          'challenge_enabled': False,
          'expected_methods': ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'),
          'api_path_prefixes': ('/',)},

    # Small, quiet, and sensitive. Path breadth and authentication failures mean
    # much more here than on a public site, so the thresholds sit lower — but
    # the mode is still shadow, because a locked-out administrator is a serious
    # outage of its own.
    ADMIN: {'expected_requests_per_minute': 60.0,
            'expected_unique_paths': 10.0,
            'expected_error_ratio': 0.02,
            'watch_threshold': 0.30,
            'challenge_threshold': 0.38,
            'rate_limit_threshold': 0.60,
            'block_threshold': 0.85,
            'challenge_enabled': True,
            'expected_methods': ('GET', 'HEAD', 'POST')},

    # A site doing several of the above. Deliberately the least opinionated
    # template: when a site is many things at once, tight thresholds are wrong
    # for some part of it.
    MIXED: {'expected_requests_per_minute': 600.0,
            'expected_unique_paths': 60.0,
            'expected_error_ratio': 0.12,
            'challenge_enabled': True,
            'expected_methods': ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE')},

    # Nothing assumed. The operator sets what they want; everything else stays
    # at the conservative global default.
    CUSTOM: {},
}

#: Site overrides may set these. Anything absent from this set is either a
#: global safety limit or not a per-site concept, and offering it here would
#: imply a site can change it.
OVERRIDABLE = frozenset(SiteSettings.__dataclass_fields__)

#: Bounds every site's settings must satisfy, whatever a template or an override
#: asks for. These are not style preferences: a threshold of zero would block
#: every visitor, and unbounded retention is an unbounded disk.
BOUNDS = {
    'expected_requests_per_minute': (1.0, 100_000.0),
    'expected_unique_paths': (1.0, 10_000.0),
    'expected_error_ratio': (0.0, 1.0),
    'watch_threshold': (0.05, 1.0),
    'challenge_threshold': (0.05, 1.0),
    'rate_limit_threshold': (0.05, 1.0),
    'block_threshold': (0.05, 1.0),
    'minimum_requests_for_action': (1, 100_000),
    'minimum_quality': (0.0, 1.0),
    'retention_days': (1, 365),
}

#: A site may not name more route prefixes than this, and none may be longer
#: than `MAX_PREFIX_CHARS` (§49). A pathological route configuration is a slow
#: request path for every request the site serves.
MAX_ROUTE_PREFIXES = 64
MAX_PREFIX_CHARS = 200
MAX_ALLOWLIST_ENTRIES = 64
MAX_METHODS = 16


@dataclass(frozen=True)
class SiteProfile:
    """One configured site: who it is, and how it behaves."""

    site_id: str
    profile_type: str = WEBSITE
    enabled: bool = True
    domains: tuple = ()
    settings: SiteSettings = field(default_factory=SiteSettings)
    #: Proxies trusted for this site. Empty means the global list applies.
    trusted_proxies: tuple = ()
    #: Which model this site should use. Empty means the global base model,
    #: which is the right default: see MULTI_SITE_MODELS.md on why one validated
    #: base model beats several weak site-specific ones.
    model_scope: str = ''

    @property
    def challenge_site_id(self):
        """The cryptographic scope for this site's challenge tokens."""
        return self.site_id

    def explain(self):
        return {'site_profile_schema_version': SITE_PROFILE_SCHEMA_VERSION,
                'site_id': self.site_id, 'profile_type': self.profile_type,
                'enabled': self.enabled, 'domains': list(self.domains),
                'model_scope': self.model_scope or 'global',
                'trusted_proxies': list(self.trusted_proxies),
                'settings': self.settings.explain(),
                'note': ('profile_type is a starting configuration chosen by an '
                         'operator; it is never a label and never a model input')}


def _bounded(name, value):
    low, high = BOUNDS[name]
    number = type(low)(value)
    if not low <= number <= high:
        raise SiteProfileError(
            f'{name} must be between {low} and {high}, not {number}')
    return number


def _prefixes(name, values):
    cleaned = []
    for raw in values or ():
        text = str(raw).strip()
        if not text.startswith('/'):
            raise SiteProfileError(f'{name}: {text!r} must start with "/"')
        if len(text) > MAX_PREFIX_CHARS:
            raise SiteProfileError(f'{name}: {text[:30]!r}... is too long')
        cleaned.append(text)
    if len(cleaned) > MAX_ROUTE_PREFIXES:
        raise SiteProfileError(
            f'{name}: {len(cleaned)} prefixes; the limit is {MAX_ROUTE_PREFIXES}')
    return tuple(cleaned)


def build_settings(profile_type, override=None, *, base=None):
    """Global defaults, then the profile template, then the site's own changes.

    Refuses an unknown key rather than ignoring it. A typo in a threshold name
    that is silently discarded leaves an operator believing they tightened a
    site when they did not, and nothing in the running system contradicts them.
    """
    if profile_type not in TEMPLATES:
        raise SiteProfileError(
            f'unknown profile type {profile_type!r}; use one of '
            f'{", ".join(PROFILE_TYPES)}')

    settings = base or SiteSettings()
    merged = dict(TEMPLATES[profile_type])
    for key, value in (override or {}).items():
        if key not in OVERRIDABLE:
            raise SiteProfileError(
                f'{key!r} is not a per-site setting; a site cannot change global '
                'safety limits, and a misspelled setting would be ignored '
                'silently otherwise')
        merged[key] = value

    for key, value in list(merged.items()):
        if key in BOUNDS:
            merged[key] = _bounded(key, value)
        elif key in ('api_path_prefixes', 'no_challenge_path_prefixes'):
            merged[key] = _prefixes(key, value)
        elif key == 'expected_methods':
            methods = tuple(str(item).upper()[:16] for item in value or ())
            if len(methods) > MAX_METHODS:
                raise SiteProfileError('too many expected methods')
            merged[key] = methods
        elif key == 'allowlist':
            entries = tuple(str(item).strip() for item in value or () if str(item).strip())
            if len(entries) > MAX_ALLOWLIST_ENTRIES:
                raise SiteProfileError(
                    f'allowlist has {len(entries)} entries; the limit is '
                    f'{MAX_ALLOWLIST_ENTRIES}')
            merged[key] = entries
        elif key in ('challenge_enabled', 'rate_limit_enabled', 'collect_dataset',
                     'allow_host_network_block'):
            merged[key] = bool(value)
        elif key == 'mode':
            if value not in ('shadow', 'enforce'):
                raise SiteProfileError(f'unknown site mode {value!r}')

    settings = replace(settings, **merged)
    _check_ladder(settings)
    return settings


def _check_ladder(settings):
    """The rungs must be in order, or the ladder is not a ladder.

    Out-of-order thresholds do not fail loudly at runtime; they quietly make one
    rung unreachable. A site whose challenge threshold sits above its rate-limit
    threshold simply never challenges anybody, and nothing says so.
    """
    ordered = [('watch', settings.watch_threshold),
               ('challenge', settings.challenge_threshold),
               ('rate_limit', settings.rate_limit_threshold),
               ('block', settings.block_threshold)]
    for (lower_name, lower), (upper_name, upper) in zip(ordered, ordered[1:]):
        if lower >= upper:
            raise SiteProfileError(
                f'{lower_name} threshold ({lower}) must be below the {upper_name} '
                f'threshold ({upper}); otherwise the {upper_name} rung is '
                'unreachable and nothing would say so')


def build_profile(site_id, spec=None):
    """One site, from its configuration. Raises rather than guessing."""
    spec = dict(spec or {})
    cleaned_id = normalise_site_id(site_id)
    if not cleaned_id:
        raise SiteProfileError(
            f'{site_id!r} is not a usable site name; use letters, digits, dot, '
            'dash or underscore')
    if cleaned_id in RESERVED_SITE_IDS:
        raise SiteProfileError(f'{cleaned_id!r} is a reserved site name')

    profile_type = str(spec.get('profile', spec.get('profile_type', WEBSITE))).lower()
    domains = []
    for raw in spec.get('domains', ()) or ():
        domain = normalise_host(raw)
        if not domain:
            raise SiteProfileError(
                f'site {cleaned_id!r}: {raw!r} is not a usable domain')
        if domain not in domains:
            domains.append(domain)

    known = {'profile', 'profile_type', 'domains', 'enabled', 'trusted_proxies',
             'model_scope', 'settings'}
    unexpected = set(spec) - known - OVERRIDABLE
    if unexpected:
        raise SiteProfileError(
            f'site {cleaned_id!r}: unknown settings {sorted(unexpected)}')

    override = dict(spec.get('settings') or {})
    override.update({key: spec[key] for key in spec if key in OVERRIDABLE})

    return SiteProfile(
        site_id=cleaned_id,
        profile_type=profile_type,
        enabled=bool(spec.get('enabled', True)),
        domains=tuple(domains),
        settings=build_settings(profile_type, override),
        trusted_proxies=tuple(str(item) for item in spec.get('trusted_proxies', ()) or ()),
        model_scope=normalise_site_id(spec.get('model_scope', '')))


def build_all(sites, *, max_sites=64):
    """Every configured site, or nothing.

    Whole-configuration validation, on purpose (§79). Partly applying a security
    configuration is the worst outcome available: some sites protected under new
    rules, others under old ones, and no single place that says which is which.
    A configuration that cannot be fully validated should stop startup with a
    diagnostic naming the site at fault.
    """
    profiles = {}
    for raw_id, spec in (sites or {}).items():
        profile = build_profile(raw_id, spec)
        if profile.site_id in profiles:
            raise SiteProfileError(f'site {profile.site_id!r} is configured twice')
        profiles[profile.site_id] = profile

    if len(profiles) > max_sites:
        raise SiteProfileError(
            f'{len(profiles)} sites are configured; the limit is {max_sites}. '
            'This bound exists so that per-site state and metrics stay bounded')

    seen = {}
    for profile in profiles.values():
        for domain in profile.domains:
            owner = seen.get(domain)
            if owner is not None:
                raise SiteResolverError(
                    f'domain {domain!r} is mapped to both {owner!r} and '
                    f'{profile.site_id!r}; one domain belongs to one site')
            seen[domain] = profile.site_id
    return profiles
