"""Which cost profile prices this decision. P15.5R §11, §12, §13, §15.

P15.5 found that every decision in every locked benchmark since P15.1 had been
priced at `public_website`'s cutoff, because the replay harness passed the
literal string `GLOBAL` as the scope and an unmapped scope resolves to the
default profile. The per-profile tables in those reports were outcomes *grouped*
by profile, not outcomes *decided* per profile.

§1 of this cycle found the runtime counterpart, which is worse: the running
sensor resolves no scope at all. It has no `site_id`, no `SiteProfile` and no
`CostProfile`, so there is no per-profile cost to get wrong.

This module is the missing step. It is deliberately small, and deliberately
refuses to be clever.

### What a running sensor actually knows

A packet carries no `Host` header. `SiteResolver` resolves a site from one, so
at the network layer there is no site to resolve — and pretending otherwise
would be inventing evidence. What a network window does carry is the set of
destination ports the source touched, and the deployment's own declaration of
what this machine is.

So three kinds of scope, in the vocabulary `CostPolicy.scope_profiles` already
uses, resolved against the operator's existing `[autonomy.cost_profiles]` table
with no new configuration key:

    SITE:<id>              when a site is known (the web ingestion path)
    SERVICE:<port>/<proto> a destination port the operator has priced
    GLOBAL                 the deployment's own answer, always a candidate

### Two rules, for two different questions

**A specific scope beats the fallback.** `GLOBAL` answers "what is this machine,
when nothing more precise is known". A mapped `SITE:` or `SERVICE:` scope is the
operator saying something more precise, so it takes precedence rather than
competing. Letting `GLOBAL` win whenever it happened to be more protective would
make `[autonomy.cost_profiles]` quietly useless for every profile cheaper than
the default — configuration that looks like it works and does not.

**Among specific scopes, the most protective wins.** A window that touched port
443 and port 22 belongs to two scopes at once, and that ambiguity was created by
the source. Picking the cheaper one would let a scanner buy a lower cutoff by
also touching something cheap, which is a way of asking to be gamed. So the
highest cutoff wins, and a profile that forbids network blocking at all wins
outright (§14 — `payment_webhook` is not blocked because something else in the
window looked ordinary).

The two together leave nothing for a source to choose. It cannot evict a scope
(see `services_for`), and every scope it adds can only move the answer towards
the more protective of the ones that apply. The cheapest pricing it can reach is
the service the operator deliberately priced cheaply, which is what pricing it
meant.

### What this does not do

It does not put `site_group` or `profile_type` into the feature vector. §16, and
P15.4 before it: those are policy scope, and a model that learned "admin traffic
is malicious" would have learned the deployment's shape. Nothing here is passed
to `FeatureTransformer`, and `tests/test_p15_5r_scope.py` asserts it.
"""
from dataclasses import dataclass, field

SCOPE_RESOLVER_VERSION = 'autonomy-scope-resolver-v1'

GLOBAL = 'GLOBAL'
SITE_PREFIX = 'SITE:'
SERVICE_PREFIX = 'SERVICE:'

#: A window touching more destination ports than this is not "traffic to one
#: service" by any reading, and enumerating its scopes would only produce the
#: global fallback more slowly. Bounded because the scope set is attacker-
#: influenced: a source that touches 60000 ports must not be able to make this
#: build 60000 scope strings.
MAX_SERVICE_SCOPES = 16


def site_scope(site_id):
    return f'{SITE_PREFIX}{site_id}' if site_id else ''


def service_scope(port, transport='tcp'):
    """The scope string for one destination service.

    Named `SERVICE:<port>/<transport>` rather than `PORT:<port>` because what an
    operator is pricing is the thing listening there, and because a UDP 443 and
    a TCP 443 are not the same service.
    """
    if port is None:
        return ''
    try:
        number = int(port)
    except (TypeError, ValueError):
        return ''
    if not 0 <= number <= 65535:
        return ''
    protocol = str(transport or 'unknown').lower()
    if not protocol.isalnum() or len(protocol) > 8:
        protocol = 'unknown'
    return f'{SERVICE_PREFIX}{number}/{protocol}'


@dataclass(frozen=True, slots=True)
class ScopeResolution:
    """The scope a decision was priced at, and what else was considered."""

    scope: str
    profile: object
    site_id: str = ''
    considered: tuple = field(default_factory=tuple)
    #: True when more than one candidate resolved to a different profile and the
    #: most protective was taken. Worth recording: it is the one case where the
    #: scope in the record is not the only scope that applied.
    ambiguous: bool = False

    def explain(self):
        return {'scope_resolver_version': SCOPE_RESOLVER_VERSION,
                'scope': self.scope, 'site_id': self.site_id,
                'cost_profile': self.profile.name,
                'threshold': round(self.profile.threshold, 6),
                'network_block_permitted': self.profile.network_block_permitted,
                'considered': list(self.considered),
                'ambiguous': self.ambiguous}


class ScopeResolver:
    """Resolve a window's scope against a cost policy. Holds no state.

    Constructed with the policy rather than the config so that a test can price
    the same window under several policies without rebuilding a runtime, and so
    that there is exactly one place — `from_config` in `cost.py` — that turns
    configuration into costs.
    """

    version = SCOPE_RESOLVER_VERSION

    def __init__(self, cost_policy):
        self.cost_policy = cost_policy

    def services_for(self, samples, *, limit=MAX_SERVICE_SCOPES):
        """The service scopes in this window that the operator has priced,
        most protective first.

        Two rules, and both of them exist because the alternative is a cap an
        attacker can aim.

        **Filter before capping.** A ninety-port scan produces ninety distinct
        service scopes. A cap applied to that raw list keeps whichever sixteen
        arrived first, which is ordering the source controls. Only scopes the
        operator has actually priced can affect the decision, and the operator's
        map is bounded by configuration at 256 entries — so filtering against it
        first bounds this list by something the operator chose rather than by
        something the traffic chose.

        **Sort before truncating.** That alone is not enough. An operator who
        prices more than `limit` services is back in the same position: a source
        that touches enough of the cheap ones first pushes the expensive one off
        the end. Since `resolve` takes the most protective candidate, ordering
        by protection makes truncation harmless by construction — everything
        dropped is something that could not have won. The policy no longer
        depends on insertion order at all, which is the property §18 asks for,
        rather than on a limit chosen to be large enough.

        Found by `tests/test_p15_5r_runtime_end_to_end.py`, which priced a
        port-22 scanner at `public_website` because port 22 happened to be the
        twenty-first distinct port in that window.
        """
        mapped = self.cost_policy.scope_profiles
        seen = []
        for sample in samples or ():
            scope = service_scope(getattr(sample, 'port', None),
                                  getattr(sample, 'transport', 'unknown'))
            if scope and scope in mapped and scope not in seen:
                seen.append(scope)
        ordered = sorted(seen, key=self._protection_key)
        return tuple(ordered[:limit])

    def _protection_key(self, scope):
        """Sort key placing the most protective profile first, ties by name.

        Deterministic all the way down: two scopes on the same profile are
        ordered by the scope string, so the same window always produces the
        same list whatever order its packets arrived in.
        """
        profile = self.cost_policy.for_scope(scope)
        return (profile.network_block_permitted, -profile.threshold,
                -profile.false_block, scope)

    def candidates(self, *, site_id='', services=(), declared=''):
        """Every scope string this window could be priced at, `GLOBAL` last.

        Order is significant only for reporting; the choice below is by
        protection, not by position.

        `declared` is a scope the caller already knows by other means — the
        profile a corpus row declares in `training/decision_replay.py`, or a
        scope a future ingestion resolves for itself. It is a candidate like any
        other and wins only if it is the most protective, so a corpus cannot
        talk its way into a cheaper cutoff than the deployment's own.
        """
        scopes = []
        for scope in (str(declared or ''), site_scope(site_id)):
            if scope and scope not in scopes:
                scopes.append(scope)
        for scope in list(services)[:MAX_SERVICE_SCOPES]:
            if scope and scope not in scopes:
                scopes.append(scope)
        scopes.append(GLOBAL)
        return tuple(scopes)

    def resolve(self, *, site_id='', services=(), declared=''):
        """The scope and profile that price this decision.

        Only scopes the operator has actually mapped compete. An unmapped
        `SERVICE:` or `SITE:` scope resolves to the default profile, which is
        already what `GLOBAL` resolves to, so including it would add a candidate
        that can never change the answer and would make the record claim a
        specificity the configuration does not have.
        """
        mapped = self.cost_policy.scope_profiles
        considered = self.candidates(site_id=site_id, services=services,
                                     declared=declared)
        # A specific scope the operator mapped is a more informed statement than
        # the deployment-wide default, so `GLOBAL` is a fallback rather than a
        # competitor. The alternative — letting `GLOBAL` win whenever it is the
        # more protective — makes `[autonomy.cost_profiles]` silently useless
        # for any profile cheaper than the default, which is configuration that
        # appears to work and does not. That is the same class of defect this
        # cycle exists to remove.
        #
        # The adversarial property survives the distinction: a source cannot
        # *evict* a specific scope (see `services_for`), and touching more
        # services can only move the answer to the most protective of the ones
        # that apply. What it can reach cheaply is the service the operator
        # deliberately priced cheaply, which is what pricing it meant.
        specific = [scope for scope in considered
                    if scope != GLOBAL and scope in mapped]
        competing = specific or [GLOBAL]
        chosen = None
        for scope in competing:
            profile = self.cost_policy.for_scope(scope)
            if chosen is None or _more_protective(profile, chosen[1]):
                chosen = (scope, profile)
        scope, profile = chosen
        distinct = {self.cost_policy.for_scope(candidate).name for candidate in competing}
        return ScopeResolution(
            scope=scope, profile=profile,
            site_id=str(site_id or ''),
            considered=considered,
            ambiguous=len(distinct) > 1)


def _more_protective(candidate, incumbent):
    """Is `candidate` the safer profile to price this decision at?

    Refusing network blocking outright beats any cutoff, because it is not a
    number on the same scale — it is the statement that no probability makes a
    block appropriate here (§14).
    """
    if candidate.network_block_permitted != incumbent.network_block_permitted:
        return not candidate.network_block_permitted
    if candidate.threshold != incumbent.threshold:
        return candidate.threshold > incumbent.threshold
    if candidate.false_block != incumbent.false_block:
        return candidate.false_block > incumbent.false_block
    return candidate.name < incumbent.name


def services_in(samples, *, limit=MAX_SERVICE_SCOPES):
    """The service scopes a correlation window touched.

    Reads `Sample.port` and `Sample.transport`, which is what the window holds;
    nothing here reaches for a `Host` header a packet does not have.
    """
    scopes = []
    for sample in samples or ():
        scope = service_scope(getattr(sample, 'port', None),
                              getattr(sample, 'transport', 'unknown'))
        if scope and scope not in scopes:
            scopes.append(scope)
            if len(scopes) >= limit:
                break
    return tuple(scopes)


def resolved_profile_mapping(config):
    """Which cost profile each configured site is actually priced at. P15S §10.

    §10 asks for the resolved mapping to be recorded, and adds the reason:
    *do not let known sites silently fall back to the global default.* That
    fallback is not a malfunction -- `resolve` is explicit that an unmapped
    `SITE:` scope resolves to the default, deliberately, so the record does not
    claim a specificity the configuration does not have. What makes it worth a
    warning is that it looks identical to a site that was priced and happens to
    be priced at the default.

    The difference matters to every per-profile number P15S produces. A site the
    operator believes is an API, resolved at `public_website`, is priced at the
    0.9756 cutoff rather than 0.9877 and reported under the wrong heading in
    §36's breakdown -- and nothing about the output says so.

    The readiness gate already checks that site identifiers normalise uniquely.
    This is the other question, which nothing was asking.

    Nothing here changes a decision. It resolves the same way the pipeline does,
    through the same resolver and the same cost policy, and reports.
    """
    from .cost import from_config as cost_from_config

    sites = getattr(config, 'sites', None)
    policy = cost_from_config(config)
    resolver = ScopeResolver(policy)
    configured = list((getattr(sites, 'profiles', {}) or {})
                      if sites is not None and getattr(sites, 'enabled', False)
                      else [])
    rows = []
    for name in configured:
        resolution = resolver.resolve(site_id=str(name))
        rows.append({
            'site': str(name),
            'scope': resolution.scope,
            'cost_profile': resolution.profile.name,
            'threshold': round(resolution.profile.threshold, 6),
            'network_block_permitted': resolution.profile.network_block_permitted,
            # The one thing this function exists to say.
            'fell_back_to_default': resolution.scope == GLOBAL,
        })
    fallbacks = [row['site'] for row in rows if row['fell_back_to_default']]
    return {
        'scope_resolver_version': SCOPE_RESOLVER_VERSION,
        'multi_site': bool(sites is not None and getattr(sites, 'enabled', False)),
        'default_profile': policy.default_profile,
        'mapped_scopes': dict(policy.scope_profiles),
        'sites': rows,
        'sites_on_the_default': fallbacks,
        'note': ('a site on the default profile is priced at the deployment-wide '
                 'cutoff rather than one chosen for it. That is correct '
                 'behaviour for a site nobody priced, and indistinguishable '
                 'from a site somebody meant to price and did not'),
    }
