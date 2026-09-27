"""What a mistake costs, per site, and the cutoff that follows from it.

There is no universal decision threshold, and 0.5 is not one. It is the number
people reach for when they have not asked what a mistake costs — and in security
the two mistakes are not comparable, not even close.

Blocking somebody who did nothing wrong denies a real person a real service. On a
public site that person cannot tell you, cannot appeal, and in most cases will
not come back. Allowing a scanner to continue means it continues — against a
system that is already rate-limiting it, already challenging it, and already
watching. Those are different sizes of wrong, and the cutoff has to follow from
that rather than from a round number.

So the costs are explicit, per profile, and owned by the operator:

    C_FP    blocking a benign source
    C_FN    allowing a malicious-automation source for one block interval

**Both are relative, unitless weights, not money.** §17 is explicit that monetary
values must not be inferred, and inventing them would give a false precision to
what is a judgement about a particular site. `C_FN = 1.0` is the reference unit
throughout: every `C_FP` reads as "this many times worse than letting one
automated source carry on for one block interval".

The cutoff that falls out of the simplest cost matrix is

    p* = C_FP / (C_FP + C_FN)

and it is deliberately high everywhere. On a public website it is 0.976. That is
not timidity — it is what the arithmetic says when a false block is forty times
worse than a false allow, and the rarity of the positive class makes it more
important rather than less.

**This is the floor, not the decision.** Passing `p*` makes a block *arithmetically*
preferable. Everything in `uncertainty.py`, `evidence.py` and `PolicyGuard` still
applies afterwards, and each of them can refuse.
"""
from dataclasses import asdict, dataclass, field, replace
import hashlib
import json

#: Bumped when the shape changes. Values are caught by the digest instead.
COST_POLICY_VERSION = 'cost-policy-v1'


class CostError(ValueError):
    """A cost policy that does not make sense."""


@dataclass(frozen=True, slots=True)
class CostProfile:
    """One site's or route's view of what its two possible mistakes cost.

    `false_block` and `false_allow` are the entries of the cost matrix that are
    not zero:

                        actual benign       actual malicious
        ALLOW                 0                 false_allow
        TEMP_BLOCK      false_block                  0

    The intermediate actions have their own costs because they are not free
    (§134): a challenge asks a real person to wait, and a rate limit slows
    somebody down. An expected-loss calculation that treated them as costless
    would reach for them constantly.
    """

    name: str
    description: str
    false_block: float
    false_allow: float = 1.0
    challenge: float = 0.05
    rate_limit: float = 0.15
    #: Some profiles must never produce an autonomous network block at all,
    #: whatever the arithmetic says (§136). A payment or webhook route is the
    #: clearest case: the cost of breaking an integration is not a number you
    #: trade against reconnaissance.
    network_block_permitted: bool = True

    def __post_init__(self):
        if self.false_block <= 0 or self.false_allow <= 0:
            raise CostError(f'{self.name}: costs must be positive')
        if not 0 <= self.challenge <= self.false_block:
            raise CostError(f'{self.name}: a challenge cannot cost more than a block')
        if not 0 <= self.rate_limit <= self.false_block:
            raise CostError(f'{self.name}: a rate limit cannot cost more than a block')

    @property
    def threshold(self):
        """`p*`, the malicious probability at which blocking becomes preferable.

        The classical cost-sensitive cutoff. It is a floor and not a decision:
        reaching it means the arithmetic no longer favours allowing, which is a
        necessary condition for a block and nowhere near a sufficient one.
        """
        return self.false_block / (self.false_block + self.false_allow)

    def explain(self):
        body = asdict(self)
        body['threshold'] = round(self.threshold, 6)
        return body


#: The shipped profiles. Every number is a judgement about a kind of site, made
#: without deployment data, and an operator who changes one is exercising their
#: own judgement rather than correcting an error.
PROFILES = {
    'public_website': CostProfile(
        name='public_website',
        description=('A site with real human readers. A false block denies a '
                     'person a service they came for, silently, with no way to '
                     'appeal — and lands hardest on unusual networks and '
                     'assistive clients.'),
        false_block=40.0, false_allow=1.0),
    'api': CostProfile(
        name='api',
        description=('Programmatic clients. A false block breaks an integration '
                     'rather than inconveniencing a person, and the failure '
                     'surfaces somewhere far from here. Browser challenges are '
                     'not available, so there is no softer action to fall back '
                     'to.'),
        false_block=80.0, false_allow=1.0, challenge=1.0),
    'payment_webhook': CostProfile(
        name='payment_webhook',
        description=('Payment callbacks, health checks and anything whose '
                     'failure is an incident. Autonomous network blocking is not '
                     'appropriate here at any probability; rate limiting and '
                     'observation remain.'),
        false_block=500.0, false_allow=1.0, challenge=5.0,
        network_block_permitted=False),
    'admin': CostProfile(
        name='admin',
        description=('An administrative interface with a small, known set of '
                     'legitimate clients. A false block is recoverable by '
                     'someone who has other access; automation here is rarely '
                     'legitimate.'),
        false_block=8.0, false_allow=1.0),
    'honeypot': CostProfile(
        name='honeypot',
        description=('A deception service with no legitimate public clients, so '
                     'a false block costs almost nothing. Still no hack-back, '
                     'still temporary, still bounded.'),
        false_block=2.0, false_allow=1.0),
}

DEFAULT_PROFILE = 'public_website'


@dataclass(frozen=True, slots=True)
class CostPolicy:
    """The whole cost model: profiles, scope mapping, and its own digest.

    Nothing learned can write to this. §131 and §196: the cost model is operator
    configuration, and a component that could adjust the price of its own
    mistakes would be grading its own work.
    """

    version: str = COST_POLICY_VERSION
    profiles: dict = field(default_factory=lambda: dict(PROFILES))
    #: scope (`GLOBAL` or `SITE:<id>`) to profile name.
    scope_profiles: dict = field(default_factory=dict)
    default_profile: str = DEFAULT_PROFILE
    #: How much better blocking has to be before it is preferred, as a fraction
    #: of the larger loss (§121). A small advantage is noise; this is what turns
    #: "arithmetically preferable" into "worth acting on".
    decision_margin: float = 0.25
    #: Hysteresis (§122): once a source is blocked, the evidence needed to keep
    #: considering it a candidate falls, so a source near the boundary does not
    #: flap in and out on adjacent requests.
    release_margin: float = 0.10

    def __post_init__(self):
        if self.default_profile not in self.profiles:
            raise CostError(f'default profile {self.default_profile!r} is not defined')
        if not 0 <= self.decision_margin < 1:
            raise CostError('decision_margin must be in [0, 1)')
        if not 0 <= self.release_margin <= self.decision_margin:
            raise CostError('release_margin must not exceed decision_margin; '
                            'hysteresis works in one direction')

    def for_scope(self, scope):
        """The profile that applies to a scope. Never guesses a cheaper one.

        An unmapped scope gets the default, and the default is the most
        protective of the general-purpose profiles rather than the most
        permissive — a site nobody configured is a site nobody thought about.
        """
        name = self.scope_profiles.get(str(scope or ''), self.default_profile)
        profile = self.profiles.get(name)
        if profile is None:
            raise CostError(f'scope {scope!r} maps to unknown cost profile {name!r}')
        return profile

    @property
    def digest(self):
        """A stable hash, so a decision record can name the costs it used.

        Changing a cost changes the digest, which makes a decision taken under
        the old numbers identifiable afterwards. "Why was this blocked" is asked
        weeks later, and the answer depends on what the costs were at the time.
        """
        return hashlib.sha256(
            json.dumps(self.explain(), sort_keys=True, separators=(',', ':'))
            .encode('utf-8')).hexdigest()

    def with_scope(self, scope, profile_name):
        mapping = dict(self.scope_profiles)
        mapping[str(scope)] = profile_name
        return replace(self, scope_profiles=mapping)

    def explain(self):
        return {'cost_policy_version': self.version,
                'default_profile': self.default_profile,
                'decision_margin': self.decision_margin,
                'release_margin': self.release_margin,
                'scope_profiles': dict(self.scope_profiles),
                'profiles': {name: profile.explain()
                             for name, profile in sorted(self.profiles.items())},
                'note': ('costs are relative weights, not money; C_FN = 1.0 is '
                         'the reference unit and no value here is derived from '
                         'measurement')}

    def summary(self):
        return {'cost_policy_version': self.version,
                'cost_policy_digest': self.digest[:16],
                'default_profile': self.default_profile,
                'thresholds': {name: round(profile.threshold, 4)
                               for name, profile in sorted(self.profiles.items())}}


def from_config(config):
    """Build a cost policy from configuration, or the shipped default."""
    settings = getattr(config, 'autonomy', None)
    if settings is None:
        return CostPolicy()
    mapping = {}
    for scope, name in (getattr(settings, 'cost_profiles', {}) or {}).items():
        if name not in PROFILES:
            raise CostError(f'{scope}: unknown cost profile {name!r}; known '
                            f'profiles are {", ".join(sorted(PROFILES))}')
        mapping[str(scope)] = str(name)
    default = getattr(settings, 'default_cost_profile', '') or DEFAULT_PROFILE
    if default not in PROFILES:
        raise CostError(f'unknown default cost profile {default!r}')
    return CostPolicy(scope_profiles=mapping, default_profile=default,
                      decision_margin=float(getattr(settings, 'decision_margin', 0.25)),
                      release_margin=float(getattr(settings, 'release_margin', 0.10)))
