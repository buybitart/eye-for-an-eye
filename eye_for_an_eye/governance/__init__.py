"""Local model governance: who may change which model, and on what evidence.

The reason this package exists is one sentence: **auto-promotion is not the
model choosing itself.** It is a deterministic policy accepting a candidate after
it has passed explicit, named, evidence-based gates — and the difference is the
whole design.

A model that could influence its own promotion would be a model that could
gradually widen its own authority, one plausible-looking release at a time. So
the authorities are kept apart, and nothing in this package is reachable from the
classifier:

    TrainingAuthority      may create a candidate, and may do nothing else
    EvaluationAuthority    may measure it
    PromotionAuthority     may choose which validated artifact is ACTIVE
    EnforcementAuthority   decides what an ACTIVE model is allowed to do

`PolicyGuard` remains the last of those, unchanged. Promotion changes which model
*provides evidence*; it never changes what evidence is allowed to cause. A
promoted model cannot add a firewall rule, move a threshold, or alter a challenge
setting, and there is no code path in this package that could.

Three things about the shape of it are worth stating before reading further.

**Every promotion has an explicit scope.** `GLOBAL` or `SITE:<site-id>`, never
ambiguous. Site-scoped promotion is the preferred and safer first target, because
its blast radius is one website; global promotion reaches every site on the
machine and is gated separately and disabled by default.

**Activation is two-phase.** A candidate does not become ACTIVE. It becomes
GUARDED_ACTIVE, contributing to decisions under a reduced action ceiling, and it
earns full authority only by accumulating real observations. Offline and shadow
evaluation cannot reproduce every production case; guarded activation is what
makes the cases they missed cheap instead of expensive.

**Everything is reversible.** A promotion with no valid rollback target is not
eligible, full stop. That rule is what lets the rest of the package be
automatic at all.
"""
from .lifecycle import (ACTIVE, ARCHIVED, ELIGIBLE, GUARDED_ACTIVE,
                        PENDING_ACTIVATION, QUARANTINED, REJECTED, ROLLED_BACK,
                        SHADOW, STATES, TRAINED, VALIDATED, LifecycleError,
                        can_transition, transition)
from .policy import GOVERNANCE_POLICY_VERSION, GovernancePolicy

__all__ = ['ACTIVE', 'ARCHIVED', 'ELIGIBLE', 'GOVERNANCE_POLICY_VERSION',
           'GUARDED_ACTIVE', 'GovernancePolicy', 'LifecycleError',
           'PENDING_ACTIVATION', 'QUARANTINED', 'REJECTED', 'ROLLED_BACK',
           'SHADOW', 'STATES', 'TRAINED', 'VALIDATED', 'can_transition',
           'transition']
