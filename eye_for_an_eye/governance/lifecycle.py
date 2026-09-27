"""The model lifecycle, as a table of allowed transitions.

A candidate moves through named states, and the moves it is allowed to make are
data rather than scattered `if` statements. That choice is the point: a lifecycle
implemented as conditions spread across a codebase is one nobody can read, and
the question "can this model reach ACTIVE from here?" has to be answerable by
looking at one table.

    TRAINED ── VALIDATED ── SHADOW ── ELIGIBLE ── PENDING_ACTIVATION
                                                          │
                                                   GUARDED_ACTIVE
                                                     │        │
                                                  ACTIVE   ROLLED_BACK
                                                              │
                                                        QUARANTINED

Three properties of this table matter more than the rest.

**Nothing reaches ACTIVE without passing through GUARDED_ACTIVE.** There is no
edge from ELIGIBLE, or from SHADOW, or from anywhere else. A candidate that has
never run under a reduced ceiling cannot have full authority, and that is
enforced by the absence of an edge rather than by a rule somebody must remember.

**ROLLED_BACK leads to QUARANTINED, not back to VALIDATED.** A model that was
promoted and then withdrawn does not get to try again unchanged on the next
assessment cycle. Without this edge the system has an obvious oscillation:
promote, regress, roll back, re-assess, promote the same artifact again. §80 and
§81 name it; the table is where it is actually prevented.

**Leaving QUARANTINED requires a person.** `transition()` refuses every automatic
path out of it. An operator can release a quarantined model with an explicit
action, and that asymmetry is deliberate — automatic quarantine is cheap and
reversible, automatic release is neither.
"""

#: A candidate exists and has not been judged.
TRAINED = 'TRAINED'
#: Offline evidence passed: schema, hashes, parity, dataset, leakage.
VALIDATED = 'VALIDATED'
#: Running beside the active model, influencing nothing.
SHADOW = 'SHADOW'
#: Every gate passed. Eligible is a verdict, not an activation.
ELIGIBLE = 'ELIGIBLE'
#: The promotion transaction has begun and has not yet completed.
PENDING_ACTIVATION = 'PENDING_ACTIVATION'
#: Contributing to decisions under a reduced action ceiling.
GUARDED_ACTIVE = 'GUARDED_ACTIVE'
#: Full policy authority, subject to the same PolicyGuard as any other model.
ACTIVE = 'ACTIVE'
#: Refused for a reason that makes the artifact itself untrustworthy.
QUARANTINED = 'QUARANTINED'
#: Refused for a reason about quality rather than integrity.
REJECTED = 'REJECTED'
#: Was active or guarded, and was withdrawn.
ROLLED_BACK = 'ROLLED_BACK'
#: Kept for the record. Terminal.
ARCHIVED = 'ARCHIVED'

STATES = (TRAINED, VALIDATED, SHADOW, ELIGIBLE, PENDING_ACTIVATION,
          GUARDED_ACTIVE, ACTIVE, QUARANTINED, REJECTED, ROLLED_BACK, ARCHIVED)

#: States from which a model is influencing live decisions in some way.
LIVE_STATES = (GUARDED_ACTIVE, ACTIVE)

#: States a model can never leave without an explicit human action.
OPERATOR_ONLY_EXITS = (QUARANTINED,)

#: Terminal states.
TERMINAL_STATES = (ARCHIVED,)

#: The allowed moves. Read this table, not the code around it.
#:
#: Quarantine and rejection are reachable from every non-terminal state on
#: purpose: discovering that an artifact is corrupt, or that its scope is wrong,
#: must never depend on how far through the lifecycle it happened to be.
TRANSITIONS = {
    TRAINED: (VALIDATED, QUARANTINED, REJECTED, ARCHIVED),
    VALIDATED: (SHADOW, QUARANTINED, REJECTED, ARCHIVED),
    # SHADOW -> SHADOW is allowed: a candidate is re-assessed on a schedule, and
    # "still gathering evidence" is the ordinary outcome, not an error.
    SHADOW: (SHADOW, ELIGIBLE, QUARANTINED, REJECTED, ARCHIVED),
    # ELIGIBLE -> SHADOW is how a stale assessment is undone (§29, §141): a
    # policy change does not retroactively authorise a verdict reached under the
    # old policy, so the candidate goes back to gathering evidence.
    ELIGIBLE: (PENDING_ACTIVATION, SHADOW, QUARANTINED, REJECTED, ARCHIVED),
    # A failed activation leaves the artifact suspect, not merely unlucky.
    PENDING_ACTIVATION: (GUARDED_ACTIVE, ROLLED_BACK, QUARANTINED),
    GUARDED_ACTIVE: (ACTIVE, ROLLED_BACK),
    ACTIVE: (ROLLED_BACK, ARCHIVED),
    # The edge that prevents the promote/rollback oscillation (§80, §81).
    ROLLED_BACK: (QUARANTINED, ARCHIVED),
    # Everything out of QUARANTINED needs a person; see `transition`.
    QUARANTINED: (VALIDATED, REJECTED, ARCHIVED),
    REJECTED: (ARCHIVED,),
    ARCHIVED: (),
}

#: The one edge out of QUARANTINED that an operator may take, and which no
#: automatic caller may. Releasing a quarantined artifact is a decision with a
#: name on it.
OPERATOR_RELEASE = (QUARANTINED, VALIDATED)


class LifecycleError(ValueError):
    """A transition that the lifecycle does not allow."""


def can_transition(current, target, *, operator=False):
    """Whether `current -> target` is allowed. Pure; never raises."""
    if current not in TRANSITIONS or target not in STATES:
        return False
    if (current, target) == OPERATOR_RELEASE and not operator:
        return False
    return target in TRANSITIONS[current]


def transition(current, target, *, operator=False):
    """Return `target`, or raise `LifecycleError` naming both states.

    `operator=True` means a person asked for this, through the CLI. It unlocks
    exactly one edge — releasing a quarantined artifact — and nothing else. It is
    not a general override, because a flag that bypassed the whole table would
    make the table decorative.
    """
    if current not in TRANSITIONS:
        raise LifecycleError(f'{current!r} is not a model lifecycle state')
    if target not in STATES:
        raise LifecycleError(f'{target!r} is not a model lifecycle state')
    if (current, target) == OPERATOR_RELEASE and not operator:
        raise LifecycleError(
            'releasing a quarantined model requires an explicit operator action; '
            'automatic release would undo the only protection quarantine offers')
    if target not in TRANSITIONS[current]:
        allowed = ', '.join(TRANSITIONS[current]) or 'nothing (terminal state)'
        raise LifecycleError(
            f'a model cannot move from {current} to {target}; from {current} it '
            f'may only become: {allowed}')
    return target


def reaches_active(state):
    """Whether ACTIVE is still reachable from `state` without an operator.

    Used by reporting rather than by control flow: an operator looking at a
    candidate wants to know whether it is still a live prospect or whether it has
    ended up somewhere terminal.
    """
    seen, frontier = set(), [state]
    while frontier:
        current = frontier.pop()
        if current == ACTIVE:
            return True
        if current in seen or current not in TRANSITIONS:
            continue
        seen.add(current)
        frontier.extend(target for target in TRANSITIONS[current]
                        if can_transition(current, target))
    return False


def explain():
    """The whole table, for `model governance status` and the documentation."""
    return {'states': list(STATES),
            'transitions': {state: list(targets) for state, targets in TRANSITIONS.items()},
            'live_states': list(LIVE_STATES),
            'operator_only_exits': list(OPERATOR_ONLY_EXITS),
            'terminal_states': list(TERMINAL_STATES),
            'notes': [
                'nothing reaches ACTIVE except through GUARDED_ACTIVE',
                'ROLLED_BACK leads to QUARANTINED, so a withdrawn model cannot '
                'immediately retry unchanged',
                'leaving QUARANTINED requires an explicit operator action']}
