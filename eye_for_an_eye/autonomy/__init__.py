"""The final decision authority: what the system does, and why it is allowed to.

This package answers one question — **ALLOW or TEMP_BLOCK** — and it answers it
the way a defender should rather than the way a classifier would.

A classifier asks "how malicious does this look?" and returns a number. That
number is an input here, and only one of several, because the question a defender
actually faces is different and harder:

    What did this source actually do?
    How many *independent* kinds of evidence say so?
    Is my data complete enough to judge?
    Do I know who I would be blocking?
    Is this behaviour inside the distribution my model understands?
    Is my model healthy?
    How uncertain is the estimate?
    What does a wrong block cost, here, on this site?
    What does allowing this cost?
    Does the advantage survive the uncertainty?
    Does PolicyGuard permit it?

Only then, ALLOW or TEMP_BLOCK.

Three things about the shape of this package matter more than the rest.

**The final authority is not a model.** No ONNX artifact reaches a decision except
through the evidence chain, and nothing in this package can be influenced by the
thing it judges. `MathRisk` stays deterministic and inspectable; the classifier
contributes a bounded share; anomaly, out-of-distribution rate and drift can
reduce confidence and can never raise suspicion.

**The decision is cost-sensitive, and the costs are local.** There is no
universal threshold, and 0.5 is not a decision boundary — it is a number people
reach for when they have not thought about what a mistake costs. Blocking a
reader of a public blog and blocking a scanner probing an admin panel are not
comparable errors, so the cutoff follows from a cost policy that an operator
owns and that no learned component can rewrite.

**Abstention is ALLOW.** When the evidence is thin, the data incomplete, the
identity uncertain or the model unwell, the answer is ALLOW and keep watching.
That is not the system calling the source benign — `record.py` says so in those
words — it is the system declining to act on something it cannot establish. The
alternative failure, a confident block of somebody who did nothing, is worse and
lands hardest on people using unusual networks, unusual clients and unusual
hours.

Autonomy here is an operational property, not a claim about accuracy. It means
no human approves each decision after an administrator switches it on. It does
not mean the decisions are right, and nothing in this package should ever be
described as though it did.
"""
from .authority import (AUTHORITY_VERSION, AutonomousDecisionAuthority,
                        DecisionGates, DecisionInputs)
from .breakers import (AUTONOMOUS_SAFE_MODE, BlockBudget, BreakerPanel,
                       BudgetLimits, FalsePositiveBreaker, MassBlockBreaker,
                       TechnicalBreaker)
from .cost import COST_POLICY_VERSION, CostPolicy, CostProfile, PROFILES
from .evidence import FAMILIES, SignalFamilies
from .record import (ALLOW, ASSUMPTIONS, AssumptionRegistry,
                     AutonomousDecisionRecord, MAX_BLOCK_TTL_SECONDS,
                     REASON_CODES, TEMP_BLOCK)
from .uncertainty import DecisionUncertainty, ExpectedLoss

__all__ = ['ALLOW', 'ASSUMPTIONS', 'AUTHORITY_VERSION', 'AUTONOMOUS_SAFE_MODE',
           'AssumptionRegistry', 'AutonomousDecisionAuthority',
           'AutonomousDecisionRecord', 'BlockBudget', 'BreakerPanel',
           'BudgetLimits', 'COST_POLICY_VERSION', 'CostPolicy', 'CostProfile',
           'DecisionGates', 'DecisionInputs', 'DecisionUncertainty',
           'ExpectedLoss', 'FAMILIES', 'FalsePositiveBreaker',
           'MAX_BLOCK_TTL_SECONDS', 'MassBlockBreaker', 'PROFILES',
           'REASON_CODES', 'SignalFamilies', 'TechnicalBreaker', 'TEMP_BLOCK']
