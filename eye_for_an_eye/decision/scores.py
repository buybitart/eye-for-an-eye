"""What each number on the decision path means, enforced by the type system.

P15.1 found a units error that had survived three review cycles: the
cost-sensitive cutoff `C_FP / (C_FP + C_FN)` is a *probability* of maliciousness,
and the value compared against it was `MathRisk` — a heuristic score on its own
scale. Both are floats in [0, 1]. Both look like a probability. Neither the
signature, the call site nor the record said which was which, so the mistake was
invisible in review and produced a system that blocked nothing at all.

The repair is not a comment. A comment would have been read and believed by the
same people who read and believed the last one. Every number that enters the
decision gets a type, the type carries its semantics, and the one function that
needs a probability accepts only the type that *is* one:

    expected_loss(probability=CalibratedProbability(0.91, ...))   # allowed
    expected_loss(probability=0.91)                               # refused
    expected_loss(probability=RiskScore(0.91))                    # refused

The wrappers are cheap: frozen slotted dataclasses over one float. They cost an
allocation per decision and they make a whole category of bug unrepresentable,
which is the trade this project has made everywhere else too.

### The contract

| Name | Range | Semantics | Probability? | May enter expected loss |
| --- | --- | --- | --- | --- |
| `RiskScore` | 0-1 | `MathRisk`: deterministic heuristic evidence | no | no |
| `ModelScore` | 0-1 | a classifier's raw output | no | no |
| `CalibratedProbability` | 0-1 | P(malicious \\| evidence), from a validated calibrator | **yes** | **yes** |
| `AnomalyScore` | 0-1 | unusualness; unusual is not malicious | no | no |
| `OODScore` | 0-1 | distance from what the model was trained on | no | no |
| `QualityScore` | 0-1 | how complete the evidence is | no | no |

Every one of them is monotonic with more of what it measures. Only
`CalibratedProbability` is monotonic with *malicious evidence in probability
units*, and that is the whole distinction.

### Why the others are not "just uncalibrated probabilities"

`AnomalyScore` and `OODScore` do not measure maliciousness at all, in any units.
A rare client is rare. A request the model has never seen is unfamiliar. Neither
observation is evidence of intent, and a pipeline that lets them raise a
malicious probability has quietly redefined "malicious" as "unusual" — which is
how a defender ends up blocking the one blind user on the site. They belong in
authority and confidence gates, and `CalibratedProbability` is the only thing the
cost arithmetic ever sees.
"""
from dataclasses import dataclass
import math

#: Bumped when the vocabulary changes shape.
SCORE_CONTRACT_VERSION = 1


class ScoreError(ValueError):
    """A number used as something it is not."""


def _checked(value, name):
    number = float(value)
    if not math.isfinite(number):
        raise ScoreError(f'{name} must be finite, got {value!r}')
    if not 0.0 <= number <= 1.0:
        raise ScoreError(f'{name} must lie in [0, 1], got {number!r}')
    return number


@dataclass(frozen=True, slots=True)
class _Bounded:
    """A finite number in [0, 1] that knows what it is.

    `float(x)` works, so arithmetic is never blocked — the point is not to make
    these hard to use. The point is that a function can ask for one *by type* and
    find out at the call site when it is handed something else.
    """

    value: float

    def __post_init__(self):
        object.__setattr__(self, 'value', _checked(self.value, type(self).__name__))

    def __float__(self):
        return self.value

    def __lt__(self, other):
        return self.value < float(other)

    def __le__(self, other):
        return self.value <= float(other)

    def __gt__(self, other):
        return self.value > float(other)

    def __ge__(self, other):
        return self.value >= float(other)

    #: Whether this number may be used as P(malicious). False everywhere but one.
    is_probability = False

    #: One line for a decision record, so an operator reading it can see which
    #: quantity the decision actually rested on.
    semantics = 'an unspecified bounded score'


@dataclass(frozen=True, slots=True)
class RiskScore(_Bounded):
    """`MathRisk`: deterministic, explainable, and not a probability.

    It is a weighted combination of behavioural evidence passed through a
    sigmoid. The sigmoid makes it bounded; it does not make it calibrated, and
    the distinction is the reason this class exists.
    """

    semantics = 'deterministic heuristic risk score, not a probability'


@dataclass(frozen=True, slots=True)
class ModelScore(_Bounded):
    """A classifier's raw output.

    A logistic regression emits something that looks like a probability and is
    one only for the distribution it was fitted on. Against a different
    prevalence, or behaviour it has never seen, it is a ranking score wearing a
    probability's clothes.
    """

    semantics = 'raw classifier output, not calibrated'


@dataclass(frozen=True, slots=True)
class AnomalyScore(_Bounded):
    semantics = 'unusualness; unusual is not malicious'


@dataclass(frozen=True, slots=True)
class OODScore(_Bounded):
    semantics = 'distance from the training distribution; reduces authority, never raises risk'


@dataclass(frozen=True, slots=True)
class QualityScore(_Bounded):
    semantics = 'completeness of the evidence, not a statement about the source'


@dataclass(frozen=True, slots=True)
class CalibratedProbability:
    """P(malicious | evidence). The only thing expected loss is allowed to use.

    Carries its provenance because a probability with no provenance cannot be
    checked: `source` says which quantity was calibrated, `calibrator_version`
    which artifact produced it, and `model_version` which model that artifact was
    fitted against. §84 — a calibrator belonging to a different model is not a
    calibrator, it is a coincidence with the right shape — so the compatibility
    check lives here rather than in a comment.
    """

    value: float
    source: str
    calibrator_version: str
    model_version: str = ''
    #: Rows the calibrator was fitted on. A calibrator fitted on 40 examples is
    #: an opinion; the number travels with the estimate so a reader can weigh it.
    calibration_samples: int = 0
    #: A Wilson lower bound on this probability, from the calibration data's own
    #: sample sizes. `None` means the artifact carried no bound, and a point
    #: estimate is not something to deny a stranger a service over.
    lower: float | None = None

    is_probability = True
    semantics = 'P(malicious | evidence) from a validated calibrator'

    def __post_init__(self):
        object.__setattr__(self, 'value', _checked(self.value, 'CalibratedProbability'))
        if not str(self.source):
            raise ScoreError('a calibrated probability must say what was calibrated')
        if not str(self.calibrator_version):
            raise ScoreError('a calibrated probability must name its calibrator')
        if self.lower is not None:
            bound = _checked(self.lower, 'CalibratedProbability.lower')
            if bound > self.value + 1e-12:
                raise ScoreError('a lower bound above the estimate is not a lower bound')
            object.__setattr__(self, 'lower', bound)

    @property
    def conservative(self):
        """The value a block may be justified with: the bound, when there is one."""
        return self.value if self.lower is None else self.lower

    @property
    def bounded(self):
        return self.lower is not None

    def __float__(self):
        return self.value

    def __lt__(self, other):
        return self.value < float(other)

    def __le__(self, other):
        return self.value <= float(other)

    def __gt__(self, other):
        return self.value > float(other)

    def __ge__(self, other):
        return self.value >= float(other)

    def compatible_with(self, model_version):
        """§84. An empty `model_version` means the calibrator is unbound.

        P15.2 wrote here that a mapping from `MathRisk` is "genuinely
        model-independent, because `MathRisk` has no learned weights to change
        under it", and left it unbound on that reasoning. P15.3 changed the
        `MathRisk` formula, and the reasoning turned out to be wrong in a way
        worth keeping visible: what a calibrator depends on is not whether the
        quantity is *learned*, it is whether the quantity can change meaning.
        Every quantity can.

        So an unbound calibrator is now a calibrator nobody bound, not a
        calibrator that is safe to reuse. `training/calibrate.py` binds the
        `MathRisk` artifact to `math_risk.VERSION`, and the caller must pass the
        version of the quantity being mapped rather than whichever version is to
        hand.
        """
        if not self.model_version:
            return True
        return str(model_version or '') == self.model_version

    def explain(self):
        return {'value': round(self.value, 6), 'source': self.source,
                'calibrator_version': self.calibrator_version,
                'model_version': self.model_version,
                'calibration_samples': self.calibration_samples,
                'lower_bound': None if self.lower is None else round(self.lower, 6),
                'semantics': self.semantics}


#: Everything that is emphatically not a probability, for the refusal message and
#: for the tests that keep this list honest.
NOT_PROBABILITIES = (RiskScore, ModelScore, AnomalyScore, OODScore, QualityScore)


def require_probability(value, *, argument='probability'):
    """Return the float of a `CalibratedProbability`, or refuse and say why.

    A bare `float` is refused too, and that is the part that matters. The P15.1
    bug was not somebody passing an `AnomalyScore` where a probability belonged —
    it was a float arriving from a fallback branch with nothing to mark it. A
    check that only rejected the wrong wrapper would have caught nothing.
    """
    if isinstance(value, CalibratedProbability):
        return value.value
    if isinstance(value, _Bounded):
        raise ScoreError(
            f'{argument} needs a CalibratedProbability; {type(value).__name__} is '
            f'{value.semantics}. Calibrate it first, or use a gate rather than the '
            f'cost arithmetic.')
    raise ScoreError(
        f'{argument} needs a CalibratedProbability, not a bare {type(value).__name__}. '
        f'A number in [0, 1] is not a probability just because it fits: say which '
        f'quantity it is and where its calibration came from.')


def contract():
    """The table above, as data, so documentation and tests read the same source."""
    entries = [
        (RiskScore, 'MathRisk', 'deterministic heuristic evidence'),
        (ModelScore, 'classifier', 'raw supervised model output'),
        (CalibratedProbability, 'calibrated', 'P(malicious | evidence)'),
        (AnomalyScore, 'anomaly', 'unusualness'),
        (OODScore, 'ood', 'distance from the training distribution'),
        (QualityScore, 'data_quality', 'completeness of the evidence'),
    ]
    return {'score_contract_version': SCORE_CONTRACT_VERSION,
            'scores': [{'name': cls.__name__, 'quantity': quantity, 'range': [0.0, 1.0],
                        'semantics': cls.semantics, 'meaning': meaning,
                        'is_probability': bool(cls.is_probability),
                        'may_enter_expected_loss': bool(cls.is_probability)}
                       for cls, quantity, meaning in entries]}
