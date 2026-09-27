"""How sure we are, and the expected loss that follows from being unsure.

Two ideas, kept together because they only make sense together.

**A point estimate is not enough to act on.** A malicious probability of 0.98
from forty observations of a source the model has never seen anything like, with
a sensor dropping events, is not the same claim as 0.98 from four thousand
observations of familiar traffic on a healthy model — and a decision procedure
that treated them identically would be acting on the arithmetic while ignoring
everything that determines whether the arithmetic means anything.

**So the decision uses a conservative estimate, never the optimistic one.** §37.
The point estimate is shrunk towards the base rate by an amount that grows with
uncertainty, and then a sampling-width term is subtracted. The result is used for
the block side of the comparison, which means uncertainty always argues for
allowing and never for blocking.

### Naming, carefully

§36 asks for correct names, so: what `conservative_probability` returns is **not**
a credible interval and not a frequentist confidence bound. It is an *empirical
lower estimate* built from two documented, deliberately crude adjustments:

1. **Shrinkage towards the prior.** `p_shrunk = (1-u)*p + u*prior`, where `u` is
   the uncertainty in [0, 1]. At full uncertainty the estimate is the base rate,
   which is the honest answer when nothing is known.
2. **A sampling-width subtraction.** A Wilson-style lower bound on a proportion
   observed `n` times. With few observations this is large; it shrinks as `n`
   grows, which is the behaviour §171 is about.

Neither step has a distributional guarantee behind it, and calling the result a
confidence interval would be borrowing authority the implementation has not
earned. It is conservative in direction, which is the property that matters.

### When the model is not calibrated

If the classifier is not calibrated, its output is a **score**, not a
probability, and §20 forbids feeding it into an expected-loss calculation as
though it were one. In that case `calibrated` is False, the deterministic
mathematical evidence carries the estimate, and the model score contributes only
through the bounded fusion share it already had. The record says which happened.
"""
from dataclasses import asdict, dataclass
import math

#: What fraction of sources are malicious automation, absent better information.
#: Used only as a shrinkage target. Deliberately low: the rare class is rare, and
#: an estimate that collapses towards "probably malicious" when it knows nothing
#: would be the opposite of conservative.
DEFAULT_PRIOR = 0.02

#: Sampling-width constant. 1.96 would suggest a 95% interval, which this is not
#: (see the module docstring), so a plain 1.0 is used and named as what it is.
WIDTH_FACTOR = 1.0


@dataclass(frozen=True, slots=True)
class DecisionUncertainty:
    """Everything that makes an estimate less trustworthy, and the total.

    Each component is in [0, 1] where 0 is "no reason for doubt". They combine
    as a bounded sum rather than a product: doubts add up, and a product would
    let one perfect component wash out four bad ones.
    """

    #: The classifier is not calibrated, so its output is a score (§19, §20).
    uncalibrated: float = 0.0
    #: This sample is outside what the model was trained on (§27, §82).
    out_of_distribution: float = 0.0
    #: Features missing, windows immature, sensor dropping (§29, §30).
    data_quality: float = 0.0
    #: Drift, inference failures, a degraded artifact (§28).
    model_health: float = 0.0
    #: Too few observations to say much (§171).
    sample: float = 0.0
    #: Models that disagree materially (§85).
    disagreement: float = 0.0
    #: How many observations the estimate rests on. Carried for the width term.
    observations: int = 0

    @property
    def total(self):
        """Bounded sum of the components, in [0, 1]."""
        return min(1.0, sum((self.uncalibrated, self.out_of_distribution,
                            self.data_quality, self.model_health, self.sample,
                            self.disagreement)))

    @property
    def dominant(self):
        """The largest single source of doubt, for the decision record."""
        components = {'uncalibrated': self.uncalibrated,
                      'out_of_distribution': self.out_of_distribution,
                      'data_quality': self.data_quality,
                      'model_health': self.model_health,
                      'sample': self.sample,
                      'disagreement': self.disagreement}
        name, value = max(components.items(), key=lambda item: item[1])
        return name if value > 0 else ''

    def conservative_probability(self, estimate, *, prior=DEFAULT_PRIOR):
        """A deliberately pessimistic reading of `estimate`. Never raises it.

        Returns a value in [0, prior_or_estimate], and is monotone: more
        uncertainty never produces a higher number. That monotonicity is the
        property the whole decision rests on, and there is a test for it.
        """
        point = max(0.0, min(1.0, float(estimate)))
        weight = self.total
        shrunk = (1.0 - weight) * point + weight * prior
        width = self._width(shrunk)
        return max(0.0, min(point, shrunk - width))

    def _width(self, proportion):
        """A Wilson-style lower-bound width. Large when `observations` is small.

        Not a confidence interval; a sampling-width penalty with the right shape.
        With no observations the width is the whole range, which collapses the
        estimate to zero — the correct answer when nothing has been seen.
        """
        count = max(0, int(self.observations))
        if count <= 0:
            return 1.0
        return WIDTH_FACTOR * math.sqrt(
            max(0.0, proportion * (1.0 - proportion)) / count) + 1.0 / (2 * count)

    def explain(self):
        body = asdict(self)
        body['total'] = round(self.total, 4)
        body['dominant'] = self.dominant
        return body


def assess(*, calibrated, ood_score=None, data_quality_score=None,
           model_health=None, observations=0, model_disagreement=None,
           drift_status='STABLE'):
    """Build a `DecisionUncertainty` from the runtime signals.

    Every argument may be `None`, meaning "not measured", and every `None` adds
    uncertainty rather than being read as "fine". A measurement nobody took is
    not a good measurement.
    """
    uncalibrated = 0.0 if calibrated else 0.30
    ood = 0.0 if ood_score is None else min(0.35, max(0.0, float(ood_score)) * 0.35)
    if ood_score is None:
        ood = 0.15
    quality = (0.20 if data_quality_score is None
               else min(0.30, max(0.0, 1.0 - float(data_quality_score)) * 0.30))
    health = 0.0
    if model_health in ('DEGRADED', 'degraded'):
        health += 0.15
    elif model_health in ('UNRELIABLE', 'unreliable', 'UNAVAILABLE', 'unavailable'):
        health += 0.30
    if str(drift_status).upper() == 'DRIFTED':
        health = min(0.35, health + 0.10)
    count = max(0, int(observations))
    sample = 0.30 if count < 20 else 0.15 if count < 100 else 0.05 if count < 500 else 0.0
    disagreement = (0.0 if model_disagreement is None
                    else min(0.20, max(0.0, float(model_disagreement)) * 0.20))
    return DecisionUncertainty(
        uncalibrated=uncalibrated, out_of_distribution=ood, data_quality=quality,
        model_health=health, sample=sample, disagreement=disagreement,
        observations=count)


@dataclass(frozen=True, slots=True)
class ExpectedLoss:
    """The two losses, the margin between them, and whether it survives doubt.

    The simplest cost matrix, deliberately:

        LossAllow  = p * C_FN          the malicious source continues
        LossBlock  = (1 - p) * C_FP    a benign source is denied

    with zero cost for the correct outcomes. `p` here is always the
    **conservative** estimate, so the comparison is made against the version of
    the evidence that is least favourable to blocking.
    """

    probability: float
    conservative_probability: float
    loss_allow: float
    loss_block: float
    threshold: float
    margin: float
    profile: str
    calibrated: bool
    #: What the P15 shrinkage would have produced, kept so a record shows both
    #: numbers and a reader can see how much the repair changed.
    legacy_conservative_probability: float = 0.0
    #: `calibration_wilson` or `shrinkage`. Which bound the decision rested on,
    #: named in every record rather than inferred from whether one was available.
    bound_source: str = 'shrinkage'

    @property
    def advantage(self):
        """How much better blocking is. Negative means allowing is better."""
        return self.loss_allow - self.loss_block

    @property
    def relative_advantage(self):
        """The advantage as a fraction of the larger loss, in [-1, 1]."""
        scale = max(self.loss_allow, self.loss_block)
        return 0.0 if scale <= 0 else self.advantage / scale

    @property
    def block_arithmetically_preferred(self):
        """`LossBlock < LossAllow`. A necessary condition, and nothing more."""
        return self.loss_block < self.loss_allow

    @property
    def block_robustly_preferred(self):
        """§120. The advantage survives the margin, on the conservative estimate.

        Everything this returns True for still has to pass evidence diversity,
        data quality, identity confidence, model health, the block budget and
        PolicyGuard. This is the arithmetic saying "yes, and by enough to be
        worth acting on" — not a decision.
        """
        return (self.block_arithmetically_preferred
                and self.relative_advantage >= self.margin
                and self.conservative_probability >= self.threshold)

    def explain(self):
        return {'probability': round(self.probability, 6),
                'conservative_probability': round(self.conservative_probability, 6),
                'loss_allow': round(self.loss_allow, 6),
                'loss_block': round(self.loss_block, 6),
                'advantage': round(self.advantage, 6),
                'relative_advantage': round(self.relative_advantage, 6),
                'threshold': round(self.threshold, 6),
                'decision_margin': self.margin,
                'cost_profile': self.profile,
                'calibrated': self.calibrated,
                'bound_source': self.bound_source,
                'legacy_conservative_probability': round(
                    self.legacy_conservative_probability, 6),
                'block_arithmetically_preferred': self.block_arithmetically_preferred,
                'block_robustly_preferred': self.block_robustly_preferred}


def evaluate(*, probability, uncertainty, profile, margin, calibrated,
             prior=DEFAULT_PRIOR, calibrated_lower=None):
    """Compute both losses under a cost profile, using the conservative estimate.

    ### Which conservative estimate, and why there are now two

    P15.2 measured what the single shrinkage-plus-width estimate could reach. At
    a probability of exactly 1.0 — total certainty of maliciousness — on a mature
    window with the realistic total uncertainty this corpus produces, it reaches
    **0.854**, against a `public_website` cutoff of 0.9756 and an `api` cutoff of
    0.9877. The gates permit a block at total uncertainty 0.60, where the same
    estimate cannot exceed **0.412**. The uncertainty budget and the cost cutoffs
    were chosen independently and are arithmetically incompatible: no evidence,
    however strong, could clear them both. Calibration alone would not have fixed
    that, and the numbers are in `reports/P15_2_FINAL_REPORT.md`.

    The cause is a sample-size mistake. The shrinkage's width term is a Wilson
    correction, and a Wilson correction bounds a proportion estimated from `n`
    observations. The proportion here is P(malicious | evidence); its sample size
    is the number of *calibration examples* supporting that estimate, in the
    thousands. P15 used the number of packets in the observation window — tens —
    and so subtracted an interval two orders of magnitude too wide.

    So `calibrated_lower` is the repair: a Wilson lower bound computed over the
    right sample size, by the calibrator that produced the estimate, from its own
    fitting data. When one is supplied it is used, and the observation count
    keeps the two jobs it should always have had — the maturity gate, and the
    `sample` component of total uncertainty — instead of a third.

    Nothing is weakened. The legacy estimate still governs every uncalibrated
    decision, and an uncalibrated decision cannot block at all: `authority.py`
    gates on `calibrated_estimate` before it reaches the arithmetic. This path is
    new behaviour for a case that previously had none.
    """
    point = max(0.0, min(1.0, float(probability)))
    legacy = uncertainty.conservative_probability(point, prior=prior)
    if calibrated_lower is None:
        conservative = legacy
    else:
        # Never above the point estimate, and never above what the heuristic
        # would have allowed *when the heuristic is the stricter of the two* —
        # no. Deliberately not that: taking the minimum of the two would
        # reintroduce the packet-count width through the back door and return
        # the system to blocking nothing. The bound used is the one whose
        # arithmetic matches its claim.
        conservative = max(0.0, min(point, float(calibrated_lower)))
    return ExpectedLoss(
        probability=point,
        conservative_probability=conservative,
        loss_allow=conservative * profile.false_allow,
        loss_block=(1.0 - conservative) * profile.false_block,
        threshold=profile.threshold,
        margin=float(margin),
        profile=profile.name,
        calibrated=bool(calibrated),
        legacy_conservative_probability=legacy,
        bound_source='calibration_wilson' if calibrated_lower is not None else 'shrinkage')
