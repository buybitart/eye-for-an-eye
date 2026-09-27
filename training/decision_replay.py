"""Replay a trusted labelled corpus through the *whole* system and score the action.

P15 could not answer the only question an operator actually asks — *of the
sources this thing blocks, how many should it have blocked, and how many real
visitors does it deny?* — because nothing had ever run a labelled corpus all the
way to `ALLOW` / `TEMP_BLOCK`. Everything upstream had been measured. The final
decision had not.

This module closes that. Each row goes through the real components, in the real
order, with no re-implementation anywhere:

    DatasetSample.features (a production FeatureVector)
        -> MathRiskEngine                    deterministic, uncalibrated
        -> IsolatedModel                     the ONNX classifier, optional
        -> AnomalyModel                      bounded, carved out of the pool
        -> OODEngine                         reduces classifier authority only
        -> DataQualityResult                 completeness and window maturity
        -> DecisionFusion                    the P7/P8 evidence and ladder
        -> PolicyGuard                       can only ever weaken
        -> AutonomousDecisionAuthority       cost, uncertainty, the gates
        -> ALLOW / TEMP_BLOCK

### Three things this deliberately does not do

**It does not invent labels.** A row's label comes from the corpus, whose
`label_source` is a controlled scenario, a trusted fixture or a reviewed answer.
Rows labelled `unlabeled` are dropped rather than guessed at, and a row whose
label source is a decision this system made cannot exist — `dataset/schema.py`
refuses to construct one.

**It does not model a proxy.** Every replayed source is treated as directly
connected: identity HIGH, `network_enforceable` true, scope `NETWORK_SOURCE`.
That is not optimism, it is the *hardest* setting — the identity gates that
refuse a CDN client are the cheapest way to look good on a false-block metric,
and switching them off means every block here had to be earned on evidence.
Sites behind a proxy are measured by `tests/test_web_enforcement_safety.py`,
which asserts they cannot be network-blocked at all.

**It does not grant hysteresis.** Every source is replayed cold, with
`offence_count = 0`, so no decision benefits from the lower repeat-offender
margin. A real deployment would sometimes clear a lower bar; this measurement
never does.

### Windows and sources

A row is one observation window. A *source* is what gets blocked, so the
headline numbers are per source: a source counts as blocked if any of its
windows reached `TEMP_BLOCK`. Both views are produced, because they answer
different questions and the difference between them is itself informative — a
system that blocks a scanner on its fourth window and not its first is behaving
correctly, and only the per-source view shows that as a success.
"""
from collections import defaultdict
from dataclasses import dataclass, field
import hashlib

from eye_for_an_eye.autonomy import evaluation as ev
from eye_for_an_eye.autonomy.authority import AUTONOMOUS, AutonomousDecisionAuthority
from eye_for_an_eye.autonomy.cost import CostPolicy
from eye_for_an_eye.autonomy.pipeline import decision_inputs
from eye_for_an_eye.autonomy.scope import ScopeResolver
from eye_for_an_eye.decision.anomaly import AnomalyModel, AnomalyResult
from eye_for_an_eye.decision.distribution import load_reference, transformed_values
from eye_for_an_eye.decision.drift import model_health
from eye_for_an_eye.decision.features import FeatureTransformer, NAMES
from eye_for_an_eye.decision.math_risk import MathRiskEngine
from eye_for_an_eye.decision.math_risk import VERSION as MATH_RISK_VERSION
from eye_for_an_eye.decision.onnx_model import IsolatedModel, MLResult
from eye_for_an_eye.decision.ood import OODEngine
from eye_for_an_eye.decision.policy import DecisionFusion, DataQualityResult, PolicyGuard, usable_ml

REPLAY_SCHEMA_VERSION = 1

#: Corpus label -> evaluation label. Only these two are scored; `uncertain` and
#: `unlabeled` rows are counted and excluded, never coerced into a class.
LABELS = {'benign_like': ev.BENIGN, 'malicious_automation_like': ev.MALICIOUS_AUTOMATION}

#: Label sources whose provenance establishes the class (§63). A row carrying
#: anything else is not ground truth for this measurement, however good it looks.
TRUSTED_LABEL_SOURCES = ('controlled_scenario', 'manual_review', 'trusted_fixture')

#: Documentation range (RFC 5737). Replayed sources need an address because
#: PolicyGuard and the authority both take one; these are not real addresses and
#: are not in any protected network, so nothing is refused for the wrong reason.
SOURCE_PREFIX = '198.51.100.'
SECOND_PREFIX = '203.0.113.'


def synthetic_address(source_group):
    """A stable documentation-range address for one corpus source group.

    Deterministic, so a replay is reproducible, and confined to two /24s of
    RFC 5737 space so that nothing here can be mistaken for an observation about
    a real host.
    """
    digest = hashlib.sha256(str(source_group).encode('utf-8')).digest()
    prefix = SOURCE_PREFIX if digest[0] % 2 == 0 else SECOND_PREFIX
    return prefix + str(1 + digest[1] % 254)


@dataclass
class ReplayComponents:
    """The real engines, built once and reused for every row."""

    config: object
    math: object = field(default_factory=MathRiskEngine)
    fusion: object = None
    guard: object = None
    classifier: object = None
    anomaly: object = None
    ood: object = None
    reference: object = None
    #: How many rows the classifier answered, so the report can say whether it
    #: contributed at all rather than assuming it did.
    ml_answered: int = 0
    ml_failed: int = 0
    #: §9, §10. Per component: NOT_CONFIGURED, HEALTHY, or UNAVAILABLE. The
    #: third state is the one that has to exist. Until P15.5 a configured
    #: anomaly model whose `load()` failed was set back to `None` here, which is
    #: indistinguishable from never having been configured — "do not silently
    #: replace broken with not configured", in the one place that did.
    component_state: dict = field(default_factory=dict)
    component_detail: dict = field(default_factory=dict)

    def __post_init__(self):
        self.fusion = DecisionFusion(self.config.decision)
        self.guard = PolicyGuard(self.config)

    def open(self, *, classifier_path='', classifier_manifest='',
             anomaly_path='', anomaly_manifest='', distribution_path=''):
        """Load the optional artifacts. A missing one is a supported state.

        Nothing here raises on absence: a deployment with no classifier, no
        anomaly model and no reference distribution is the deterministic
        fallback configuration, and measuring it is the point of §37's second
        clause.
        """
        self._configured('classifier', bool(classifier_path and classifier_manifest))
        if classifier_path and classifier_manifest:
            self.config.ml.enabled = True
            self.config.ml.model_path = str(classifier_path)
            self.config.ml.manifest_path = str(classifier_manifest)
            self.classifier = IsolatedModel(self.config.ml)
            state = self.classifier.load() or {}
            self._resolve('classifier', state.get('status') == 'healthy',
                          str(state.get('error') or state.get('status') or '')[:160])

        self._configured('anomaly', bool(anomaly_path and anomaly_manifest))
        if anomaly_path and anomaly_manifest:
            self.anomaly = AnomalyModel(enabled=True, model_path=str(anomaly_path),
                                        manifest_path=str(anomaly_manifest))
            loaded = self.anomaly.load()
            # The model stays attached when it fails. It reports `usable=False`
            # and scores nothing, which is the correct behaviour; discarding it
            # would also discard the fact that somebody configured one.
            self._resolve('anomaly', bool(loaded),
                          '' if loaded else 'configured artifact did not load')

        self._configured('reference_distribution', bool(distribution_path))
        if distribution_path:
            try:
                self.reference = load_reference(distribution_path)
                self.ood = OODEngine(self.reference)
                self._resolve('reference_distribution', self.reference is not None,
                              '' if self.reference is not None else 'reference was empty')
            except (OSError, ValueError) as exc:
                # An OOD reference that cannot be read means the classifier's
                # authority is withdrawn, not that OOD was switched off.
                self.reference, self.ood = None, None
                self._resolve('reference_distribution', False,
                              f'{type(exc).__name__}: {exc}'[:160])
        return self

    # -- §9, §10: configured, and then either healthy or honestly broken -------

    def _configured(self, name, configured):
        self.component_state[name] = 'NOT_CONFIGURED' if not configured else 'CONFIGURED'
        self.component_detail.setdefault(name, '')

    def _resolve(self, name, healthy, detail=''):
        self.component_state[name] = 'HEALTHY' if healthy else 'UNAVAILABLE'
        self.component_detail[name] = detail

    def health(self):
        """What each optional component is, and whether it answered.

        `calibrator` is resolved by the caller, which owns the artifact; the
        counters for the classifier are resolved from what it actually did,
        because a model that loads and then fails every prediction is the exact
        P15.4 auxiliary-ML defect and "HEALTHY at load" would have hidden it.
        """
        state = dict(self.component_state)
        if state.get('classifier') == 'HEALTHY' and self.ml_answered == 0 and self.ml_failed:
            state['classifier'] = 'UNAVAILABLE'
            self.component_detail['classifier'] = (
                f'loaded but answered nothing: {self.ml_failed} predictions unusable')
        return {'components': state,
                'detail': {k: v for k, v in self.component_detail.items() if v},
                'classifier_predictions': {'answered': self.ml_answered,
                                           'unusable': self.ml_failed},
                'degraded': sorted(name for name, value in state.items()
                                   if value == 'UNAVAILABLE'),
                'note': ('NOT_CONFIGURED and UNAVAILABLE are different states and '
                         'are never merged: the first is a deployment choice, the '
                         'second is a fault')}

    def close(self):
        if self.classifier is not None:
            self.classifier.close()
        return self


@dataclass(frozen=True, slots=True)
class WindowDecision:
    """What the system decided about one observation window, and why."""

    sample_id: str
    source_group: str
    scenario_group: str
    source_type: str
    label: str
    label_source: str
    action: str
    blocked: bool
    conservative_probability: float
    math_risk: float
    model_score: float | None
    anomaly_score: float | None
    ood_status: str
    data_quality: float
    signal_diversity: int
    behavioural_diversity: int
    reason_codes: tuple
    policy_guard_action: str
    block_ttl_seconds: int
    # --- P15.2 -------------------------------------------------------------
    # Additive, with defaults, so every P15.1 construction of this type still
    # works and the release-critical replay tests keep their meaning.
    #: The window's maturity, which several gates depend on and P15.1 could not
    #: see in the output — a block refused for "too few observations" and one
    #: refused on the evidence look identical without it.
    observations: int = 0
    observation_seconds: float = 0.0
    # --- P15.4 -------------------------------------------------------------
    # Additive, with defaults, same rule as the P15.2 block above. Which site
    # this traffic belongs to and what kind of site that is. Both are evaluation
    # metadata and neither can reach a model (`dataset.schema.NEVER_MODEL_INPUT`
    # names them, `tests/test_p15_4_profiles.py` proves it from four
    # directions); they are here because `autonomy.evaluation.per_site` and
    # `worst_site` have existed since P13 and have never been given a real site
    # to group by. Every corpus before P15.4 carried `site_group = None`, so
    # every per-site table in every report so far was a per-scenario table
    # wearing a different name, and "the worst site" -- the number an average
    # false-block rate is supposed to be read against -- could not be computed.
    site_group: str = ""
    profile_type: str = ""
    #: The calibrated probability the decision used, when a calibrator applied.
    calibrated_probability: float | None = None
    calibrated: bool = False
    calibrator_source: str = ''
    calibrator_version: str = ''
    # --- P15.5 -------------------------------------------------------------
    #: The `AutonomousDecisionRecord` this row came from. Additive with a
    #: default, same rule as the two blocks above, and excluded from equality
    #: and repr because it is an object rather than a measurement.
    #:
    #: It is here because §5 asks the whole-system smoke test to continue past
    #: the authority into a validated `EnforcementRequest`, and
    #: `security.host_enforcer.request_from_record` reads the record — by
    #: design, so that a caller cannot ask for a different address or a longer
    #: block than the decision supports. Without this field the smoke test would
    #: have to rebuild a record from the summary, which is precisely the
    #: second-implementation problem §8 forbids.
    record: object = field(default=None, compare=False, repr=False)


def _ml_inputs(components, vector):
    """Run the classifier, or report honestly that there was not one.

    Projected to the schema the loaded artifact declares, exactly as
    `DecisionEngine.observe` does — §32 says replay is the production path and
    not a second implementation of it, and this line is what that means in
    practice.

    Between the schema-2 change and the P15.4 calibration refit it was not: a
    forty-six column tensor went to a thirty-six column model, every prediction
    failed, `model_score` was absent from every window of every corpus, and the
    only visible symptom was a `model_score` calibrator that could not be fitted
    because it had no points to fit. Nothing crashed, nothing logged, and the
    deterministic path carried on alone.
    """
    if components.classifier is None:
        # `not_configured` is only truthful when nothing was asked for. If the
        # caller configured a classifier and it is absent here, that is a fault
        # and `health()` says so rather than this line pretending otherwise.
        configured = components.component_state.get('classifier', 'NOT_CONFIGURED')
        return MLResult(status='unavailable',
                        error='not_configured' if configured == 'NOT_CONFIGURED'
                        else 'configured_classifier_absent')
    schema = components.classifier.health().get('feature_schema_version')
    result = components.classifier.predict(FeatureTransformer.project(vector, schema))
    if usable_ml(result):
        components.ml_answered += 1
    else:
        components.ml_failed += 1
    return result


def _calibrated(calibrator, *, math_risk, model_score, ml_model_version):
    """Apply a calibrator, if one applies. Returns (probability, semantics) or None.

    Which score is calibrated is the calibrator's own business: it declares a
    `source`, and this reads that rather than guessing. A calibrator for
    `model_score` cannot be handed `math_risk` by accident, because the name it
    asks for is the name it gets.

    The version checked against the artifact is **the version of the quantity it
    maps**, not whichever version happens to be to hand. P15.3 is why this is
    spelled out: `MathRisk` was treated as model-independent because it has no
    learned weights, and then P15.3 changed its formula. A calibrator fitted on
    `math-risk-v1` scores is meaningless against `math-risk-v2` scores, and
    handing it the *classifier's* version would have let it through.
    """
    if calibrator is None:
        return None
    available = {'math_risk': (math_risk, MATH_RISK_VERSION),
                 'model_score': (model_score, ml_model_version)}
    score, version = available.get(calibrator.source, (None, ''))
    if score is None:
        return None
    return calibrator.calibrate(score, model_version=version)


def replay_sample(sample, components, *, authority, classifier_authority=True,
                  calibrator=None):
    """One row, all the way to ALLOW or TEMP_BLOCK."""
    vector = sample.features
    tensor = FeatureTransformer.transform(vector)
    values = dict(zip(NAMES, vector.values))

    math_result = components.math.evaluate(vector)
    ml = _ml_inputs(components, vector) if classifier_authority else MLResult(
        status='unavailable', error='classifier_authority_withheld')

    anomaly_result = AnomalyResult(status='disabled')
    if components.anomaly is not None and components.anomaly.loaded:
        anomaly_result = components.anomaly.score(tensor)

    ood_result = None
    if components.ood is not None:
        ood_result = components.ood.evaluate(transformed_values(vector))

    quality = DataQualityResult.evaluate(vector)
    confidence = ood_result.distribution_confidence if ood_result is not None else 1.0
    persistence = min(1.0, (values['persistence_900s'] or 0) / 300)
    evidence = components.fusion.evaluate(math_result, ml, persistence,
                                          distribution_confidence=confidence,
                                          anomaly=anomaly_result)
    proposed = components.fusion.state(evidence.threat_evidence)
    address = synthetic_address(sample.source_group or sample.sample_id)
    health = model_health(loaded=ml.status == 'healthy', model_version=ml.model_version,
                          drift=None, ood_rate=None)
    guard_action, guard_reasons, _ = components.guard.apply(
        proposed, vector, math_result, ml, source=address, healthy=True,
        ood=ood_result, model_health=health if components.reference is not None else None,
        evidence=evidence)

    probability = _calibrated(
        calibrator, math_risk=math_result.score,
        model_score=ml.risk_score if usable_ml(ml) else None,
        ml_model_version=ml.model_version)

    # P15.5R §17, §19. The scope this corpus row declares, resolved by the same
    # resolver the runtime uses, against the same cost policy the authority is
    # about to price with.
    #
    # It was the literal `'GLOBAL'` until P15.5, and with an empty
    # `scope_profiles` map every scope resolves to the default — so every
    # decision in every locked benchmark was taken at the `public_website`
    # cutoff of 0.975610 regardless of the site it belonged to, and the
    # per-profile tables were outcomes *grouped* by profile rather than *decided*
    # per profile. Found by the P15.5 locked benchmark; that result was not
    # rescored (§25, §26). A corpus that declares no profile still resolves to
    # `GLOBAL` and therefore to the default, which is the pre-P15.4 behaviour
    # unchanged.
    resolution = ScopeResolver(authority.cost_policy).resolve(
        declared=str((sample.provenance or {}).get('profile_type') or ''))

    # §17. *The* assembly, not this file's copy of it. Two assemblies of the
    # same components are what P15.4 was — a forty-six column tensor to a
    # thirty-six column model, every unit test passing, and the defect invisible
    # from either side. `decision_inputs` lives in the shipped package precisely
    # so that a benchmark cannot measure a decision the runtime would not make.
    inputs = decision_inputs(
        source=address, vector=vector, math_result=math_result, ml=ml,
        quality=quality, resolution=resolution, calibration=probability,
        ood=ood_result, anomaly=anomaly_result,
        # Directly connected, deliberately: see the module docstring.
        identity_confidence='HIGH', identity_origin='direct_peer',
        network_enforceable=True, enforcement_scope='NETWORK_SOURCE',
        offence_count=0, enforcement_healthy=True, clock_sane=True,
        model_health='HEALTHY' if usable_ml(ml) else 'UNKNOWN',
        policy_guard_action='REFUSED' if guard_action == 'OBSERVE' and 'protected_source'
                            in guard_reasons else 'ALLOW',
        policy_guard_reasons=tuple(guard_reasons)[:8])

    record = authority.decide(inputs)
    return WindowDecision(
        record=record,
        sample_id=sample.sample_id,
        source_group=str(sample.source_group or ''),
        scenario_group=str(sample.scenario_group or ''),
        source_type=sample.source_type,
        label=sample.label, label_source=str(sample.label_source or ''),
        action=record.action, blocked=record.blocked,
        conservative_probability=record.conservative_probability,
        math_risk=math_result.score,
        model_score=ml.risk_score if usable_ml(ml) else None,
        anomaly_score=anomaly_result.anomaly_score if anomaly_result.usable else None,
        ood_status=ood_result.status if ood_result is not None else 'INSUFFICIENT_REFERENCE',
        data_quality=quality.score,
        signal_diversity=record.signal_diversity,
        behavioural_diversity=record.behavioural_diversity,
        reason_codes=record.reason_codes,
        policy_guard_action=guard_action,
        block_ttl_seconds=record.block_ttl_seconds,
        observations=vector.sample_count,
        observation_seconds=vector.observation_seconds,
        site_group=str(getattr(sample, "site_group", "") or ""),
        profile_type=str((sample.provenance or {}).get("profile_type") or ""),
        calibrated_probability=float(probability) if probability is not None else None,
        calibrated=probability is not None,
        calibrator_source=probability.source if probability is not None else '',
        calibrator_version=probability.calibrator_version if probability is not None else '')


def _vector_key(sample):
    vector = sample.features
    return (vector.values, round(vector.observation_seconds, 3), vector.sample_count)


def ambiguous_vectors(samples):
    """Feature vectors that appear in the corpus under more than one label.

    A generator can produce the same bounded window from a benign session and
    from a slow scan — both are, say, four connections to one port over ninety
    seconds, and at that point the features genuinely do not distinguish them.
    Such a row is not a hard case to be scored and got wrong; it is a row where
    ground truth does not exist at the resolution the system can see.

    Scoring them either way would move a metric without measuring anything, so
    they are excluded and counted. `dataset/validator.py` reports the same
    vectors as a critical finding, which is where this was noticed.
    """
    labels = defaultdict(set)
    for sample in samples:
        if sample.label in LABELS:
            labels[_vector_key(sample)].add(sample.label)
    return {key for key, found in labels.items() if len(found) > 1}


def trusted(samples):
    """The rows this measurement is allowed to score, and why the rest are not."""
    ambiguous = ambiguous_vectors(samples)
    kept, dropped = [], defaultdict(int)
    for sample in samples:
        if sample.label not in LABELS:
            dropped[f'label={sample.label}'] += 1
            continue
        if sample.label_source not in TRUSTED_LABEL_SOURCES:
            dropped[f'label_source={sample.label_source}'] += 1
            continue
        if _vector_key(sample) in ambiguous:
            dropped['identical_vector_under_both_labels'] += 1
            continue
        kept.append(sample)
    return kept, dict(dropped)


#: How much time each replayed window is treated as occupying. P15.2.
#:
#: The block budget is a rate limit — ten blocks a minute, five hundred active —
#: and a replay puts thousands of windows through it in a few seconds of wall
#: clock. With a frozen clock the budget is spent on the tenth block and every
#: later decision is refused with `BLOCK_BUDGET_EXHAUSTED`, which measures the
#: harness rather than the system: in production those windows are minutes or
#: hours apart. P15.1 did not notice because nothing blocked at all.
#:
#: One minute per window means the per-minute budget never binds and active
#: blocks expire on schedule, so what is measured is the *decision*. The budget
#: is a real brake and its effect is reported separately rather than removed —
#: `budget_effect()` re-runs with a frozen clock and counts what it refuses.
REPLAY_SECONDS_PER_WINDOW = 60.0


class ReplayClock:
    """A monotonic clock that advances a fixed step per reading batch."""

    def __init__(self, step=REPLAY_SECONDS_PER_WINDOW):
        self.step = float(step)
        self.now = 0.0

    def __call__(self):
        return self.now

    def advance(self):
        self.now += self.step
        return self.now


def replay(samples, components, *, authority=None, classifier_authority=True,
           calibrator=None, clock=None, seconds_per_window=REPLAY_SECONDS_PER_WINDOW):
    """Replay every trusted row. Returns the window decisions and what was dropped.

    `seconds_per_window` spaces the decisions out in the authority's own clock.
    Pass `0` to freeze it, which is what P15.1 did and what makes the block
    budget dominate the result.
    """
    ticker = clock if clock is not None else ReplayClock(seconds_per_window)
    authority = authority or AutonomousDecisionAuthority(
        cost_policy=CostPolicy(), enabled=True, mode=AUTONOMOUS, clock=ticker)
    kept, dropped = trusted(samples)
    decisions = []
    for sample in kept:
        decisions.append(replay_sample(sample, components, authority=authority,
                                       classifier_authority=classifier_authority,
                                       calibrator=calibrator))
        advance = getattr(ticker, 'advance', None)
        if advance is not None:
            advance()
    return decisions, dropped


def window_outcomes(decisions):
    # The real site when the corpus declares one, the scenario family when it
    # does not. The fallback is what keeps every pre-P15.4 report reproducible
    # byte for byte while the newer corpora finally group by something that
    # means what the column is called.
    return [ev.Outcome(blocked=d.blocked, label=LABELS[d.label],
                       site_id=d.site_group or d.scenario_group,
                       score=d.conservative_probability,
                       label_source=d.label_source)
            for d in decisions]


def source_outcomes(decisions):
    """One row per source: blocked if any of its windows blocked.

    Refuses to score a source whose windows disagree about the label. That
    should not happen in a corpus with group-consistent scenarios, and if it
    ever does, silently picking one label would be inventing ground truth.
    """
    grouped = defaultdict(list)
    for decision in decisions:
        grouped[decision.source_group or decision.sample_id].append(decision)
    outcomes, conflicts = [], []
    for group, rows in sorted(grouped.items()):
        labels = {row.label for row in rows}
        if len(labels) != 1:
            conflicts.append(group)
            continue
        blocked = any(row.blocked for row in rows)
        outcomes.append(ev.Outcome(
            blocked=blocked,
            label=LABELS[rows[0].label],
            site_id=rows[0].site_group or rows[0].scenario_group,
            # The strongest estimate any window of this source reached, which is
            # the one the decision actually rested on.
            score=max(row.conservative_probability for row in rows),
            label_source=rows[0].label_source))
    return outcomes, conflicts


#: Each evidence stage the decision passes through, and how to read its score off
#: a window. `None` for a stage a window could not produce is excluded from that
#: stage's AUC rather than substituted with a number — a classifier that did not
#: answer has no opinion, and giving it 0.0 would invent one.
STAGES = (
    ('classifier model_score', lambda d: d.model_score),
    ('anomaly score', lambda d: d.anomaly_score),
    ('signal diversity', lambda d: float(d.signal_diversity)),
    ('MathRisk (raw)', lambda d: d.math_risk),
    ('conservative probability (what decides)',
     lambda d: d.conservative_probability),
    ('behavioural diversity', lambda d: float(d.behavioural_diversity)),
)


def ranking_breakdown(decisions):
    """ROC-AUC of every evidence stage, per window and per source.

    This answers a question the confusion matrix cannot: threshold aside, does
    the pipeline *order* scanners above ordinary traffic? A system that blocks
    nothing has a useless matrix and may still have a usable ordering, and the
    two findings have completely different repairs.

    Sources aggregate with **max**, matching `source_outcomes` and matching the
    system's own behaviour: a source is blocked if any of its windows blocks, so
    the strongest window is the one the decision rests on. The choice is stated
    because it changes the numbers — a mean would flatter a stage that is right
    once and quiet afterwards, which is exactly the shape a scanner has.
    """
    rows = {}
    for name, score_of in STAGES:
        windows, per_source = [], defaultdict(list)
        for decision in decisions:
            score = score_of(decision)
            if score is None:
                continue
            outcome = ev.Outcome(blocked=decision.blocked, label=LABELS[decision.label],
                                 site_id=decision.scenario_group, score=score,
                                 label_source=decision.label_source)
            windows.append(outcome)
            per_source[decision.source_group or decision.sample_id].append(outcome)
        sources = []
        for group, group_rows in sorted(per_source.items()):
            if len({row.label for row in group_rows}) != 1:
                continue
            best = max(group_rows, key=lambda row: row.score)
            sources.append(ev.Outcome(blocked=any(row.blocked for row in group_rows),
                                      label=best.label, site_id=best.site_id,
                                      score=best.score, label_source=best.label_source))
        rows[name] = {'scored_windows': len(windows),
                      'scored_sources': len(sources),
                      'per_window_roc_auc': ev.roc_auc(windows),
                      'per_source_roc_auc': ev.roc_auc(sources)}
    return rows


def summarise(decisions, dropped, *, components=None, thresholds=None, resamples=500):
    """Everything §7 asks for, at both the window and the source level."""
    windows = window_outcomes(decisions)
    sources, conflicts = source_outcomes(decisions)
    body = {
        'replay_schema_version': REPLAY_SCHEMA_VERSION,
        'rows_scored': len(decisions),
        'rows_dropped': dropped,
        'sources_scored': len(sources),
        'label_conflicts': conflicts,
        'per_window': ev.report(windows, thresholds=thresholds, resamples=resamples),
        'per_source': ev.report(sources, thresholds=thresholds, resamples=resamples),
        'ranking_breakdown': ranking_breakdown(decisions),
        'assumptions': [
            'every replayed source is directly connected: identity HIGH, '
            'network-enforceable, scope NETWORK_SOURCE. The identity gates that '
            'refuse a proxy client are switched off, so no block here was won by '
            'refusing to judge',
            'every source is replayed cold with offence_count 0, so no decision '
            'benefits from repeat-offender hysteresis',
            'labels come from the corpus and from nowhere else; rows whose label '
            'source is not a controlled scenario, a trusted fixture or a reviewed '
            'answer are dropped rather than scored',
            'the classifier is uncalibrated by its own manifest, so the '
            'deterministic engine carries the probability estimate',
        ],
    }
    if components is not None:
        body['classifier'] = {'answered': components.ml_answered,
                              'failed_or_absent': components.ml_failed,
                              'configured': components.classifier is not None}
        body['anomaly_loaded'] = components.anomaly is not None
        body['ood_reference_loaded'] = components.reference is not None
    return body


def scenario_breakdown(decisions):
    """Per scenario group: how many blocked, and what the label was.

    The number that matters most on a false-block metric is *which* benign
    scenario got blocked, not how many did. An aggregate hides a monitoring
    probe being blocked every time behind a thousand quiet windows.
    """
    grouped = defaultdict(lambda: {'rows': 0, 'blocked': 0, 'label': '', 'sources': set()})
    for decision in decisions:
        entry = grouped[decision.scenario_group or '(none)']
        entry['rows'] += 1
        entry['blocked'] += int(decision.blocked)
        entry['label'] = decision.label
        entry['sources'].add(decision.source_group)
    return {name: {'rows': entry['rows'], 'blocked_windows': entry['blocked'],
                   'label': entry['label'], 'sources': len(entry['sources'])}
            for name, entry in sorted(grouped.items())}
