"""Fusion and deterministic gates. A model never grants firewall authority."""
from dataclasses import dataclass
import ipaddress
import math
from ..compatibility import FEATURE_SCHEMA
from .features import NAMES, completeness as feature_completeness

ACTIONS = ('OBSERVE', 'WATCH', 'RATE_LIMIT', 'TEMP_BLOCK')

#: The reduction algorithm in `PolicyGuard.apply`: which conditions may weaken an
#: action, the protected-address classes that refuse one outright, and the rule
#: that none of it can ever raise an action. Named for the same reason
#: `autonomy.authority.AUTHORITY_VERSION` is — a decision record read six months
#: later has to be interpretable against the arithmetic that produced it, and
#: "PolicyGuard refused" means nothing without knowing which PolicyGuard.
POLICY_GUARD_VERSION = 'policy-guard-v1'


def usable_ml(result):
    """A classifier answer this build can act on.

    The schema check used to pin the literal 1, which stopped meaning "a schema
    we understand" the moment a column was appended: every healthy prediction
    became unusable, and the fusion silently fell back to the deterministic
    engine alone. P15.4 fixed it here and missed the identical line in
    `autonomy/authority.py`, which is why the question is now asked of one
    contract rather than re-expressed at each call site (P15.5 §3).
    """
    return (result.status == 'healthy' and FEATURE_SCHEMA.supports(result.feature_schema_version) and
        all(type(v) in (int, float) and math.isfinite(v) and 0 <= v <= 1 for v in (result.risk_score, result.confidence)))


@dataclass(frozen=True, slots=True)
class EvidenceResult:
    """P8 fusion output: how suspicious, and how much that judgement can be trusted.

    ThreatEvidence and DecisionConfidence are kept apart on purpose. Merging them
    into one number hides the difference between "this is probably an attack" and
    "I do not have enough evidence to say".
    """
    threat_evidence: float
    decision_confidence: float
    reliable_risk: float
    math_contribution: float
    ml_contribution: float
    persistence_contribution: float
    distribution_confidence: float
    model_confidence: float
    anomaly_contribution: float = 0.0
    anomaly_score: float | None = None
    fusion_version: str = 'decision-fusion-v2'

    def explain(self):
        return {'fusion_version': self.fusion_version,
                'threat_evidence': round(self.threat_evidence, 6),
                'decision_confidence': round(self.decision_confidence, 6),
                'reliable_risk': round(self.reliable_risk, 6),
                'math_contribution': round(self.math_contribution, 6),
                'ml_contribution': round(self.ml_contribution, 6),
                'persistence_contribution': round(self.persistence_contribution, 6),
                'distribution_confidence': round(self.distribution_confidence, 6),
                'model_confidence': round(self.model_confidence, 6),
                'anomaly_contribution': round(self.anomaly_contribution, 6),
                'anomaly_score': None if self.anomaly_score is None else round(self.anomaly_score, 6)}


class DecisionFusion:
    def __init__(self, config):
        self.config = config

    def evaluate(self, math_result, ml, persistence, *, distribution_confidence=1.0, anomaly=None):
        """Fuse the evidence and report how much of it is trustworthy.

        `distribution_confidence` is 1 - OODScore, or 1.0 when no reference
        distribution is configured. It can only shrink the classifier's share,
        which then returns to the deterministic mathematical engine.
        """
        c = self.config
        confidence = ml.confidence if usable_ml(ml) else 0.0
        model_confidence = max(0.0, 2 * confidence - 1) if usable_ml(ml) else 0.0
        bounded = min(1.0, max(0.0, distribution_confidence))
        trust = model_confidence * bounded
        # Anomaly evidence is carved out of the maths+ML pool, never added on
        # top. With no anomaly model the scale is 1.0 and the arithmetic is
        # byte-for-byte what it was before this component existed.
        anomaly_score = anomaly.anomaly_score if (anomaly is not None and anomaly.usable) else None
        pool = c.math_weight + c.ml_weight
        anomaly_weight = getattr(c, 'anomaly_weight', 0.0) if anomaly_score is not None else 0.0
        anomaly_weight = min(anomaly_weight, pool)
        scale = (pool - anomaly_weight) / pool if pool > 0 else 0.0
        weight = c.ml_weight * scale * trust
        math_share = (pool * scale - weight) * math_result.score
        ml_share = weight * ml.risk_score if weight else 0.0
        anomaly_share = anomaly_weight * anomaly_score if anomaly_score is not None else 0.0
        persistence_share = c.persistence_weight * persistence
        evidence = min(1.0, max(0.0, math_share + ml_share + anomaly_share + persistence_share))
        # With no usable classifier the deterministic engine carries the decision
        # on its own, so distribution distance must not discount it.
        decision_confidence = bounded if usable_ml(ml) else 1.0
        return EvidenceResult(threat_evidence=evidence, decision_confidence=decision_confidence,
            reliable_risk=min(1.0, max(0.0, evidence * decision_confidence)),
            math_contribution=math_share, ml_contribution=ml_share,
            persistence_contribution=persistence_share, distribution_confidence=bounded,
            model_confidence=model_confidence, anomaly_contribution=anomaly_share,
            anomaly_score=anomaly_score)

    def combine(self, math_result, ml, persistence, *, distribution_confidence=1.0, anomaly=None):
        """Backward-compatible scalar risk. Identical to P7 with no OOD or anomaly signal."""
        return self.evaluate(math_result, ml, persistence, anomaly=anomaly,
                             distribution_confidence=distribution_confidence).threat_evidence

    def state(self, risk, previous='OBSERVE'):
        thresholds = (self.config.watch_threshold, self.config.rate_limit_threshold, self.config.block_threshold)
        level = sum(risk >= threshold for threshold in thresholds)
        prior = ACTIONS.index(previous)
        if prior > level and risk >= thresholds[prior - 1] - self.config.hysteresis_margin:
            level = prior
        return ACTIONS[level]


@dataclass(frozen=True, slots=True)
class DataQualityResult:
    score: float
    categories: int
    completeness: float
    loss_known: bool

    @classmethod
    def evaluate(cls, vector):
        f = dict(zip(NAMES, vector.values))
        categories = sum((
            (f['ports_60s'] or 0) >= 8,
            (f['anomaly_60s'] or 0) >= .2,
            (f['credentials_60s'] or 0) >= 3,
            (f['continuation_60s'] or 0) >= .15 and (f['persistence_900s'] or 0) >= 5,
        ))
        # Applicable features only. A source that never authenticated has no
        # authentication outcome to be *missing*, and treating its silence as a
        # gap would lower the data quality of every ordinary visitor — tightening
        # a safety gate by accident and for no reason anybody chose. See
        # `features.CONDITIONAL_GROUPS`.
        completeness = feature_completeness(vector.values)
        score = (min(1, vector.sample_count / 20) * .35 + min(1, vector.observation_seconds / 5) * .25 +
                 completeness * .25 + min(1, categories / 3) * .15)
        score *= (1 - vector.loss_fraction) if vector.loss_fraction is not None else .65
        if vector.capped:
            score = min(score, .49)
        return cls(score, categories, completeness, vector.loss_fraction is not None)


class PolicyGuard:
    def __init__(self, config):
        self.config = config
        e = config.enforcement
        self.networks = tuple(ipaddress.ip_network(n) for n in (*e.management_networks, *e.allowlist, *e.trusted_proxies))

    def protected(self, source, local_addresses=()):
        ip = ipaddress.ip_address(source)
        # IPv4 mapped IPv6 is the same source for protection purposes.
        if getattr(ip, 'ipv4_mapped', None):
            ip = ip.ipv4_mapped
        locals_set = {ipaddress.ip_address(v) for v in local_addresses}
        return (ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip in locals_set or
                any(ip.version == network.version and ip in network for network in self.networks))

    def apply(self, action, vector, math_result, ml, *, source, healthy=True, local_addresses=(),
              ood=None, model_health=None, evidence=None):
        """Reduce an action to what the evidence supports. It can never raise one.

        P8 adds three refusals, all of which only ever weaken a decision:
        an observation far outside the training distribution, a model that is no
        longer healthy, and a fused risk whose confidence is low.
        """
        c = self.config.decision
        reliability = getattr(self.config, 'reliability', None)
        quality = DataQualityResult.evaluate(vector)
        reasons = []
        if self.protected(source, local_addresses):
            return 'OBSERVE', ['protected_source'], quality
        if not healthy:
            reasons.append('sensor_health')
        if quality.score < c.minimum_quality:
            reasons.append('insufficient_data_quality')
        if vector.sample_count < c.minimum_samples_for_block:
            reasons.append('minimum_samples')
        if vector.observation_seconds < c.minimum_observation_seconds:
            reasons.append('minimum_duration')
        if quality.categories < c.minimum_categories:
            reasons.append('independent_behavior_categories')
        if math_result.score < c.minimum_math_risk:
            reasons.append('math_confirmation')
        if usable_ml(ml) and ml.confidence < c.minimum_ml_confidence:
            reasons.append('low_ml_confidence')
        if usable_ml(ml) and math_result.score >= .8 and ml.risk_score <= .2:
            reasons.append('model_disagreement')
        # An unusual input is not an attack. It means the classifier knows less,
        # so the classifier may not drive a strong action here.
        if (ood is not None and getattr(ood, 'status', '') == 'OUT_OF_DISTRIBUTION'
                and (reliability is None or reliability.ood_suppresses_block)):
            reasons.append('out_of_distribution')
        # Drift and a high population OOD rate are model health, not source guilt.
        # They withdraw the classifier's authority; the maths engine keeps working.
        if (model_health is not None and not model_health.allows_ml_enforcement
                and (reliability is None or reliability.degraded_model_suppresses_block)
                and usable_ml(ml) and math_result.score < c.minimum_math_risk):
            reasons.append('model_health_' + model_health.state.lower())
        if action in ('RATE_LIMIT', 'TEMP_BLOCK') and reasons:
            action = 'WATCH'
        return action, reasons, quality
