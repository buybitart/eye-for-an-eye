"""P9 promotion gate and recommendation.

Three authorities are kept apart on purpose:

* Training may create a candidate.
* Evaluation may judge its quality.
* Deployment may change ACTIVE.

Nothing in this module changes ACTIVE. It produces a verdict and a
recommendation, and the separation of the three authorities above is what makes
that safe.

Through P13 this docstring added that `auto_promote` did not exist as a code
path at all. P14 changes that: `eye_for_an_eye/governance/` can act on a verdict
when an operator has switched it on. The guarantee this module still offers is
narrower and worth stating exactly — **nothing here promotes anything**. The
governance engine reads assessments, not this module's recommendations, and it
accepts only a record whose every gate passed. A bug in this file can advise
badly; it cannot activate a model.
"""
from dataclasses import dataclass, field

PASS = 'PASS'
PASS_WITH_WARNINGS = 'PASS_WITH_WARNINGS'
FAIL = 'FAIL'

PROMOTE = 'PROMOTE'
KEEP_ACTIVE = 'KEEP_ACTIVE'
REJECT = 'REJECT'
NEED_MORE_DATA = 'NEED_MORE_DATA'

BLOCKING = 'blocking'
WARNING = 'warning'

# Provisional tolerances. They are configurable and are NOT calibrated against a
# real deployment. They are stated as a starting point, not as science.
DEFAULTS = {
    'max_block_precision_drop': 0.02,
    'max_false_block_increase_per_1000': 0.5,
    'max_hard_negative_regression': 0.01,
    'max_hard_positive_recall_drop': 0.05,
    'max_latency_increase_ratio': 2.0,
    'max_model_size_bytes': 33_554_432,
    'max_onnx_parity_error': 1e-5,
    'minimum_shadow_samples': 500,
}


@dataclass(frozen=True, slots=True)
class GateCheck:
    name: str
    severity: str
    passed: bool
    detail: str
    active_value: float | None = None
    candidate_value: float | None = None

    def explain(self):
        return {'check': self.name, 'severity': self.severity, 'passed': self.passed,
                'detail': self.detail, 'active': self.active_value, 'candidate': self.candidate_value}


@dataclass(frozen=True, slots=True)
class GateResult:
    status: str
    checks: tuple[GateCheck, ...] = field(default_factory=tuple)

    @property
    def passed(self):
        """Only a clean pass authorises promotion. Warnings need a human."""
        return self.status == PASS

    @property
    def failures(self):
        return tuple(c for c in self.checks if not c.passed and c.severity == BLOCKING)

    @property
    def warnings(self):
        return tuple(c for c in self.checks if not c.passed and c.severity == WARNING)

    def explain(self):
        return {'status': self.status,
                'blocking_failures': [c.explain() for c in self.failures],
                'warnings': [c.explain() for c in self.warnings],
                'checks': [c.explain() for c in self.checks],
                'note': 'a passing gate authorises nothing by itself'}


def _check(name, severity, passed, detail, active=None, candidate=None):
    return GateCheck(name=name, severity=severity, passed=passed, detail=detail,
                     active_value=active, candidate_value=candidate)


def evaluate_gate(*, candidate, active=None, thresholds=None):
    """Compare a candidate with the active model across every dimension that matters.

    `candidate` and `active` are metric mappings. A missing metric is reported
    as an unknown, never silently treated as an improvement.
    """
    limits = {**DEFAULTS, **(thresholds or {})}
    checks = []

    schema_ok = candidate.get('feature_schema_version') == (
        active.get('feature_schema_version') if active else candidate.get('feature_schema_version'))
    checks.append(_check('feature_schema_compatible', BLOCKING, bool(schema_ok),
                         'the candidate must use the active feature schema'))

    parity = candidate.get('onnx_parity_max_abs_error')
    checks.append(_check('onnx_parity', BLOCKING,
                         parity is not None and parity <= limits['max_onnx_parity_error'],
                         'ONNX output must match the training model', candidate=parity))

    size = candidate.get('model_size_bytes')
    checks.append(_check('model_size', BLOCKING,
                         size is not None and 0 < size <= limits['max_model_size_bytes'],
                         'model artifact size must be within the configured bound', candidate=size))

    checks.append(_check('dataset_validation', BLOCKING, bool(candidate.get('dataset_validation_passed')),
                         'the training dataset must have passed validation'))
    checks.append(_check('no_group_leakage', BLOCKING, bool(candidate.get('group_split_verified')),
                         'the split must be by group, never by row'))

    if active:
        a, c = active.get('block_precision'), candidate.get('block_precision')
        if a is None or c is None:
            checks.append(_check('block_precision', BLOCKING, False,
                                 'block precision is unknown for one of the models', a, c))
        else:
            checks.append(_check('block_precision', BLOCKING,
                                 c >= a - limits['max_block_precision_drop'],
                                 'the candidate must not block less precisely than the active model', a, c))

        a, c = active.get('false_blocks_per_1000_benign'), candidate.get('false_blocks_per_1000_benign')
        if a is None or c is None:
            checks.append(_check('false_blocks', BLOCKING, False,
                                 'false-block rate is unknown for one of the models', a, c))
        else:
            checks.append(_check('false_blocks', BLOCKING,
                                 c <= a + limits['max_false_block_increase_per_1000'],
                                 'the candidate must not block more benign sources', a, c))

        a, c = active.get('hard_negative_false_block_rate'), candidate.get('hard_negative_false_block_rate')
        if a is not None and c is not None:
            checks.append(_check('hard_negatives', BLOCKING,
                                 c <= a + limits['max_hard_negative_regression'],
                                 'monitoring, proxies and backups must not start being blocked', a, c))
        else:
            checks.append(_check('hard_negatives', BLOCKING, False,
                                 'hard-negative behaviour was not measured', a, c))

        a, c = active.get('hard_positive_recall'), candidate.get('hard_positive_recall')
        if a is not None and c is not None:
            checks.append(_check('hard_positives', WARNING,
                                 c >= a - limits['max_hard_positive_recall_drop'],
                                 'the candidate must not buy precision by ignoring difficult scanners', a, c))

        a, c = active.get('inference_p95_ms'), candidate.get('inference_p95_ms')
        if a and c:
            checks.append(_check('inference_latency', WARNING,
                                 c <= a * limits['max_latency_increase_ratio'],
                                 'inference must stay within the latency budget', a, c))

        for name, key, higher_is_better in (('pr_auc', 'pr_auc', True), ('roc_auc', 'roc_auc', True),
                                            ('calibration_error', 'calibration_error', False)):
            a, c = active.get(key), candidate.get(key)
            if a is None or c is None:
                continue
            better = c >= a if higher_is_better else c <= a
            checks.append(_check(name, WARNING, better,
                                 f'{name} should not regress against the active model', a, c))
    else:
        checks.append(_check('active_comparison', WARNING, False,
                             'there is no active model to compare against'))

    if any(not c.passed and c.severity == BLOCKING for c in checks):
        status = FAIL
    elif any(not c.passed for c in checks):
        status = PASS_WITH_WARNINGS
    else:
        status = PASS
    return GateResult(status=status, checks=tuple(checks))


@dataclass(frozen=True, slots=True)
class PromotionRecommendation:
    """The output of evaluation. It is advice; it changes nothing."""
    decision: str
    gate_status: str
    reasons: tuple[str, ...] = field(default_factory=tuple)
    candidate_version: str = ''
    active_version: str = ''
    shadow_samples: int = 0
    auto_promote: bool = False

    def explain(self):
        return {'decision': self.decision, 'gate_status': self.gate_status,
                'reasons': list(self.reasons), 'candidate': self.candidate_version,
                'active': self.active_version, 'shadow_samples': self.shadow_samples,
                'auto_promote': self.auto_promote,
                'note': 'promotion is explicit; nothing here changes the active model'}


def recommend(*, gate, candidate_version, active_version='', shadow=None, thresholds=None):
    """Turn a gate result and a shadow comparison into one of four recommendations."""
    limits = {**DEFAULTS, **(thresholds or {})}
    shadow = shadow or {}
    samples = int(shadow.get('feature_vectors', 0))
    reasons = []

    if gate.status == FAIL:
        reasons.extend(f'{c.name}: {c.detail}' for c in gate.failures)
        return PromotionRecommendation(decision=REJECT, gate_status=gate.status, reasons=tuple(reasons),
                                       candidate_version=candidate_version, active_version=active_version,
                                       shadow_samples=samples)

    if samples < limits['minimum_shadow_samples']:
        reasons.append(f'shadow comparison has {samples} observations, '
                       f'{limits["minimum_shadow_samples"]} required')
        return PromotionRecommendation(decision=NEED_MORE_DATA, gate_status=gate.status,
                                       reasons=tuple(reasons), candidate_version=candidate_version,
                                       active_version=active_version, shadow_samples=samples)

    # A candidate that would block traffic the active model allows is the single
    # most expensive way to be wrong, so it holds promotion back on its own.
    new_blocks = shadow.get('candidate_would_block_active_would_not', 0)
    if new_blocks:
        reasons.append(f'the candidate would block {new_blocks} sources the active model allows; '
                       'review those before promoting')
        return PromotionRecommendation(decision=KEEP_ACTIVE, gate_status=gate.status,
                                       reasons=tuple(reasons), candidate_version=candidate_version,
                                       active_version=active_version, shadow_samples=samples)

    if gate.status == PASS_WITH_WARNINGS:
        reasons.extend(f'{c.name}: {c.detail}' for c in gate.warnings)
        reasons.append('a person should read the warnings before promoting')
        return PromotionRecommendation(decision=KEEP_ACTIVE, gate_status=gate.status,
                                       reasons=tuple(reasons), candidate_version=candidate_version,
                                       active_version=active_version, shadow_samples=samples)

    reasons.append('every blocking check passed and no new blocking behaviour appeared in shadow')
    reasons.append('promotion is still a manual step: eye-for-an-eye model promote <version>')
    return PromotionRecommendation(decision=PROMOTE, gate_status=gate.status, reasons=tuple(reasons),
                                   candidate_version=candidate_version, active_version=active_version,
                                   shadow_samples=samples)
