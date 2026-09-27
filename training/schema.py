"""Frozen risk-logreg-v1 model feature contract.

The contract itself lives in `dataset.schema`, which is upstream of training: the dataset
declares which of its columns may reach a model and why every other column may not. This
module re-exports it and adds only what belongs to a fitted model - the model version and
the ablation groups - so there is one definition, not two.
"""
from dataset.schema import (  # noqa: F401  re-exported contract
    AVAILABILITY_FEATURES, BEHAVIOUR_FEATURES as BEHAVIOR_FEATURES, EXCLUDED_FROM_MODEL as EXCLUDED_FEATURES,
    EXCLUDED_INDEX, FEATURE_DTYPE, FEATURE_RANGE, FEATURE_SCHEMA_VERSION, FINGERPRINT_DERIVED,
    LABEL_MEANING, MISSING_POLICY, MODEL_FEATURES, MODEL_INDEX, NEVER_MODEL_INPUT,
    expand, feature_names_for, model_features_for, select)
from dataset.schema import MALICIOUS as POSITIVE_CLASS
from eye_for_an_eye.decision.features import INPUT_ORDER, NAMES

MODEL_VERSION = 'risk-logreg-v1'
FEATURE_CONTRACT_VERSION = 1

# Dataset bookkeeping columns: required in a training file, forbidden in the fitted matrix.
GROUP_COLUMNS = ('sample_id', 'feature_schema_version', 'timestamp', 'scenario_id', 'scenario_group',
                 'source_group', 'split', 'label', 'label_source')
FORBIDDEN_FEATURES = frozenset(NEVER_MODEL_INPUT) | frozenset((
    'ip', 'ip_numeric', 'as_number', 'region', 'user_agent', 'split', 'source_ip'))

LABEL_NAMES = {0: 'benign_like', 1: POSITIVE_CLASS}
# synthetic-behavior-v3 predates the dataset-phase vocabulary and stays on its own frozen
# values, because a shipped model manifest records that dataset version as its provenance.
ALLOWED_LABEL_SOURCES = ('synthetic_scenario', 'controlled_lab', 'manual_review', 'trusted_labeled_dataset',
                         'controlled_scenario', 'trusted_fixture', 'synthetic_generator')
# Values emitted by superseded corpora, listed so the mismatch is a stated fact
# rather than a surprise. `training/build_dataset.py` (the frozen P7 v2 generator,
# kept only so `research-v2` stays byte-reproducible) writes the value below, and
# it is deliberately NOT in ALLOWED_LABEL_SOURCES: `validation.py` must reject a
# v2 corpus offered to the current pipeline rather than accept rows whose
# provenance conventions it was never written for. Widening the accepted tuple to
# silence the mismatch would weaken a gate to tidy a name.
LEGACY_LABEL_SOURCES = ('synthetic_scenario_intent_not_observed_verdict',)
FORBIDDEN_LABEL_SOURCES = ('blocked', 'automatically_blocked', 'risk_threshold', 'ml_score', 'final_risk',
                           'firewall', 'decision', 'previous_model', 'shadow_decision', 'math_score',
                           'self_labelled')

# Counter the sensor itself influences by choosing to answer; ablated separately.
ENGINE_INFLUENCED = ('deception_60s', 'available_deception_60s')
ABLATIONS = {
    'all_model_features': MODEL_FEATURES,
    'behaviour_only_no_masks': BEHAVIOR_FEATURES,
    'no_engine_influenced_deception': tuple(n for n in MODEL_FEATURES if n not in ENGINE_INFLUENCED),
}

if set(MODEL_FEATURES) & FORBIDDEN_FEATURES or len(MODEL_FEATURES) != len(INPUT_ORDER) - len(EXCLUDED_FEATURES):
    raise RuntimeError('model feature contract violates its own exclusion list')
if len(NAMES) * 2 != len(INPUT_ORDER):
    raise RuntimeError('unexpected feature schema layout')
