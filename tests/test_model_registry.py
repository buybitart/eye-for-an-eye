"""P9 model lifecycle: registry, atomic promotion, rollback, promotion gate.

The properties defended here are the ones that make automatic training safe to
allow at all: a candidate starts with no authority, ACTIVE survives every
failure, and promotion is never a code path the system can take by itself.
"""
import json
from pathlib import Path
import pytest

from eye_for_an_eye.decision.features import INPUT_ORDER, SCHEMA_VERSION
from eye_for_an_eye.decision.promotion import (FAIL, KEEP_ACTIVE, NEED_MORE_DATA, PASS,
                                               PASS_WITH_WARNINGS, PROMOTE, REJECT,
                                               evaluate_gate, recommend)
from eye_for_an_eye.decision.registry import ACTIVE, CANDIDATE, ModelRegistry, RegistryError


def manifest(version, **overrides):
    payload = {'manifest_version': 1, 'model_version': version, 'model_family': 'logistic_regression',
               'feature_schema_version': SCHEMA_VERSION, 'training_dataset_version': 'dataset-v1',
               'parent_model': '', 'created_at': '2026-09-10T00:00:00+00:00',
               'recommended_mode': 'shadow', 'feature_order': list(INPUT_ORDER)}
    payload.update(overrides)
    return payload


def artifacts(version, *, model=b'onnx-bytes', **overrides):
    return {'classifier.onnx': model,
            'manifest.json': json.dumps(manifest(version, **overrides)).encode('utf-8'),
            'distribution.json': json.dumps({'distribution_version': 1}).encode('utf-8')}


@pytest.fixture
def registry(tmp_path):
    return ModelRegistry(tmp_path / 'models')


def seed_active(registry, version='risk-logreg-v1'):
    registry.register_candidate(version, artifacts(version))
    registry.promote(version, gate_passed=True, reason='initial')
    return version


# --- registry basics ------------------------------------------------------

def test_an_empty_registry_has_no_roles(registry):
    state = registry.state
    assert state.active is None and state.candidate is None and state.previous_active is None
    assert registry.list_versions() == []
    assert registry.resolve(ACTIVE) is None


def test_registering_a_candidate_gives_it_the_candidate_role_only(registry):
    registry.register_candidate('risk-logreg-v2', artifacts('risk-logreg-v2'))
    state = registry.state
    assert state.candidate == 'risk-logreg-v2'
    assert state.active is None, 'a candidate must never become active by being registered'
    assert registry.resolve(CANDIDATE)['version'] == 'risk-logreg-v2'


def test_model_versions_are_immutable(registry):
    registry.register_candidate('risk-logreg-v2', artifacts('risk-logreg-v2'))
    with pytest.raises(RegistryError, match='immutable'):
        registry.register_candidate('risk-logreg-v2', artifacts('risk-logreg-v2'))


def test_resolve_returns_usable_paths(registry):
    seed_active(registry)
    resolved = registry.resolve(ACTIVE)
    assert Path(resolved['model_path']).is_file()
    assert Path(resolved['manifest_path']).is_file()
    assert Path(resolved['distribution_path']).is_file()


def test_listing_reports_roles(registry):
    seed_active(registry, 'risk-logreg-v1')
    registry.register_candidate('risk-logreg-v2', artifacts('risk-logreg-v2'))
    roles = {v.version: v.role for v in registry.list_versions()}
    assert roles == {'risk-logreg-v1': ACTIVE, 'risk-logreg-v2': CANDIDATE}


# --- artifact validation (spec sections 92, 126) --------------------------

def test_a_mismatched_hash_is_refused(registry):
    bad = artifacts('risk-logreg-v2', sha256='0' * 64)
    with pytest.raises(RegistryError, match='SHA256'):
        registry.register_candidate('risk-logreg-v2', bad)
    assert not (registry.versions_dir / 'risk-logreg-v2').exists(), 'a rejected candidate leaves nothing'


def test_a_wrong_feature_schema_is_refused(registry):
    with pytest.raises(RegistryError, match='feature schema'):
        registry.register_candidate('risk-logreg-v2',
                                    artifacts('risk-logreg-v2', feature_schema_version=99))


def test_a_wrong_feature_order_is_refused(registry):
    with pytest.raises(RegistryError, match='feature order'):
        registry.register_candidate('risk-logreg-v2',
                                    artifacts('risk-logreg-v2', feature_order=['a', 'b']))


def test_a_manifest_naming_another_version_is_refused(registry):
    payload = artifacts('risk-logreg-v2')
    payload['manifest.json'] = json.dumps(manifest('something-else')).encode('utf-8')
    with pytest.raises(RegistryError, match='does not match the directory name'):
        registry.register_candidate('risk-logreg-v2', payload)


def test_an_empty_model_artifact_is_refused(registry):
    with pytest.raises(RegistryError, match='size'):
        registry.register_candidate('risk-logreg-v2', artifacts('risk-logreg-v2', model=b''))


def test_a_missing_manifest_is_refused(registry):
    payload = artifacts('risk-logreg-v2')
    del payload['manifest.json']
    with pytest.raises(RegistryError, match='manifest.json is missing'):
        registry.register_candidate('risk-logreg-v2', payload)


@pytest.mark.parametrize('version', ['../escape', 'a/b', '', 'x' * 200, 'bad name'])
def test_path_traversal_and_bad_names_are_refused(registry, version):
    with pytest.raises(RegistryError):
        registry.register_candidate(version, artifacts('x'))


# --- promotion (spec sections 50, 55, 84) ---------------------------------

def test_promotion_requires_a_passing_gate(registry):
    registry.register_candidate('risk-logreg-v2', artifacts('risk-logreg-v2'))
    with pytest.raises(RegistryError, match='quality gate'):
        registry.promote('risk-logreg-v2', gate_passed=False)
    assert registry.state.active is None


def test_promotion_records_the_previous_active(registry):
    seed_active(registry, 'risk-logreg-v1')
    registry.register_candidate('risk-logreg-v2', artifacts('risk-logreg-v2'))
    state = registry.promote('risk-logreg-v2', gate_passed=True, reason='operator approved')
    assert state.active == 'risk-logreg-v2'
    assert state.previous_active == 'risk-logreg-v1'
    assert state.candidate is None, 'a promoted candidate is no longer a candidate'


def test_promoting_an_unregistered_version_is_refused(registry):
    with pytest.raises(RegistryError, match='not a registered model version'):
        registry.promote('never-existed', gate_passed=True)


def test_promotion_is_a_single_pointer_write(registry):
    """The version directories are untouched, so there is no half-written state."""
    seed_active(registry, 'risk-logreg-v1')
    registry.register_candidate('risk-logreg-v2', artifacts('risk-logreg-v2'))
    before = {p.name: p.stat().st_mtime_ns for p in (registry.versions_dir / 'risk-logreg-v1').iterdir()}
    registry.promote('risk-logreg-v2', gate_passed=True)
    after = {p.name: p.stat().st_mtime_ns for p in (registry.versions_dir / 'risk-logreg-v1').iterdir()}
    assert before == after


# --- rollback (spec sections 51, 75, 92) ----------------------------------

def test_rollback_restores_the_previous_active(registry):
    seed_active(registry, 'risk-logreg-v1')
    registry.register_candidate('risk-logreg-v2', artifacts('risk-logreg-v2'))
    registry.promote('risk-logreg-v2', gate_passed=True)
    state = registry.rollback(reason='regression found in production')
    assert state.active == 'risk-logreg-v1'
    assert state.previous_active == 'risk-logreg-v2', 'rollback is itself reversible'
    assert Path(registry.resolve(ACTIVE)['model_path']).is_file()


def test_rollback_survives_a_restart(registry, tmp_path):
    seed_active(registry, 'risk-logreg-v1')
    registry.register_candidate('risk-logreg-v2', artifacts('risk-logreg-v2'))
    registry.promote('risk-logreg-v2', gate_passed=True)
    reopened = ModelRegistry(tmp_path / 'models')          # simulate a service restart
    reopened.rollback()
    assert ModelRegistry(tmp_path / 'models').state.active == 'risk-logreg-v1'


def test_rollback_without_history_is_refused(registry):
    seed_active(registry)
    with pytest.raises(RegistryError, match='no previous active'):
        registry.rollback()


def test_the_active_and_its_fallback_are_never_prunable(registry):
    seed_active(registry, 'risk-logreg-v1')
    registry.register_candidate('risk-logreg-v2', artifacts('risk-logreg-v2'))
    registry.promote('risk-logreg-v2', gate_passed=True)
    registry.register_candidate('risk-logreg-v3', artifacts('risk-logreg-v3'))
    prunable = registry.prunable()
    assert 'risk-logreg-v2' not in prunable and 'risk-logreg-v1' not in prunable
    assert 'risk-logreg-v3' not in prunable


def test_rejecting_a_candidate_keeps_the_active_model(registry):
    seed_active(registry, 'risk-logreg-v1')
    registry.register_candidate('risk-logreg-v2', artifacts('risk-logreg-v2'))
    state = registry.reject_candidate(reason='hard negative regression')
    assert state.candidate is None and state.active == 'risk-logreg-v1'


# --- audit (spec section 77) ----------------------------------------------

def test_every_lifecycle_event_is_audited(registry):
    seed_active(registry, 'risk-logreg-v1')
    registry.register_candidate('risk-logreg-v2', artifacts('risk-logreg-v2'))
    registry.promote('risk-logreg-v2', gate_passed=True)
    registry.rollback()
    events = [entry['event'] for entry in registry.state.audit]
    assert events == ['candidate_registered', 'promoted', 'candidate_registered',
                      'promoted', 'rolled_back']
    assert all('at' in entry for entry in registry.state.audit)


# --- promotion gate (spec sections 47, 53, 54, 55) ------------------------

def good_candidate(**overrides):
    payload = {'feature_schema_version': SCHEMA_VERSION, 'onnx_parity_max_abs_error': 1e-8,
               'model_size_bytes': 1024, 'dataset_validation_passed': True,
               'group_split_verified': True, 'block_precision': 0.95,
               'false_blocks_per_1000_benign': 1.0, 'hard_negative_false_block_rate': 0.001,
               'hard_positive_recall': 0.80, 'inference_p95_ms': 1.0, 'pr_auc': 0.94}
    payload.update(overrides)
    return payload


def good_active(**overrides):
    payload = {'feature_schema_version': SCHEMA_VERSION, 'block_precision': 0.94,
               'false_blocks_per_1000_benign': 1.2, 'hard_negative_false_block_rate': 0.002,
               'hard_positive_recall': 0.78, 'inference_p95_ms': 1.0, 'pr_auc': 0.93}
    payload.update(overrides)
    return payload


def test_a_clean_candidate_passes():
    result = evaluate_gate(candidate=good_candidate(), active=good_active())
    assert result.status == PASS and result.passed and not result.failures


def test_a_hard_negative_regression_blocks_promotion():
    result = evaluate_gate(candidate=good_candidate(hard_negative_false_block_rate=0.9),
                           active=good_active())
    assert result.status == FAIL
    assert 'hard_negatives' in {c.name for c in result.failures}


def test_more_false_blocks_blocks_promotion():
    result = evaluate_gate(candidate=good_candidate(false_blocks_per_1000_benign=9.0),
                           active=good_active())
    assert result.status == FAIL
    assert 'false_blocks' in {c.name for c in result.failures}


def test_a_better_f1_does_not_override_a_safety_regression():
    """The single-metric promotion this project must never do."""
    result = evaluate_gate(candidate=good_candidate(pr_auc=0.99, block_precision=0.10),
                           active=good_active())
    assert result.status == FAIL, 'a better headline metric cannot buy a safety regression'


def test_failed_onnx_parity_blocks_promotion():
    assert evaluate_gate(candidate=good_candidate(onnx_parity_max_abs_error=0.5),
                         active=good_active()).status == FAIL


def test_an_unvalidated_dataset_blocks_promotion():
    assert evaluate_gate(candidate=good_candidate(dataset_validation_passed=False),
                         active=good_active()).status == FAIL


def test_a_row_split_blocks_promotion():
    assert evaluate_gate(candidate=good_candidate(group_split_verified=False),
                         active=good_active()).status == FAIL


def test_an_unmeasured_metric_is_never_treated_as_an_improvement():
    result = evaluate_gate(candidate=good_candidate(block_precision=None), active=good_active())
    assert result.status == FAIL
    assert 'unknown' in ' '.join(c.detail for c in result.failures)


def test_a_latency_regression_is_a_warning_not_a_block():
    result = evaluate_gate(candidate=good_candidate(inference_p95_ms=1.9), active=good_active())
    assert result.status == PASS
    result = evaluate_gate(candidate=good_candidate(inference_p95_ms=50.0), active=good_active())
    assert result.status == PASS_WITH_WARNINGS and not result.passed


# --- recommendation (spec sections 62, 63) --------------------------------

def shadow(**overrides):
    payload = {'feature_vectors': 5000, 'candidate_would_block_active_would_not': 0}
    payload.update(overrides)
    return payload


def test_a_clean_candidate_with_enough_shadow_data_is_recommended():
    gate = evaluate_gate(candidate=good_candidate(), active=good_active())
    result = recommend(gate=gate, candidate_version='risk-logreg-v2',
                       active_version='risk-logreg-v1', shadow=shadow())
    assert result.decision == PROMOTE
    assert result.auto_promote is False
    assert any('manual step' in reason for reason in result.reasons)


def test_a_failed_gate_is_rejected():
    gate = evaluate_gate(candidate=good_candidate(hard_negative_false_block_rate=0.9),
                         active=good_active())
    assert recommend(gate=gate, candidate_version='v2', shadow=shadow()).decision == REJECT


def test_too_little_shadow_data_asks_for_more():
    gate = evaluate_gate(candidate=good_candidate(), active=good_active())
    result = recommend(gate=gate, candidate_version='v2', shadow=shadow(feature_vectors=10))
    assert result.decision == NEED_MORE_DATA


def test_new_blocking_behaviour_holds_promotion_back():
    gate = evaluate_gate(candidate=good_candidate(), active=good_active())
    result = recommend(gate=gate, candidate_version='v2',
                       shadow=shadow(candidate_would_block_active_would_not=3))
    assert result.decision == KEEP_ACTIVE
    assert any('would block 3 sources' in reason for reason in result.reasons)


def test_warnings_require_a_person():
    gate = evaluate_gate(candidate=good_candidate(inference_p95_ms=50.0), active=good_active())
    result = recommend(gate=gate, candidate_version='v2', shadow=shadow())
    assert result.decision == KEEP_ACTIVE


def test_the_recommendation_changes_nothing(registry):
    """The regression test for auto-promotion: advice never moves the pointer."""
    seed_active(registry, 'risk-logreg-v1')
    registry.register_candidate('risk-logreg-v2', artifacts('risk-logreg-v2'))
    gate = evaluate_gate(candidate=good_candidate(), active=good_active())
    result = recommend(gate=gate, candidate_version='risk-logreg-v2',
                       active_version='risk-logreg-v1', shadow=shadow())
    assert result.decision == PROMOTE
    assert registry.state.active == 'risk-logreg-v1', 'ACTIVE must be unchanged by a recommendation'
    assert registry.state.candidate == 'risk-logreg-v2'


def test_there_is_no_auto_promote_code_path():
    """Stronger than a default: the capability does not exist."""
    import eye_for_an_eye.decision.promotion as module
    source = Path(module.__file__).read_text(encoding='utf-8')
    assert 'auto_promote = True' not in source
    for name in dir(module):
        assert 'auto_promote' not in name.lower() or name == 'PromotionRecommendation'
