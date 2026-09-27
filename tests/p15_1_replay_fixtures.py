"""Small, explicit rows for the replay-harness tests.

Kept out of the test module so the tests read as statements about behaviour
rather than as dataclass construction. Every value here is arbitrary except the
one the calling test varies.
"""
from datetime import UTC, datetime

from dataset.schema import DatasetSample
from eye_for_an_eye.decision.features import NAMES, SCHEMA_VERSION, FeatureVector
from training.decision_replay import WindowDecision

#: Which column `sample()` varies. Any feature would do; port breadth is the one
#: a reader of these tests will expect to tell a scan from a visit.
PORT_BREADTH = NAMES.index('ports_60s')


def vector(port_breadth=1.0, seconds=60.0, sample_count=12):
    values = [0.0] * len(NAMES)
    values[PORT_BREADTH] = port_breadth
    return FeatureVector(tuple(values), seconds, sample_count, False, 0.0)


def sample(sample_id, *, label='benign_like', label_source='controlled_scenario',
           port_breadth=1.0, seconds=60.0, source_group=None,
           scenario_group='group', source_type='LAB', confidence='HIGH'):
    return DatasetSample(
        dataset_version='test-v1',
        feature_schema_version=SCHEMA_VERSION,
        sample_id=sample_id,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        source_type=source_type,
        scenario_group=scenario_group,
        source_group=source_group or sample_id,
        capture_group=None,
        label=label,
        label_source=label_source,
        label_confidence=confidence,
        features=vector(port_breadth, seconds))


def window(source_group, *, label='benign_like', blocked=False, probability=0.0,
           math_risk=0.5, model_score=0.5, anomaly_score=0.5, signal_diversity=1,
           behavioural_diversity=1, scenario_group='group'):
    return WindowDecision(
        sample_id=f'{source_group}-{probability}-{math_risk}',
        source_group=source_group,
        scenario_group=scenario_group,
        source_type='LAB',
        label=label,
        label_source='controlled_scenario',
        action='TEMP_BLOCK' if blocked else 'ALLOW',
        blocked=blocked,
        conservative_probability=probability,
        math_risk=math_risk,
        model_score=model_score,
        anomaly_score=anomaly_score,
        ood_status='IN_DISTRIBUTION',
        data_quality=1.0,
        signal_diversity=signal_diversity,
        behavioural_diversity=behavioural_diversity,
        reason_codes=(),
        policy_guard_action='TEMP_BLOCK' if blocked else 'ALLOW',
        block_ttl_seconds=300 if blocked else 0)
