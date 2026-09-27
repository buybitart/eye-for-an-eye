import pytest
from eye_for_an_eye.decision.features import (FeatureVector, FeatureTransformer, NAMES, INPUT_ORDER,
                                              SCHEMA_VERSION)
from eye_for_an_eye.decision.math_risk import MathRiskEngine, decay


def vector(**changes):
    values = dict.fromkeys(NAMES, 0.0)
    values.update(changes)
    return FeatureVector(tuple(values.values()), 30, 40, loss_fraction=0.0)


def test_numeric_contract_missing_order_and_clipping():
    row = FeatureTransformer.transform(vector(connections_10s=512, ports_60s=128, anomaly_60s=None))
    # One value column and one availability column per feature. The literal 36
    # was pinned here until P15.4 appended five authentication columns; the
    # relationship is the contract, and the width is only today's value of it.
    assert len(row) == len(INPUT_ORDER) == 2 * len(NAMES)
    assert row[0] == row[3] == 1.0
    index = NAMES.index('anomaly_60s')
    assert row[index] == row[len(NAMES) + index] == 0.0
    assert FeatureTransformer.transform(vector())[len(NAMES) + index] == 1.0
    assert FeatureTransformer.fingerprint(vector()) != FeatureTransformer.fingerprint(vector(anomaly_60s=None))
    for value in (float('nan'), float('inf'), -1, 'payload', True):
        with pytest.raises(ValueError):
            vector(anomaly_60s=value)
    with pytest.raises(ValueError):
        FeatureVector((0.0,), 0, 0)
    with pytest.raises(ValueError):
        FeatureVector((0.0,) * len(NAMES), 0, 0, schema_version=SCHEMA_VERSION + 1)


def test_math_independent_and_explainable():
    """Under v4 the score is a composition of family scores, not a weighted sum.

    The explainability claim is unchanged and the check for it is stronger: the
    score must be exactly reproducible from the contributions the result
    carries, by the stated rule. What changed is the rule — noisy-OR over
    independent families instead of a sigmoid over a sum — and that a source is
    convincing because several families agree rather than because one number is
    large. `credentials_60s` is deliberately absent from the hostile vector: it
    no longer contributes anything, which is the point of P15.4.
    """
    engine = MathRiskEngine()
    benign = engine.evaluate(vector())
    hostile = engine.evaluate(vector(ports_60s=64, ports_900s=64, anomaly_60s=1,
                                     deception_60s=30, auth_failures_60s=12,
                                     auth_principals_900s=8))
    assert benign.score < .03 < .9 < hostile.score
    innocence = 1.0
    for value in hostile.contributions.values():
        innocence *= (1 - value)
    assert hostile.score == pytest.approx(1 - innocence)


def test_credential_presence_alone_is_no_longer_evidence():
    """§8. The exact defect P15.4 exists to fix, pinned so it cannot return."""
    engine = MathRiskEngine()
    quiet = engine.evaluate(vector())
    authenticating = engine.evaluate(vector(credentials_60s=20, auth_successes_60s=60,
                                            auth_failures_60s=0, auth_failure_ratio=0.0))
    assert authenticating.score == quiet.score, (
        'a client that authenticates on every request, successfully, must score '
        'exactly what silence scores')


def test_decay_half_life_and_domains():
    assert decay(.8, 60, 60) == pytest.approx(.4)
    assert decay(.8, 0, 60) == .8
    assert decay(.8, 1e100, 1) == 0
    for args in ((.8, -1, 1), (float('nan'), 1, 1), (1.1, 1, 1), (.8, 1, 0)):
        with pytest.raises(ValueError):
            decay(*args)
