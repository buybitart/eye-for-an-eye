"""P14 §146: what model governance costs.

Four questions, because they are the four places this could hurt a live site.

**Assessment.** Runs on a timer, not per request, so it could be slow and nobody
would notice — but a governance assessment that took minutes would be one nobody
runs often enough to be useful.

**Activation.** This one matters. §147 says promotion must not create a
user-visible outage, and the guarded switch happens while the site is serving.

**Rollback.** The number an operator cares about during an incident.

**The guarded ceiling.** Applied per decision while a model is guarded, so it is
the only part of this stage on a hot path. If it is not free, it is wrong.

Single process, one core, no network. This measures this machine and this
configuration, not a deployment.
"""
import json
from pathlib import Path
import statistics
import tempfile
import time

from benchmarks.common import environment, resources
from eye_for_an_eye.decision.features import INPUT_ORDER, SCHEMA_VERSION
from eye_for_an_eye.decision.registry import ModelRegistry
from eye_for_an_eye.governance.activation import PromotionActivator
from eye_for_an_eye.governance.assessment import ELIGIBLE, PromotionAssessmentRecord
from eye_for_an_eye.governance.engine import ModelGovernanceEngine
from eye_for_an_eye.governance.evidence import (ArtifactEvidence, ContextEvidence,
                                                GovernanceState, HEALTHY,
                                                HealthEvidence, OfflineEvidence,
                                                ShadowEvidence)
from eye_for_an_eye.governance.guarded import GuardedStore, ceiling_for, clamp
from eye_for_an_eye.governance.monitor import (PostPromotionMonitor,
                                               PostPromotionSignals)
from eye_for_an_eye.governance.policy import AutoPromoteSettings, GovernancePolicy

SITE = 'SITE:main'
TRUSTED = ('controlled_lab', 'manual_review')


def percentiles(samples):
    ordered = sorted(samples)
    def at(fraction):
        return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]
    return {'p50_us': at(0.50) * 1e6, 'p95_us': at(0.95) * 1e6,
            'p99_us': at(0.99) * 1e6, 'mean_us': statistics.fmean(ordered) * 1e6}


def policy():
    return GovernancePolicy(auto_promote=AutoPromoteSettings(
        enabled=True, sites=('main',)))


def evidence():
    return dict(
        artifact=ArtifactEvidence(
            version='web-risk-v5', scope=SITE, sha256='a' * 64,
            declared_sha256='a' * 64, feature_schema_version=SCHEMA_VERSION,
            feature_order_matches=True, dataset_version='dataset-v2',
            size_bytes=1_048_576, load_seconds=0.8),
        offline=OfflineEvidence(
            dataset_validation_passed=True, group_split_verified=True,
            onnx_parity_max_abs_error=3e-7, pr_auc=0.81,
            hard_positive_recall=0.74, false_blocks_per_1000_benign=0.30,
            hard_negative_false_block_rate=0.004, block_precision=0.92,
            system_replay_completed=True, inference_p95_ms=1.6,
            rss_bytes=54_000_000, trusted_outcomes=140, label_provenance=TRUSTED),
        active_offline=OfflineEvidence(
            dataset_validation_passed=True, group_split_verified=True,
            onnx_parity_max_abs_error=2e-7, pr_auc=0.79,
            hard_positive_recall=0.75, false_blocks_per_1000_benign=0.32,
            hard_negative_false_block_rate=0.005, block_precision=0.90,
            system_replay_completed=True, inference_p95_ms=1.5,
            rss_bytes=52_000_000, trusted_outcomes=140, label_provenance=TRUSTED),
        shadow=ShadowEvidence(
            observed_seconds=864_000.0, feature_vectors=41_000, source_groups=2_400,
            sites_with_activity=1, scored_by_both=41_000, large_disagreements=700,
            active_actions={'OBSERVE': 38_000, 'WATCH': 2_600},
            candidate_actions={'OBSERVE': 37_800, 'WATCH': 2_750},
            inference_p95_ms=1.6, trusted_outcomes=140,
            reviewed_false_blocks_active=3, reviewed_false_blocks_candidate=2),
        health=HealthEvidence(candidate_state=HEALTHY, active_state=HEALTHY,
                              candidate_load_succeeded=True,
                              candidate_finite_outputs=True, warmup_completed=True),
        context=ContextEvidence(drift_status='STABLE', active_ood_ratio=0.14,
                                candidate_ood_ratio=0.08),
        state=GovernanceState(seconds_since_last_promotion=1_209_600.0,
                              rollback_target='web-risk-v4',
                              last_known_good='web-risk-v4'))


def manifest(version):
    return {'manifest_version': 1, 'model_version': version,
            'feature_schema_version': SCHEMA_VERSION,
            'training_dataset_version': 'dataset-v2', 'parent_model': '',
            'created_at': '2026-09-11T00:00:00+00:00', 'scope': SITE,
            'recommended_mode': 'shadow', 'feature_order': list(INPUT_ORDER)}


def artifacts(version):
    return {'classifier.onnx': b'onnx-bytes',
            'manifest.json': json.dumps(manifest(version)).encode(),
            'distribution.json': json.dumps({'distribution_version': 1}).encode()}


def bench_assessment(rounds=2_000):
    engine = ModelGovernanceEngine(policy())
    parts = evidence()
    samples = []
    for _ in range(rounds):
        start = time.perf_counter()
        engine.assess(scope=SITE, **parts)
        samples.append(time.perf_counter() - start)
    result = engine.assess(scope=SITE, **parts)
    return percentiles(samples), result.decision, len(result.outcomes)


def bench_monitor(rounds=5_000):
    monitor = PostPromotionMonitor(policy())
    signals = PostPromotionSignals(
        observed_seconds=7_200.0, feature_vectors=5_000, reviewed_outcomes=40,
        reviewed_false_blocks=1, baseline_reviewed_false_blocks=1,
        latency_p95_ms=1.6, baseline_latency_p95_ms=1.5,
        actions={'OBSERVE': 4_600, 'WATCH': 350},
        baseline_actions={'OBSERVE': 4_620, 'WATCH': 330})
    samples = []
    for _ in range(rounds):
        start = time.perf_counter()
        monitor.evaluate(signals)
        samples.append(time.perf_counter() - start)
    return percentiles(samples)


def bench_ceiling(rounds=200_000):
    """The only part of governance on a per-decision path."""
    store = GuardedStore(Path(tempfile.mkdtemp()))
    state = store.enter(scope=SITE, version='web-risk-v5',
                        previous_version='web-risk-v4',
                        stage='GUARDED_ACTIVE_STAGE_1')
    current = policy()
    ceiling = ceiling_for(state, current)
    samples = []
    for index in range(rounds):
        action = ('OBSERVE', 'WATCH', 'RATE_LIMIT', 'TEMP_BLOCK')[index % 4]
        start = time.perf_counter()
        clamp(action, ceiling)
        samples.append(time.perf_counter() - start)
    return percentiles(samples), ceiling


def bench_activation(rounds=40):
    current = policy()
    activations, rollbacks = [], []
    for _ in range(rounds):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = ModelRegistry(root / 'models', scope=SITE)
            registry.register_candidate('web-risk-v4', artifacts('web-risk-v4'))
            registry.promote('web-risk-v4', gate_passed=True, reason='seed')
            registry.register_candidate('web-risk-v5', artifacts('web-risk-v5'))
            activator = PromotionActivator(root=root / 'governance', policy=current)
            assessment = PromotionAssessmentRecord(
                scope=SITE, candidate_version='web-risk-v5', decision=ELIGIBLE,
                policy_version=current.version, policy_digest=current.digest,
                active_version='web-risk-v4', created_at='2026-09-11T00:00:00+00:00')

            start = time.perf_counter()
            activator.promote(assessment=assessment, registry=registry,
                              warmup=lambda resolved: True)
            activations.append(time.perf_counter() - start)

            start = time.perf_counter()
            activator.roll_back(scope=SITE, registry=registry, reason='benchmark')
            rollbacks.append(time.perf_counter() - start)
    return percentiles(activations), percentiles(rollbacks)


def main():
    before = resources()
    assessment, decision, gates = bench_assessment()
    monitor = bench_monitor()
    ceiling, ceiling_action = bench_ceiling()
    activation, rollback = bench_activation()
    after = resources()

    print('Governance assessment:')
    print(f'  decision {decision} across {gates} gates')
    for name, value in assessment.items():
        print(f'  {name.replace("_us", "")} {value:8.1f} us')

    print('\nPost-promotion monitor:')
    for name, value in monitor.items():
        print(f'  {name.replace("_us", "")} {value:8.1f} us')

    print(f'\nGuarded action ceiling (per decision, ceiling {ceiling_action}):')
    for name, value in ceiling.items():
        print(f'  {name.replace("_us", "")} {value:8.3f} us')

    print('\nActivation (lock, verify, journal, warm up, switch, guarded):')
    for name, value in activation.items():
        print(f'  {name.replace("_us", "")} {value / 1000:8.2f} ms')

    print('\nRollback:')
    for name, value in rollback.items():
        print(f'  {name.replace("_us", "")} {value / 1000:8.2f} ms')

    print('\nProcess RSS:')
    print(f'  before {before["rss_bytes"] // 1024} KB')
    print(f'  after  {after["rss_bytes"] // 1024} KB')
    print(f'  growth {(after["rss_bytes"] - before["rss_bytes"]) // 1024} KB')
    print(f'  cpu    {after["cpu_seconds"] - before["cpu_seconds"]:.2f} s')

    print('\nEnvironment:')
    detail = environment()
    print(f'  {detail["cpu"]}, {detail["logical_cpus"]} logical CPUs')
    print(f'  {detail["kernel_settings"]}')

    print('\nNote:')
    print('single process, one core, no network; synthetic evidence against this')
    print('configuration, not a deployment measurement. Activation here excludes')
    print('the real model load, which is injected as a warmup callable: the number')
    print('below is the governance overhead around a load, not the load itself.')


if __name__ == '__main__':
    main()
