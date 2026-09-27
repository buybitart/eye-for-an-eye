import math
import threading

NAMES = frozenset('connections_accepted_total connections_rejected_total connections_active '
    'packets_received_total events_created_total events_dropped_total parse_errors_total '
    'queue_depth queue_bytes cache_entries cache_evictions_total enrichment_requests_total '
    'enrichment_failures_total enrichment_latency_seconds handler_latency_seconds response_bytes_total '
    'storage_written_total storage_failures_total storage_retained_events storage_bytes'.split())
NAMES |= frozenset('packet_parse_errors_total source_state_entries fingerprint_results_total fingerprint_errors_total '
    'correlation_results_total deception_connections_total deception_responses_total deception_response_bytes_total '
    'storage_writes_total storage_write_failures_total log_suppressed_total log_dropped_total log_errors_total '
    'storage_pressure api_requests_total api_errors_total metrics_errors_total storage_batches_total storage_pending_events'.split())
DURATIONS = ('handler_duration_seconds', 'enrichment_duration_seconds', 'storage_write_duration_seconds', 'ml_inference_seconds')
NAMES |= frozenset('ml_inference_total ml_inference_failed_total math_decision_total decision_disagreement_total '
    'shadow_would_block_total enforced_block_total policy_override_total model_load_failure_total '
    'decision_observe_total decision_watch_total decision_rate_limit_total decision_temp_block_total'.split())
# P8 reliability metrics. Feature names are a bounded, controlled vocabulary and
# may be used as labels; source addresses and review identifiers never are.
NAMES |= frozenset('drift_evaluations_total drift_drifted_features drift_warning_features '
    'ood_evaluations_total ood_high_total ood_insufficient_reference_total '
    'data_quality_low_total model_health_state distribution_load_failures_total '
    'policy_ood_suppressed_total policy_model_health_suppressed_total '
    'anomaly_inference_total anomaly_inference_failures_total anomaly_model_unavailable_total'.split())
NAMES |= frozenset(f'anomaly_inference_seconds_{suffix}' for suffix in ('sum', 'count'))
# P9 review queue metrics. Counts only: how much was offered, how much was
# admitted, how much a person has answered. No metric here is ever a label,
# and no source identifier appears in any of them.
NAMES |= frozenset('review_queue_offered_total review_queue_admitted_total '
    'review_queue_failures_total review_queue_unavailable_total '
    'review_queue_entries review_queue_unreviewed review_queue_reviewed'.split())
# P9 learning lifecycle metrics. Counts and bounded states only: no source
# address, no review identity, no label ever appears as a metric label.
NAMES |= frozenset('retraining_checks_total retraining_recommended_total '
    'training_jobs_total training_jobs_failed_total '
    'dataset_candidates_total dataset_candidates_rejected_total '
    'candidate_models_created_total candidate_quality_gate_failed_total '
    'candidate_shadow_inference_total candidate_shadow_failures_total '
    'candidate_disagreement_total candidate_new_block_total '
    'promotion_recommendation_total active_model_age_seconds'.split())
NAMES |= frozenset(f'training_job_duration_seconds_{suffix}' for suffix in ('sum', 'count'))
# P10 web protection metrics. Counts and gauges only. No path, address,
# user agent or account name ever appears as a metric label: those are
# unbounded and attacker-chosen, which is how a metrics endpoint becomes a
# memory problem.
NAMES |= frozenset('web_events_total web_events_dropped_total web_parse_errors_total '
    'web_requests_analyzed_total web_sources_active web_feature_vectors_total '
    'web_risk_decisions_total web_shadow_would_block_total '
    'web_observe_total web_watch_total web_rate_limit_total web_temp_block_total '
    'web_log_rotations_total web_rejected_field_lines_total '
    'proxy_identity_uncertain_total web_source_evictions_total'.split())
# P11 challenge metrics. Counts and one duration. No token, address, path or
# user agent ever appears as a label: a token as a metric label would be a
# short-lived bypass sitting in a scrape endpoint.
NAMES |= frozenset('challenge_issued_total challenge_passed_total '
    'challenge_failed_total challenge_expired_total challenge_invalid_total '
    'challenge_timed_out_total challenge_suppressed_total '
    'challenge_loop_prevented_total challenge_budget_rejected_total '
    'challenge_shadow_total challenge_active_contexts '
    'challenge_subsystem_errors_total web_soft_challenge_total '
    'web_challenge_adjusted_total web_sensor_state_pruned_total'.split())
NAMES |= frozenset(f'challenge_response_seconds_{suffix}' for suffix in ('sum', 'count'))
# P14 model governance metrics (§100). Counts, one gauge and one duration.
#
# Nothing here is ever a label. A model version, a candidate id, a model hash or
# a site domain as a metric label would be unbounded in exactly the way that
# turns a scrape endpoint into a memory problem, and a site domain would also put
# the list of protected websites in something an operator may expose to a
# monitoring system. The scope *type* — global or site — is bounded at two and is
# the only dimension that would be safe, so the counters below are split by it
# rather than labelled.
NAMES |= frozenset('model_promotion_assessments_total model_promotion_eligible_total '
    'model_promotion_need_more_data_total model_promotion_not_eligible_total '
    'model_auto_promotions_total model_auto_promotion_failures_total '
    'model_guarded_activations_total model_guarded_stage_advances_total '
    'model_auto_rollbacks_total model_auto_rollback_technical_total '
    'model_auto_rollback_resource_total model_auto_rollback_quality_total '
    'model_governance_freeze_total model_governance_safe_mode_total '
    'model_quarantine_total model_governance_frozen '
    'model_guarded_ceiling_applied_total model_post_promotion_disagreement_ratio '
    'model_promotion_assessments_global_total model_promotion_assessments_site_total'.split())
NAMES |= frozenset(f'model_promotion_duration_seconds_{suffix}' for suffix in ('sum', 'count'))
NAMES |= frozenset('events_shed_low_total events_shed_normal_total events_shed_high_total enrichment_suppressed_backpressure_total'.split())
# P15.5R §38. The autonomous decision path, now that a running sensor has one.
#
# Bounded by construction, deliberately. The counters here are a fixed list, and
# the per-assumption suppression counters are derived from
# `autonomy.record.ASSUMPTION_NAMES` — a tuple in the source — rather than from
# anything a decision contains. No address, scope, site, schema number or cost
# profile can become a metric name by this route, which is the same rule P14
# states above for model versions and site domains.
#
# `autonomous_block_suppressed_by_<assumption>_total` exists because of how
# P15.4 presented. Every gate agreed on 889 windows, one assumption refused all
# of them, and the only visible symptom was a recall of zero on a benchmark that
# ran days later. "Blocks suppressed" was already counted; *which assumption
# suppressed them* was not, and that is the number that turns a silent failure
# into an alarm.
NAMES |= frozenset('autonomous_decisions_total autonomous_block_records_total '
    'autonomous_shadow_blocks_total autonomous_enforced_total '
    'autonomous_enforcement_refused_total autonomous_enforcement_failed_total '
    'autonomous_enforcement_withheld_total autonomous_calibrator_usable '
    'autonomous_assumption_health_degraded '
    'decision_journal_records_total decision_journal_failures_total '
    'decision_journal_rotations_total decision_journal_bytes '
    'shadow_export_rows_total shadow_export_failures_total '
    'shadow_export_dropped_total shadow_export_bytes'.split())


def _assumption_metric_names():
    """Derived from the assumption registry rather than transcribed beside it.

    A copy of the list here would be a copy that can drift, and a suppression
    counter that exists in the authority and not in this set raises
    `invalid metric name` from inside the runtime's own thread — where the only
    symptom is a status file that stops updating.
    """
    from ..autonomy.record import ASSUMPTION_NAMES
    return frozenset(f'autonomous_block_suppressed_by_{name}_total'
                     for name in ASSUMPTION_NAMES)


NAMES |= _assumption_metric_names()
NAMES |= frozenset(f'{name}_{suffix}' for name in DURATIONS for suffix in ('sum', 'count'))


class Metrics:
    def __init__(self):
        self._values = dict.fromkeys(NAMES, 0)
        self._lock = threading.Lock()

    def set(self, name, value):
        if name not in NAMES or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ValueError('invalid metric name/value')
        with self._lock:
            self._values[name] = value

    def inc(self, name, value=1):
        if name not in NAMES or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ValueError('invalid metric name/value')
        with self._lock:
            self._values[name] += value

    def snapshot(self):
        with self._lock:
            return dict(self._values)

    def observe(self, name, value):
        if name not in DURATIONS:
            raise ValueError('unknown duration')
        self.inc(name + '_sum', value)
        self.inc(name + '_count')

    def prometheus(self):
        values = self.snapshot()
        lines = []
        for name, value in sorted(values.items()):
            kind = 'counter' if name.endswith(('_total', '_sum', '_count')) else 'gauge'
            lines.extend([f'# TYPE e4e_{name} {kind}', f'e4e_{name} {value}'])
        return '\n'.join(lines) + '\n'


def health(components):
    """Optional enrichment failure degrades the sensor; it does not disable intake."""
    allowed = {'healthy', 'degraded', 'unavailable', 'disabled'}
    if any(value not in allowed for value in components.values()):
        raise ValueError('invalid health state')
    core = [state for name, state in components.items() if name not in ('enrichment', 'api', 'metrics', 'logging', 'ml')]
    overall = 'unavailable' if 'unavailable' in core else (
        'degraded' if any(state in ('degraded', 'unavailable') for state in components.values()) else 'healthy')
    return {'status': overall, 'components': dict(components)}
