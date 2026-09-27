"""Strict stdlib TOML configuration; validation happens before network setup."""
from dataclasses import asdict, dataclass, field, fields
import ipaddress
import math
import json
import os
import re
from pathlib import Path
import tomllib

CONFIG_VERSION = 1

#: The three deployment profiles the runtime understands. `validate()` refuses
#: anything else, and the operator CLI offers exactly these wherever it writes
#: `deployment.profile`. Named once, because the same list written in two places
#: is how `config init` came to offer three profiles while the template registry
#: held five. A *setup* profile is a different vocabulary — see
#: `configuration.PROFILE_TEMPLATES` — and the two are not interchangeable.
DEPLOYMENT_PROFILES = ('sensor', 'honeypot', 'lab')


@dataclass
class DeploymentConfig:
    profile: str = 'sensor'
    egress: str = 'disabled'


@dataclass
class NetworkConfig:
    bind_address: str = "127.0.0.1"
    port: int = 1234
    protocol: str = "tcp"
    udp_responses: bool = False


@dataclass
class Limits:
    max_connections: int = 256
    max_connections_per_ip: int = 8
    max_request_bytes: int = 4096
    max_response_bytes: int = 1024
    first_byte_timeout: float = 2.0
    idle_timeout: float = 5.0
    total_timeout: float = 10.0
    state_entries: int = 10_000
    state_ttl: float = 600.0
    connections_per_second: float = 100.0


@dataclass
class EnrichmentConfig:
    enabled: bool = False
    rdap_enabled: bool = False
    mmdb_path: str = ""
    workers: int = 4
    queue_size: int = 512
    timeout: float = 2.0
    negative_ttl: float = 30.0


@dataclass
class CaptureConfig:
    interface: str = ""
    pcap_path: str = ""
    bpf: str = "ip or ip6"
    p0f_db: str = ""
    ipc_socket: str = ""
    helper_uid: int = 65534
    analysis_uid: int = 65534
    max_frame_bytes: int = 8192


@dataclass
class ActiveConfig:
    enabled: bool = False
    allowed_cidrs: list[str] = field(default_factory=list)
    timeout: float = 1.0


@dataclass
class DeceptionConfig:
    enabled: bool = True
    secret_file: str = ""
    secret_env: str = "EYE_FOR_AN_EYE_SECRET"
    mode: str = 'sensor'
    catalogue_version: int = 2
    port_set: str = 'custom'
    decoy_ports: list[int] = field(default_factory=list)
    port_profiles: dict = field(default_factory=dict)
    source_allowlist: list[str] = field(default_factory=lambda: ['127.0.0.0/8', '::1/128'])
    redirected: bool = False
    username_policy: str = 'redact'
    preview_enabled: bool = False
    max_messages: int = 12
    max_transitions: int = 40
    jitter_enabled: bool = False
    jitter_min_ms: int = 10
    jitter_max_ms: int = 150
    overload_degraded: float = .7
    overload_observe_only: float = .9
    overload_recover: float = .5
    recovery_seconds: float = 2.0
    storage_slow_seconds: float = .1


@dataclass
class LabConfig:
    enabled: bool = False
    max_duration: float = 10.0
    max_bytes: int = 256
    max_connections: int = 16


@dataclass
class LoggingConfig:
    file: str = ""
    max_bytes: int = 5_000_000
    backups: int = 2
    queue_size: int = 512
    events_per_second: float = 100.0
    per_source_per_second: float = 5.0
    per_event_type_per_second: float = 100.0
    repeated_window: float = 1.0
    min_free_bytes: int = 1_048_576


@dataclass
class RuntimeConfig:
    sensor_id: str = 'local'
    #: The configuration file this was loaded from, filled in by `load_config`
    #: and empty for a programmatically built config. It is here because the
    #: privileged firewall helper is invoked as `--config <path>` and reads its
    #: own protected networks from that file: P15.5R §17 needs the unprivileged
    #: side to know which file the deployment is running, and threading the path
    #: through four constructors was a worse answer than recording it once.
    #: Writing it by hand in TOML has no effect the loader does not overwrite.
    config_path: str = ''
    queue_events: int = 1024
    queue_bytes: int = 4_194_304
    shutdown_timeout: float = 10.0
    status_file: str = ''
    enforce_unprivileged: bool = True
    load_shedding: bool = False
    low_priority_watermark: float = .75
    normal_priority_watermark: float = .9


@dataclass
class StorageConfig:
    enabled: bool = False
    path: str = 'eye-for-an-eye.sqlite3'
    max_events: int = 100000
    retention_seconds: float = 86400.0
    max_bytes: int = 134_217_728
    busy_timeout: float = .2
    max_batch_events: int = 1
    max_batch_delay_ms: float = 10.0
    cleanup_interval: float = 5.0
    cleanup_batch: int = 500
    pressure_warning: float = .7
    pressure_critical: float = .9


@dataclass
class FirewallConfig:
    enabled: bool = False
    lab_namespace: str = ''
    destination_addresses: list[str] = field(default_factory=list)
    decoy_ports: list[int] = field(default_factory=list)
    real_service_ports: list[int] = field(default_factory=lambda: [22])
    management_ports: list[int] = field(default_factory=lambda: [22, 3389])
    listener_address: str = '127.0.0.1'
    listener_port: int = 1234
    lease_seconds: int = 30


@dataclass
class FingerprintConfig:
    initial_ttls: list[int] = field(default_factory=lambda: [32, 64, 128, 255])
    max_hops: int = 32
    ip_id_samples: int = 32
    min_probe_evidence: int = 8


@dataclass
class CorrelationConfig:
    enabled: bool = True
    windows: list[int] = field(default_factory=lambda: [60, 900])
    max_windows: int = 4
    max_sources: int = 10000
    max_events_per_source: int = 256
    max_bytes: int = 33554432
    ttl_seconds: float = 900.0
    emit_interval: float = 5.0
    distributed_groups: int = 1024
    distributed_sources: int = 5
    focused_seconds: float = 300.0
    scanner_threshold: int = 40
    bot_threshold: int = 35
    suspicious_threshold: int = 25
    weights: dict = field(default_factory=lambda: dict(port_breadth=25, host_breadth=35, probe_diversity=15,
        connection_rate=10, sequential_ports=15, anomalies=20, credentials=25, persistence=20,
        repeated_probe=15, timing_regular=20, sequence_repeat=15))


@dataclass
class APIConfig:
    enabled: bool = False
    bind_address: str = '127.0.0.1'
    port: int = 8777
    allow_insecure_non_loopback: bool = False
    docs_enabled: bool = False
    redact_ip: bool = False
    token_file: str = ''
    max_page_size: int = 100
    max_response_bytes: int = 65536
    max_query_seconds: float = .2
    max_range_seconds: int = 604800
    max_scan_rows: int = 5000
    requests_per_second: float = 20.0
    max_connections: int = 16


@dataclass
class MetricsConfig:
    enabled: bool = False
    bind_address: str = '127.0.0.1'
    port: int = 8778
    allow_insecure_non_loopback: bool = False


@dataclass
class MLConfig:
    enabled: bool = True
    required: bool = False
    model_path: str = ''
    manifest_path: str = ''
    max_model_bytes: int = 16_777_216
    max_pending: int = 64
    max_concurrent: int = 1
    inference_timeout_ms: int = 200
    startup_timeout_seconds: float = 15.0
    cache_entries: int = 256
    cache_ttl_seconds: float = 10.0


@dataclass
class DecisionConfig:
    enabled: bool = True
    mode: str = 'shadow'
    interval_ms: int = 2000
    math_weight: float = .55
    ml_weight: float = .35
    persistence_weight: float = .10
    watch_threshold: float = .40
    rate_limit_threshold: float = .70
    block_threshold: float = .88
    hysteresis_margin: float = .10
    minimum_samples_for_block: int = 20
    minimum_observation_seconds: float = 5.0
    minimum_quality: float = .70
    minimum_categories: int = 3
    minimum_math_risk: float = .80
    minimum_ml_confidence: float = .70
    # Anomaly evidence is deliberately small. It is carved out of the
    # maths+ML pool only when an anomaly model is loaded, so a deployment
    # without one behaves exactly as before.
    anomaly_weight: float = .10
    half_life_seconds: float = 60.0
    history_entries: int = 4096
    history_ttl_seconds: float = 43200.0


@dataclass
class ReliabilityConfig:
    """P8 decision reliability. Every factor here can only ever reduce trust."""
    registry_path: str = ''
    anomaly_enabled: bool = True
    anomaly_model_path: str = ''
    anomaly_manifest_path: str = ''
    anomaly_timeout_ms: float = 200.0
    anomaly_max_failures: int = 5
    ood_enabled: bool = True
    distribution_path: str = ''
    ood_borderline_threshold: float = 0.25
    ood_high_threshold: float = 0.60
    ood_minimum_features: int = 4
    # A high-OOD observation means the classifier is outside what it knows.
    # Suppressing the strong action is the safe reading, not the cautious one.
    ood_suppresses_block: bool = True
    drift_enabled: bool = True
    drift_minimum_samples: int = 200
    drift_warning_threshold: float = 0.10
    drift_drifted_threshold: float = 0.25
    drift_interval_seconds: float = 900.0
    drift_ood_rate_warning: float = 0.30
    drift_ood_rate_unreliable: float = 0.60
    # A degraded model may still advise; it may not drive a block on its own.
    degraded_model_suppresses_block: bool = True
    # P9 review queue. Off by default: it writes behaviour summaries to disk and
    # needs a local secret, so an operator has to ask for it. Nothing here can
    # label anything; only a person answering an entry produces a label.
    review_queue_enabled: bool = False
    review_queue_path: str = ''
    review_queue_secret_file: str = ''
    review_queue_max_entries: int = 2000
    review_queue_per_source: int = 20
    review_queue_per_day: int = 500
    review_queue_ttl_days: int = 30
    review_queue_min_observations: int = 5


@dataclass
class WebConfig:
    """P10 web protection. Off by default; safe when switched on.

    `trusted_proxy_networks` is the setting that matters most. Empty means no
    forwarded header is believed, which is the correct default: believing one
    from an arbitrary client lets anyone claim to be anyone.
    """
    enabled: bool = False
    # Where request metadata comes from. Only a local Nginx JSON access log is
    # implemented; the reader is generic enough for other servers later.
    source_type: str = 'nginx'
    access_log_path: str = ''
    # Read from the end on the first start, so a fresh install does not replay a
    # month of history as if it had just happened.
    start_at_end: bool = True
    secret_file: str = ''
    # Networks whose forwarded headers are believed. Nothing is trusted by
    # default. A network here is never blocked on behalf of a client behind it.
    trusted_proxy_networks: list[str] = field(default_factory=list)
    trust_forwarded_headers: bool = True
    # Privacy. Both default to off; a URL and a query value routinely carry
    # secrets, and this project does not need them to see behaviour.
    store_raw_path: bool = False
    store_query_values: bool = False
    # Bounds. Every one is a refusal under load, never a warning.
    max_sources: int = 4096
    max_distinct_paths: int = 64
    source_ttl_seconds: float = 1800.0
    max_lines_per_poll: int = 2000
    max_queued_events: int = 20000
    # How often a source is re-scored. Feature updates stay per request.
    evaluation_interval_seconds: float = 5.0
    minimum_quality: float = 0.5
    expected_methods: list[str] = field(default_factory=lambda: ['GET', 'HEAD', 'POST',
                                                                'OPTIONS'])


@dataclass
class ChallengeConfig:
    """P11 adaptive web challenge. Off by default; shadow when first switched on.

    A challenge sits between watching and rate limiting. It is not
    authentication: a valid token means only that a client completed an ordinary
    web flow recently, and it grants nothing.
    """
    enabled: bool = False
    # shadow: decide but send nothing, so impact can be measured first.
    # active: actually send the challenge.
    mode: str = 'shadow'
    # The local master secret. Per-site keys are derived from it, so one file
    # covers every site on the server.
    secret_file: str = ''
    # Rotation: the previous secret is accepted for a window, so a rotation does
    # not invalidate every live cookie at once.
    previous_secret_file: str = ''
    # A configured identifier, never the Host header: a client controls Host, and
    # using it as a cryptographic scope would let a client pick its own key.
    site_id: str = 'default'
    token_ttl_seconds: int = 900
    cookie_secure: bool = True
    cookie_same_site: str = 'Lax'
    cookie_path: str = '/'
    # Where a challenge is worth its cost to the user.
    risk_floor: float = 0.45
    risk_ceiling: float = 0.88
    # Budgets. Every one is a refusal, and a refusal is normal operation.
    max_per_source_per_hour: int = 5
    max_per_second: int = 20
    max_contexts: int = 10000
    minimum_seconds_between: float = 10.0
    max_attempts: int = 3
    grace_seconds: float = 300.0
    failure_decay_seconds: float = 1800.0
    # Route policy. Empty means the built-in defaults, which do not challenge
    # API, auth, webhook or health routes.
    api_path_prefixes: list[str] = field(default_factory=list)
    no_challenge_path_prefixes: list[str] = field(default_factory=list)


@dataclass
class SitesConfig:
    """P12 multi-site. One engine, several websites, kept apart.

    Off by default, and a single-site owner never has to know it exists: with
    `enabled = false` everything behaves exactly as it did before, which is the
    point of §158.

    `profiles` holds one table per site. In TOML that reads:

        [sites]
        enabled = true

        [sites.profiles.main]
        profile = "website"
        domains = ["example.org"]

        [sites.profiles.api]
        profile = "api"
        domains = ["api.example.org"]

    Note what is *not* here. Memory bounds and site counts live in this section
    because they are properties of the installation; nothing inside a site's own
    table can change them. A site configures its own behaviour and nothing else.
    """
    enabled: bool = False
    #: Hard ceiling on configured sites (§127). An open-source website
    #: deployment does not need unlimited tenancy, and every site costs bounded
    #: state, bounded metrics and a bounded number of open registries.
    max_sites: int = 32
    #: Where traffic goes when no configured domain matches. Empty means the
    #: bounded UNKNOWN_SITE bucket, which is the conservative default: silently
    #: treating every unknown Host as the primary site is how one site's policy
    #: ends up applied to another's traffic.
    default_site: str = ''
    #: What may happen to traffic in the unknown bucket. Deliberately the
    #: weakest action: an unmatched Host is usually a misconfiguration or a
    #: scanner, and neither is a reason to act on a site nobody configured.
    unknown_site_action: str = 'OBSERVE'
    #: Shared state budget across every site.
    max_sources_global: int = 8192
    max_sources_per_site: int = 2048
    #: What a site can always claim, however busy its neighbours are.
    reserved_sources_per_site: int = 64
    #: Per-site configuration tables.
    profiles: dict = field(default_factory=dict)


@dataclass
class ModelGovernanceConfig:
    """P14 model governance. Whether a validated candidate may be promoted without being asked.

    **Everything here is off on a fresh install, and a package upgrade cannot turn
    it on** (P14 §4, §98, §143). Enabling it is an explicit local decision with a
    command attached, because it is the setting that lets this software change
    what it blocks without a person in the loop.

    The two switches are separate because their blast radii are not comparable.
    `auto_promote_enabled` permits site-scoped promotion, which affects one
    website. `auto_promote_global_enabled` permits promotion of the shared base
    model, which reaches every site on the machine including ones whose operator
    never opted in — so it is a second decision, not a detail of the first.

    `auto_promote_sites` is the list of sites that opted in by name. A site that
    is not in it does not auto-promote whatever the global switch says.

    Two structural safeguards are not settings and cannot be switched off from
    here: a candidate always enters service under a reduced action ceiling, and a
    promotion with no rollback target is refused. `guarded_activation_enabled`
    and `auto_rollback_enabled` exist so an operator can see them, and turning
    either off while auto-promotion is on is refused by the governance policy
    rather than silently accepted.
    """
    auto_promote_enabled: bool = False
    auto_promote_global_enabled: bool = False
    auto_promote_sites: list[str] = field(default_factory=list)
    #: How much shadow observation a candidate needs before its evidence counts.
    #: Deliberately configurable per installation: one event count applied to
    #: every site would be far too strict for a quiet admin panel and far too
    #: lax for a busy API.
    minimum_shadow_seconds: float = 604800.0
    minimum_shadow_samples: int = 5000
    minimum_source_groups: int = 500
    #: Reviewed outcomes with trusted provenance. Below this, quality gates
    #: answer NEED_MORE_DATA rather than guessing.
    minimum_trusted_outcomes: int = 50
    promotion_cooldown_seconds: float = 604800.0
    max_promotions_per_day: int = 2
    max_promotions_per_site_per_day: int = 1
    max_rollbacks_per_day: int = 3
    guarded_activation_enabled: bool = True
    auto_rollback_enabled: bool = True
    #: Set by an operator or by the system itself after repeated failures. While
    #: true, nothing is promoted and no guarded stage advances.
    frozen: bool = False
    journal_path: str = ""
    history_path: str = ""


@dataclass
class LearningConfig:
    """P9 adaptive learning. Preparation and training may be automated; promotion may not.

    **There is no promotion switch in this class**, and that is the boundary P14
    did not move. Training may not promote what it trained (P14 §109): the
    settings that decide promotion live in `ModelGovernanceConfig`, they are read
    by a separate authority, and no code path from a training job reaches them.

    Before P14 this docstring said no such setting existed anywhere in the
    project. That was true then and is not true now — `model_governance` has one,
    it is off by default, and it is gated by evidence this class cannot produce.
    """
    enabled: bool = False
    # RESERVED, AND NOT YET HONOURED. Both names exist, both default to False,
    # and no code path reads either one to start anything: `learning status`
    # reports `auto_train` and that is the whole of it. Setting either to true
    # changes no behaviour in this release.
    #
    # They are kept rather than deleted because the eventual meaning is already
    # decided -- build a candidate dataset, train a candidate model, neither of
    # which may ever promote one -- and a later release that wires them up must
    # not quietly reuse a name an operator had already set expecting something
    # else. Until then the honest word is "reserved", not "off".
    auto_prepare_dataset: bool = False
    auto_train: bool = False
    # Candidate shadow inference. On by default *when a candidate exists*, because
    # a candidate that is never scored tells an operator nothing.
    candidate_shadow_enabled: bool = True
    candidate_sample_every: int = 1
    candidate_max_failures: int = 5
    jobs_path: str = ''
    workspace_path: str = ''
    audit_log_path: str = ''
    training_max_duration_seconds: int = 1800
    training_max_memory_mb: int = 2048
    training_max_parallel_jobs: int = 1
    training_nice: int = 10
    minimum_retraining_interval_days: int = 14
    minimum_trusted_samples: int = 200
    minimum_samples_per_label: int = 50
    minimum_label_sources: int = 20
    keep_job_records: int = 50


@dataclass
class AutonomyConfig:
    """P15 autonomous decision authority. Off on a fresh install, as everything is.

    Autonomy here is an operational property and nothing else: with `enabled`
    true and `mode` autonomous, no person approves each ALLOW or TEMP_BLOCK. It
    is not a claim that the decisions are right, and no setting in this class
    makes it one.

    Three groups of settings, with different characters.

    **The cost model** (`default_cost_profile`, `cost_profiles`, the two margins)
    is a judgement about a particular deployment and is the operator's to make.
    §131 and §196: nothing learned writes here, and there is no code path from
    training, governance or the models to any of these values.

    **The evidence gates** (`minimum_*`, `maximum_uncertainty`) are floors on the
    system's willingness to act. Raising them is caution; lowering them spends
    safety margin, which is worth knowing before doing it.

    **The brakes** (`blocks_per_minute`, `max_block_share`, and the rest) bound
    how wrong the system can get at scale. The mass-block circuit breaker has no
    off switch and is deliberately not represented here as one — §198 lists the
    mass-block ceiling among the limits no autonomous component may change, and
    a switch to disable it would be exactly such a change with an operator's
    name on it. What is configurable is the ceiling, not whether it exists.
    """
    enabled: bool = False
    #: `shadow` computes and records the same decision without expecting it to be
    #: enforced; `autonomous` is the mode §103 names. Shadow stays available in
    #: autonomous deployments for new sites and new models (§191).
    mode: str = "shadow"
    #: Scope (`GLOBAL` or `SITE:<id>`) to cost profile name.
    cost_profiles: dict[str, str] = field(default_factory=dict)
    default_cost_profile: str = "public_website"
    decision_margin: float = 0.25
    release_margin: float = 0.10
    minimum_observations: int = 20
    minimum_observation_seconds: float = 10.0
    minimum_data_quality: float = 0.55
    minimum_signal_diversity: int = 3
    minimum_behavioural_diversity: int = 2
    maximum_uncertainty: float = 0.60
    blocks_per_minute: int = 10
    max_active_blocks: int = 500
    max_block_share: float = 0.02
    minimum_sources_for_share: int = 200
    max_false_blocks_per_1000: float = 1.0
    minimum_benign_sample: int = 500
    breaker_cooldown_seconds: float = 300.0
    #: How long the runtime stays in safe mode after a health gate passes before
    #: returning to autonomous decisions (§193, §194).
    recovery_cooldown_seconds: float = 900.0
    #: Where decision records are written. Empty means they are produced and
    #: reported but not persisted, which is the default: a decision journal is
    #: useful and it is also a file of addresses, so an operator opts in.
    decision_journal_path: str = ""
    decision_journal_max_entries: int = 20000
    #: P15.5R §5. The journal's four ceilings. Every one of them is a bound on
    #: local disk, because a forensic log without a ceiling is a way to fill the
    #: disk of the machine this software is defending.
    journal_max_file_bytes: int = 8_388_608
    journal_max_files: int = 4
    journal_max_total_bytes: int = 33_554_432
    #: P15.5R §8-§11. Where privacy-safe analytic rows are written for later
    #: independent evaluation, one per decision, derived from the same records
    #: the journal keeps. Empty means none, which is the default.
    #:
    #: This is the evidence a shadow deployment exists to produce, and it is
    #: deliberately a different file from the journal: the journal is forensic
    #: and local, this is analytic and meant to be aggregated. It carries no
    #: address at any setting, coarsens timestamps to the hour, and leaves its
    #: label fields empty — a system decision is never ground truth.
    #:
    #: Local only. Nothing here is sent anywhere; moving it off the machine is
    #: the operator's deliberate act.
    shadow_export_path: str = ""
    shadow_export_max_file_bytes: int = 8_388_608
    shadow_export_max_files: int = 8
    shadow_export_max_total_bytes: int = 67_108_864
    shadow_export_max_records: int = 100_000
    #: How coarse an exported timestamp is. An exact time and a stable
    #: pseudonym together are a re-identification tool even though neither is
    #: one alone, and nothing an evaluation asks of this evidence needs better
    #: than an hour.
    shadow_export_bucket_seconds: int = 3600
    #: P15S §12, §13, §31. Which collection the exported rows belong to.
    #: `real_shadow` is ordinary traffic on a deployment; `controlled_positive`
    #: is a bounded test against an owned asset. They are separated at the point
    #: of writing because a controlled scan is real runtime evidence and is
    #: emphatically not benign-population evidence, and reconstructing the split
    #: from timestamps afterwards is how the two get mixed.
    shadow_export_collection: str = "real_shadow"
    #: Where this sensor sits, in the operator's own words. Travels with every
    #: row so an evaluation can say which vantage point produced it. Free text;
    #: never an address, and never a model feature.
    shadow_export_placement: str = ""
    #: P15S §46, §47. Names the evidence segment. A configuration or code change
    #: ends a segment and starts a new one, and rows from either side of that
    #: line must not be evaluated as one immutable dataset.
    shadow_export_segment: str = ""
    #: P15.5R §4. Whether the journal keeps the operational address as well as
    #: the pseudonym. Off by default: the pseudonym is what correlates one
    #: source's records, and a journal that is kept, exported or graphed should
    #: not be a log of who visited (§87). An operator doing forensics on their
    #: own machine can turn it on.
    journal_include_source: bool = False
    #: P15.5R §6. Whether a decision that could not be journalled may still be
    #: enforced.
    #:
    #: False, because the accountable minimum survives either way: the
    #: operational log carries the decision id, the action, the profile, the
    #: probability, the bound and the reason codes, so a block stays explainable
    #: even when its full record did not land. Nothing in this project's
    #: existing policy makes durable auditability a precondition for acting, and
    #: inventing one here would be inventing policy silently.
    #:
    #: True is the stricter reading, and it is a real choice rather than a
    #: hypothetical one: with it, a full disk stops autonomous blocking, which
    #: is safe in the false-positive direction and turns a storage problem into
    #: a defence outage. The operator decides which failure they prefer.
    #:
    #: Named for the *action* rather than for enforcement on purpose.
    #: `tests/test_p15_invariants.py` refuses any setting in this section whose
    #: name contains `firewall`, `nftables`, `namespace` or `enforce`, because
    #: `[autonomy]` is the decision section and nothing in it may reach the
    #: firewall. This setting only ever *withholds* an action, never grants one
    #: — but the invariant is a name check precisely so that it needs no
    #: judgement, and weakening it to admit a well-intentioned exception is how
    #: an invariant stops being one.
    journal_required_for_action: bool = False
    #: Local secret keying the pseudonymous source identifier in decision
    #: records. Without one, records correlate within a process run and across
    #: none - weaker, and said out loud rather than papered over.
    pseudonym_secret_file: str = ""
    #: P15.5R §7, §9. The math-risk calibrator this deployment decides with,
    #: relative to this configuration file.
    #:
    #: Until P15.5R there was no such setting, and the consequence was not a
    #: missing convenience: `decision/calibration.py` was not imported by a
    #: running sensor at all, so the only artifact that turns a MathRisk score
    #: into a probability was loaded exclusively by the evaluator. The
    #: benchmarks measured a calibrated system and the product shipped an
    #: uncalibrated one.
    #:
    #: Empty is a supported state and the default. The authority's
    #: `calibrated_estimate` gate then refuses every block — which is why
    #: `autonomy.mode = "autonomous"` requires one, and why shadow mode does
    #: not. A file that is missing, unreadable, fitted on another formula or
    #: carrying no conservative bound degrades the component rather than
    #: stopping the sensor; §10 is explicit that the raw MathRisk score must
    #: never be promoted to a probability to fill the gap.
    calibrator_path: str = ""


@dataclass
class EnforcementConfig:
    """Temporary blocking. Two separate switches, because two separate blast radii.

    `enabled` is the P7 lab path: nftables inside a named, disposable network
    namespace, refused anywhere else by three independent gates.

    `host_enabled` is the P15.1 path that can place a bounded temporary block on
    *this machine*. It is off on a fresh installation, a package upgrade cannot
    turn it on, and turning it on is the single most consequential setting in
    this file: it is the one that lets the software deny somebody access to a
    real service without being asked.

    It is a second switch rather than a mode of the first because the two are not
    versions of the same risk. Getting the lab path wrong costs a test namespace.
    Getting this one wrong costs an operator their own server.
    """
    enabled: bool = False
    #: P15.1 host enforcement. Requires a configured protected network, a
    #: privileged helper that can reach `nft`, and the autonomy readiness gate.
    host_enabled: bool = False
    management_networks: list[str] = field(default_factory=list)
    allowlist: list[str] = field(default_factory=list)
    trusted_proxies: list[str] = field(default_factory=list)
    max_entries: int = 1024
    block_seconds: list[int] = field(default_factory=lambda: [300, 1800, 7200, 43200])
    offense_decay_seconds: float = 21600.0


@dataclass
class Config:
    config_version: int = CONFIG_VERSION
    deployment: DeploymentConfig = field(default_factory=DeploymentConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    limits: Limits = field(default_factory=Limits)
    enrichment: EnrichmentConfig = field(default_factory=EnrichmentConfig)
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    active_probes: ActiveConfig = field(default_factory=ActiveConfig)
    deception: DeceptionConfig = field(default_factory=DeceptionConfig)
    lab: LabConfig = field(default_factory=LabConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    fingerprint: FingerprintConfig = field(default_factory=FingerprintConfig)
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)
    api: APIConfig = field(default_factory=APIConfig)
    metrics: MetricsConfig = field(default_factory=MetricsConfig)
    ml: MLConfig = field(default_factory=MLConfig)
    decision: DecisionConfig = field(default_factory=DecisionConfig)
    enforcement: EnforcementConfig = field(default_factory=EnforcementConfig)
    reliability: ReliabilityConfig = field(default_factory=ReliabilityConfig)
    learning: LearningConfig = field(default_factory=LearningConfig)
    model_governance: ModelGovernanceConfig = field(default_factory=ModelGovernanceConfig)
    autonomy: AutonomyConfig = field(default_factory=AutonomyConfig)
    web: WebConfig = field(default_factory=WebConfig)
    challenge: ChallengeConfig = field(default_factory=ChallengeConfig)
    sites: SitesConfig = field(default_factory=SitesConfig)
    probes_path: str = ""

    def validate(self):
        # Types are checked even for programmatically constructed configurations.
        default = Config()
        for section in fields(self):
            current, template = getattr(self, section.name), getattr(default, section.name)
            if section.name == 'config_version':
                if type(current) is not int or current != CONFIG_VERSION:
                    found = current if type(current) is int else type(current).__name__
                    raise ValueError(f'config_version: Configuration version {CONFIG_VERSION} required; found {found}; use config migrate')
                continue
            if section.name == "probes_path":
                if not isinstance(current, str):
                    raise ValueError("probes_path must be a string")
                continue
            if type(current) is not type(template):
                raise ValueError(f'{section.name}: expected a configuration table; use E4E__SECTION__FIELD overrides')
            for setting in fields(template):
                value, example = getattr(current, setting.name), getattr(template, setting.name)
                name = f"{section.name}.{setting.name}"
                if isinstance(example, float):
                    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                        raise ValueError(f"{name}: value type {type(value).__name__}; expected a finite positive number")
                elif type(value) is not type(example):
                    raise ValueError(f"{name}: value type {type(value).__name__}; expected {type(example).__name__}")
                elif type(value) is int and value < 1:
                    raise ValueError(f"{name}: value {value}; expected a positive integer")
        ml, decision, enforcement = self.ml, self.decision, self.enforcement
        if (ml.max_concurrent != 1 or ml.max_pending > 256 or ml.cache_entries > 4096 or
                not 1024 <= ml.max_model_bytes <= 33_554_432 or not 10 <= ml.inference_timeout_ms <= 5000 or
                not 1 <= ml.startup_timeout_seconds <= 30 or ml.cache_ttl_seconds > 60 or
                ml.required and (not ml.enabled or not ml.model_path or not ml.manifest_path or not decision.enabled)):
            raise ValueError('invalid ML bounds/required configuration; P7 supports one isolated CPU worker')
        if (decision.mode not in ('shadow', 'enforce') or not 1000 <= decision.interval_ms <= 60000 or
                not 0 < decision.watch_threshold < decision.rate_limit_threshold < decision.block_threshold <= 1 or
                not 0 < decision.hysteresis_margin < decision.watch_threshold or
                abs(decision.math_weight + decision.ml_weight + decision.persistence_weight - 1) > 1e-6 or
                not 1 <= decision.minimum_samples_for_block <= 512 or not 1 <= decision.minimum_categories <= 4 or
                not 0 < decision.minimum_quality <= 1 or not 0 < decision.minimum_math_risk <= 1 or
                not .5 <= decision.minimum_ml_confidence <= 1 or decision.history_entries > 10000 or
                decision.history_ttl_seconds > 86400 or decision.half_life_seconds > 86400 or
                decision.minimum_observation_seconds > 900):
            raise ValueError('invalid decision policy bounds')
        if decision.enabled and not self.correlation.enabled:
            raise ValueError('decision engine requires correlation windows')
        governance = self.model_governance
        if governance.auto_promote_enabled and not governance.guarded_activation_enabled:
            raise ValueError(
                'model_governance: auto-promotion requires guarded activation; a '
                'candidate would otherwise reach full authority on evidence that '
                'cannot cover every production case')
        if governance.auto_promote_enabled and not governance.auto_rollback_enabled:
            raise ValueError(
                'model_governance: auto-promotion requires automatic rollback; an '
                'automatic change with no automatic way back is a one-way door')
        if governance.auto_promote_global_enabled and not governance.auto_promote_enabled:
            raise ValueError(
                'model_governance: auto_promote_global_enabled has no effect while '
                'auto_promote_enabled is false; set both deliberately or neither')
        if len(governance.auto_promote_sites) > 64 or any(
                not isinstance(site, str) for site in governance.auto_promote_sites):
            raise ValueError('model_governance: at most 64 site names, all strings')
        if (enforcement.max_entries > 10000 or not 1 <= len(enforcement.block_seconds) <= 8 or
                any(type(v) is not int or not 1 <= v <= 43200 for v in enforcement.block_seconds) or
                sorted(set(enforcement.block_seconds)) != enforcement.block_seconds or enforcement.offense_decay_seconds > 86400):
            raise ValueError('invalid temporary enforcement bounds')
        for networks in (enforcement.management_networks, enforcement.allowlist,
                         enforcement.trusted_proxies, self.web.trusted_proxy_networks):
            if len(networks) > 64 or any(not isinstance(v, str) for v in networks):
                raise ValueError('protected network limit is 64 CIDRs per list')
            for value in networks:
                ipaddress.ip_network(value, strict=True)
        if enforcement.enabled and not (decision.enabled and decision.mode == 'enforce' and
                self.deployment.profile == 'lab' and self.firewall.lab_namespace):
            raise ValueError('P7 enforcement requires explicit enforce mode and isolated lab namespace')
        self._validate_host_enforcement()
        self._validate_autonomy()
        if self.deployment.profile not in DEPLOYMENT_PROFILES:
            raise ValueError('deployment.profile: expected '
                             + ', '.join(DEPLOYMENT_PROFILES))
        if self.deployment.egress not in ('disabled', 'restricted'):
            raise ValueError('deployment.egress: expected disabled or restricted')
        if self.deployment.egress == 'disabled' and (self.enrichment.rdap_enabled or self.active_probes.enabled):
            raise ValueError('deployment.egress=disabled requires enrichment.rdap_enabled=false and active_probes.enabled=false')
        if self.active_probes.enabled and self.deployment.profile != 'lab':
            raise ValueError('active_probes.enabled: requires deployment.profile=lab and an explicit restricted egress policy')
        if not 0 < self.runtime.low_priority_watermark < self.runtime.normal_priority_watermark < 1:
            raise ValueError('invalid runtime priority watermarks')
        api = self.api
        for endpoint in (api, self.metrics):
            address = ipaddress.ip_address(endpoint.bind_address)
            if address.is_multicast or not 1 <= endpoint.port <= 65535:
                raise ValueError('invalid operational bind/port')
            if endpoint.enabled and not address.is_loopback and not endpoint.allow_insecure_non_loopback:
                raise ValueError('non-loopback operational bind requires explicit insecure override')
            if endpoint.enabled and endpoint.port == self.network.port:
                raise ValueError('operational endpoint must use a separate port')
        if api.enabled and self.metrics.enabled and api.port == self.metrics.port:
            raise ValueError('API and metrics must use separate ports')
        if (not 1 <= api.max_page_size <= 500 or not 1024 <= api.max_response_bytes <= 65536 or
                not .01 <= api.max_query_seconds <= 1 or not 60 <= api.max_range_seconds <= 604800 or
                not 100 <= api.max_scan_rows <= 10000 or not 1 <= api.max_connections <= 32 or
                api.requests_per_second > 1000):
            raise ValueError('invalid API request/query bounds')
        if api.token_file and (not Path(api.token_file).is_file() or Path(api.token_file).stat().st_size > 4096):
            raise ValueError('API token file must be a bounded existing file')
        if (not 1 <= self.storage.cleanup_batch <= 1000 or not .1 <= self.storage.cleanup_interval <= 3600 or
                not 0 < self.storage.pressure_warning < self.storage.pressure_critical < 1):
            raise ValueError('invalid retention/pressure thresholds')
        if self.logging.backups > 20 or self.logging.queue_size > 10000:
            raise ValueError('invalid logging retention/queue limits')
        from .compatibility import DECEPTION_CATALOGUE
        dec = self.deception
        # Not `!= 2`. The catalogue version says what the machine looks like from
        # outside; pinning the current literal here would refuse every future
        # catalogue with a configuration error, which is the P15.4 shape exactly
        # (P15.5 §2).
        if (dec.mode not in ('sensor', 'lab')
                or not DECEPTION_CATALOGUE.supports(dec.catalogue_version) or
                dec.port_set not in ('common', 'extended', 'custom') or dec.username_policy not in ('redact', 'hash')):
            raise ValueError('invalid deception mode/catalogue/ports/privacy policy')
        if (not 1 <= dec.max_messages <= 16 or not 3 <= dec.max_transitions <= 64 or
                not 1 <= dec.jitter_min_ms <= dec.jitter_max_ms <= 150 or
                not 0 < dec.overload_recover < dec.overload_degraded < dec.overload_observe_only <= 1 or
                not .1 <= dec.recovery_seconds <= 30 or dec.storage_slow_seconds > 1):
            raise ValueError('invalid deception state/timing/load budgets')
        if (len(dec.decoy_ports) > 256 or len(set(dec.decoy_ports)) != len(dec.decoy_ports) or
                any(type(port) is not int or not 1 <= port <= 65535 for port in dec.decoy_ports)):
            raise ValueError('invalid deception decoy ports')
        if len(dec.port_profiles) > 256 or any(not isinstance(port, str) or not port.isascii() or not port.isdigit() or
                str(int(port)) != port or not 1 <= int(port) <= 65535 or family not in ('http', 'ssh', 'ftp')
                for port, family in dec.port_profiles.items()):
            raise ValueError('invalid port profile family mapping')
        if len(dec.source_allowlist) > 64:
            raise ValueError('deception source allowlist limit is 64')
        for value in dec.source_allowlist:
            if not isinstance(value, str):
                raise ValueError('source allowlist entries must be CIDRs')
            network = ipaddress.ip_network(value, strict=True)
            if dec.mode == 'lab' and (network.is_global or network.prefixlen < (24 if network.version == 4 else 120)):
                raise ValueError('lab needs narrow non-global source allowlist')
        if dec.mode == 'lab' and (not dec.source_allowlist or not ipaddress.ip_address(self.network.bind_address).is_loopback):
            raise ValueError('lab deception requires loopback bind and explicit source allowlist')
        if dec.redirected and self.network.protocol != 'tcp':
            raise ValueError('redirected UDP deception is unsupported')
        from .deception.policy import decoy_ports
        protected_ports = set(self.firewall.real_service_ports + self.firewall.management_ports)
        if protected_ports.intersection(decoy_ports(self)):
            raise ValueError('deception decoy ports overlap real services or management ports')
        if set(map(int, dec.port_profiles)) - decoy_ports(self):
            raise ValueError('port profiles must refer to configured decoys')
        fp = self.fingerprint
        corr = self.correlation
        if (not 1 <= corr.max_windows <= 4 or not 1 <= len(corr.windows) <= corr.max_windows
                or any(type(value) is not int or not 1 <= value <= 3600 for value in corr.windows)
                or len(set(corr.windows)) != len(corr.windows) or corr.ttl_seconds < max(corr.windows)):
            raise ValueError('invalid correlation windows/TTL')
        if (corr.max_sources > 100000 or not 8 <= corr.max_events_per_source <= 512
                or not 65536 <= corr.max_bytes <= 134217728 or corr.distributed_groups > 10000
                or not 2 <= corr.distributed_sources <= corr.max_events_per_source or corr.emit_interval > 3600
                or corr.focused_seconds > 3600):
            raise ValueError('invalid correlation state bounds')
        if set(corr.weights) != set(CorrelationConfig().weights) or any(type(value) is not int or not 0 <= value <= 100 for value in corr.weights.values()):
            raise ValueError('unknown or invalid correlation weight')
        if any(not 1 <= value <= 100 for value in (corr.scanner_threshold, corr.bot_threshold, corr.suspicious_threshold)):
            raise ValueError('invalid detection thresholds')
        if not 1 <= fp.max_hops <= 254 or not 3 <= fp.ip_id_samples <= 128 or not 1 <= fp.min_probe_evidence <= 65536:
            raise ValueError('invalid fingerprint bounds')
        if not 1 <= len(fp.initial_ttls) <= 16 or any(type(value) is not int or not 1 <= value <= 255 for value in fp.initial_ttls):
            raise ValueError('invalid initial TTL candidates')
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', self.runtime.sensor_id):
            raise ValueError('runtime.sensor_id must be 1..64 safe identifier characters')
        if self.runtime.queue_events > 100000 or not 4096 <= self.runtime.queue_bytes <= 67_108_864:
            raise ValueError('event queue ceiling is 100000 events / 64 MiB, minimum 4096 bytes')
        if not 3 <= self.runtime.shutdown_timeout <= 60:
            raise ValueError('shutdown timeout must be 3..60 seconds')
        if self.storage.max_bytes < 1_048_576 or self.storage.busy_timeout > 1:
            raise ValueError('storage needs >=1 MiB and busy_timeout <=1 second')
        if not 1 <= self.storage.max_batch_events <= min(32, self.storage.max_events) or not 1 <= self.storage.max_batch_delay_ms <= 50:
            raise ValueError('storage batch needs 1..32 events within row budget and 1..50 ms delay')
        if self.storage.enabled and not Path(self.storage.path).parent.is_dir():
            raise ValueError('storage directory does not exist')
        if self.storage.enabled and Path(self.storage.path).exists() and not Path(self.storage.path).is_file():
            raise ValueError('storage path must be a regular file')
        if self.storage.enabled and Path(self.storage.path).is_file() and Path(self.storage.path).stat().st_size > self.storage.max_bytes:
            raise ValueError('existing storage exceeds configured size budget')
        if self.runtime.status_file and not Path(self.runtime.status_file).parent.is_dir():
            raise ValueError('status directory does not exist')
        if not 1024 <= self.capture.max_frame_bytes <= 16384:
            raise ValueError('IPC frame size must be 1024..16384 bytes')
        if self.capture.ipc_socket and (len(self.capture.ipc_socket.encode()) > 100 or not Path(self.capture.ipc_socket).is_absolute()):
            raise ValueError('IPC socket path must be absolute and <=100 bytes')
        if self.firewall.lab_namespace and not re.fullmatch(r'e4e-lab-[a-z0-9-]{1,32}', self.firewall.lab_namespace):
            raise ValueError('firewall requires an explicit e4e-lab-* named namespace')
        if not 5 <= self.firewall.lease_seconds <= 300 or self.firewall.listener_port > 65535:
            raise ValueError('invalid firewall lease/port')
        for ports in (self.firewall.decoy_ports, self.firewall.real_service_ports, self.firewall.management_ports):
            if len(ports) > 256 or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
                raise ValueError('firewall ports must be at most 256 literal integers in 1..65535')
        protected = set(self.firewall.real_service_ports + self.firewall.management_ports + [self.firewall.listener_port])
        if protected.intersection(self.firewall.decoy_ports):
            raise ValueError('decoy ports overlap protected or listener ports')
        if len(self.firewall.destination_addresses) > 16:
            raise ValueError('firewall destination address limit is 16')
        for value in [self.firewall.listener_address, *self.firewall.destination_addresses]:
            if not isinstance(value, str):
                raise ValueError('firewall addresses must be literal IPv4 strings')
            address = ipaddress.ip_address(value)
            if address.version != 4 or address.is_unspecified or address.is_multicast or address.is_global:
                raise ValueError('P1 firewall supports explicit non-global lab IPv4 addresses only; IPv6 unsupported')
        if self.firewall.enabled and not (self.firewall.lab_namespace and self.firewall.destination_addresses and self.firewall.decoy_ports):
            raise ValueError('firewall requires namespace, destination addresses and decoy ports')
        address = ipaddress.ip_address(self.network.bind_address)
        if address.is_multicast:
            raise ValueError("multicast bind is not supported")
        if not 1 <= self.network.port <= 65535:
            raise ValueError(f"network.port: value {self.network.port}; expected 1..65535")
        if self.network.protocol not in ("tcp", "udp"):
            raise ValueError("protocol must be tcp or udp")
        if self.network.udp_responses:
            raise ValueError("UDP responses are unsupported in P0; observation only")
        if self.limits.max_connections_per_ip > self.limits.max_connections:
            raise ValueError(f"limits.max_connections_per_ip: value {self.limits.max_connections_per_ip}; expected <= limits.max_connections ({self.limits.max_connections})")
        if max(self.limits.max_request_bytes, self.limits.max_response_bytes) > 65536:
            raise ValueError("request/response budgets cannot exceed 65536 bytes")
        if self.enrichment.workers > 16:
            raise ValueError("enrichment.workers must be <=16")
        if self.enrichment.queue_size > 10000 or self.enrichment.timeout > 60:
            raise ValueError("enrichment queue/timeout ceiling is 10000 jobs / 60 seconds")
        if self.active_probes.timeout > 59:
            raise ValueError("active probe timeout must be <=59 seconds including worker budget")
        if self.limits.max_connections > 256:
            raise ValueError(f"limits.max_connections: value {self.limits.max_connections}; expected 1..256 for the portable selector")
        if max(self.limits.first_byte_timeout, self.limits.idle_timeout) > self.limits.total_timeout:
            raise ValueError("first-byte/idle timeout exceeds total timeout")
        if self.lab.enabled and not address.is_loopback:
            raise ValueError("LAB ONLY: bind must be a loopback literal")
        if self.lab.max_duration > 60 or self.lab.max_bytes > 4096 or self.lab.max_connections > 64:
            raise ValueError("lab budgets exceed P0 safety ceiling (60s/4096B/64 connections)")
        if self.active_probes.enabled and not self.active_probes.allowed_cidrs:
            raise ValueError("active probes require an explicit lab allowlist")
        for cidr in self.active_probes.allowed_cidrs:
            if not isinstance(cidr, str):
                raise ValueError("active lab allowlist entries must be CIDR strings")
            network = ipaddress.ip_network(cidr, strict=True)
            if network.version != 4 or network.prefixlen < 24:
                raise ValueError("active lab allowlist must contain IPv4 /24 or narrower")
        for name in (self.probes_path, self.capture.pcap_path,
                     self.deception.secret_file):
            if name and not Path(name).is_file():
                raise ValueError(f"input file does not exist: {name}")
        if self.capture.interface and (len(self.capture.interface) > 256 or
                any(ord(c) < 32 for c in self.capture.interface)):
            raise ValueError("invalid interface")
        if len(self.capture.bpf) > 4096:
            raise ValueError("BPF filter too long")
        if self.logging.file and not Path(self.logging.file).parent.is_dir():
            raise ValueError("log directory does not exist")
        return self

    def _validate_host_enforcement(self):
        """P15.1 §20, §21, §23. What must be true before this may act on a host.

        Every rule refuses a configuration that would be *unsafe*, not one that
        is merely bold. An operator may run a generous block budget; they may not
        run host enforcement with nothing marked as protected, because the first
        thing an autonomous defender gets wrong on a bad day is the address its
        operator is connecting from.
        """
        enforcement = self.enforcement
        if not enforcement.host_enabled:
            return
        if enforcement.enabled:
            # The lab path pins the whole installation to a disposable namespace.
            # Asking for both means asking to enforce in two places at once with
            # one set of protected networks, and neither answer is right.
            raise ValueError(
                'enforcement.enabled (lab namespace) and enforcement.host_enabled '
                'are mutually exclusive: choose the disposable namespace or this host')
        if not self.decision.enabled:
            raise ValueError('enforcement.host_enabled requires the decision engine')
        if not (enforcement.management_networks or enforcement.allowlist):
            raise ValueError(
                'enforcement.host_enabled requires at least one protected network: '
                'set enforcement.management_networks to the addresses you administer '
                'this machine from, or this software can lock you out of it')
        if self.deployment.profile == 'lab':
            raise ValueError(
                'enforcement.host_enabled is for a real host; the lab profile uses '
                'enforcement.enabled and an isolated namespace')
        if max(enforcement.block_seconds) > 43_200:
            raise ValueError('the maximum automatic block stays at 12 hours')

    def _validate_autonomy(self):
        """P15 §187. The settings that let this software act without being asked.

        Every rule here refuses a configuration that would be *incoherent*, not
        one that is merely bold. An operator is allowed to set a low margin or a
        generous block budget; they are not allowed to name a cost profile that
        does not exist, or to ask for hysteresis that works in both directions.
        """
        from .autonomy.cost import PROFILES
        autonomy = self.autonomy
        if autonomy.mode not in ('shadow', 'autonomous'):
            raise ValueError('autonomy.mode: expected shadow or autonomous')
        if autonomy.default_cost_profile not in PROFILES:
            raise ValueError(f'autonomy.default_cost_profile: unknown profile '
                             f'{autonomy.default_cost_profile!r}; known profiles are '
                             f'{", ".join(sorted(PROFILES))}')
        if len(autonomy.cost_profiles) > 256:
            raise ValueError('autonomy.cost_profiles: at most 256 scope mappings')
        for scope, name in autonomy.cost_profiles.items():
            if not isinstance(scope, str) or not isinstance(name, str):
                raise ValueError('autonomy.cost_profiles: scope and profile must be strings')
            if not scope or len(scope) > 128 or not scope.isascii():
                raise ValueError(f'autonomy.cost_profiles: invalid scope {scope!r}')
            if name not in PROFILES:
                raise ValueError(f'autonomy.cost_profiles[{scope}]: unknown profile {name!r}')
        if not 0 <= autonomy.decision_margin < 1:
            raise ValueError('autonomy.decision_margin must be in [0, 1)')
        if not 0 <= autonomy.release_margin <= autonomy.decision_margin:
            # Hysteresis that raised the bar for a known repeat offender, or
            # lowered it for a source nobody has seen before, would be hysteresis
            # pointing the wrong way.
            raise ValueError('autonomy.release_margin must not exceed decision_margin')
        if not 0 < autonomy.minimum_data_quality <= 1:
            raise ValueError('autonomy.minimum_data_quality must be in (0, 1]')
        if not 0 < autonomy.maximum_uncertainty <= 1:
            raise ValueError('autonomy.maximum_uncertainty must be in (0, 1]')
        if autonomy.minimum_behavioural_diversity > autonomy.minimum_signal_diversity:
            raise ValueError('autonomy.minimum_behavioural_diversity cannot exceed '
                             'minimum_signal_diversity')
        if not 1 <= autonomy.minimum_signal_diversity <= 10:
            raise ValueError('autonomy.minimum_signal_diversity must be between 1 and 10')
        if not 0 < autonomy.max_block_share <= 1:
            raise ValueError('autonomy.max_block_share must be a fraction in (0, 1]')
        if autonomy.blocks_per_minute > 600 or autonomy.max_active_blocks > 100000:
            raise ValueError('autonomy block budget ceilings are unreasonably large')
        if autonomy.decision_journal_max_entries > 1_000_000:
            raise ValueError('autonomy.decision_journal_max_entries limit is 1000000')
        if autonomy.enabled and not self.decision.enabled:
            raise ValueError('autonomy.enabled requires the decision engine; there is '
                             'nothing to be autonomous about otherwise')
        if autonomy.enabled and self.enforcement.enabled:
            # P15.5R §2, §4, §33. Two final authorities, silently. With autonomy
            # on, `DecisionEngine` does not construct `TemporaryBlocks` at all,
            # so this configuration used to mean "the lab namespace path is
            # configured and does nothing" — which is exactly the class of quiet
            # disagreement between two components that P15.4 was. The same rule
            # `_validate_host_enforcement` applies between the two enforcement
            # switches applies here between the two decision paths.
            raise ValueError(
                'autonomy.enabled and enforcement.enabled (the P0-P14 lab '
                'namespace path) are mutually exclusive: the P15 authority owns '
                'TEMP_BLOCK when it is enabled, and the lab enforcer would be '
                'configured and never called. Use enforcement.host_enabled for '
                'autonomous host enforcement, or turn autonomy off to keep the '
                'legacy path')
        if autonomy.enabled and autonomy.mode == 'autonomous' and not autonomy.calibrator_path:
            # P15.5R §7, §9. Incoherent rather than merely bold, which is the
            # standard this method applies. An autonomous block needs a
            # calibrated probability and a conservative bound on it; with no
            # calibrator the authority refuses every block with
            # CALIBRATION_UNAVAILABLE. A configuration that asks this software
            # to act without being asked, and does not say what turns its scores
            # into probabilities, is asking for something it has not provided —
            # and the failure would otherwise present exactly as P15.4 did: a
            # healthy sensor, a passing readiness gate, and a recall of zero.
            raise ValueError(
                'autonomy.mode = "autonomous" requires autonomy.calibrator_path: an '
                'autonomous block is taken against a calibrated probability and its '
                'conservative bound, and without a calibrator every block is refused '
                'with CALIBRATION_UNAVAILABLE. Use mode = "shadow" to run the '
                'decision path without one')
        if autonomy.pseudonym_secret_file:
            path = Path(autonomy.pseudonym_secret_file)
            if not path.is_file() or path.stat().st_size > 4096:
                raise ValueError('autonomy.pseudonym_secret_file must be a bounded '
                                 'existing file')
        if autonomy.decision_journal_path and not Path(
                autonomy.decision_journal_path).parent.is_dir():
            raise ValueError('autonomy.decision_journal_path directory does not exist')
        # P15S §31. Refused rather than defaulted. A typo here would file a
        # controlled scan into the benign population, which is the single
        # mistake this setting exists to prevent, and it would do so silently.
        from .autonomy.shadow_export import COLLECTIONS
        if autonomy.shadow_export_collection not in COLLECTIONS:
            raise ValueError(
                f'autonomy.shadow_export_collection must be one of '
                f'{", ".join(COLLECTIONS)}: `real_shadow` is ordinary traffic on '
                f'a deployment, `controlled_positive` is a bounded test against '
                f'an asset you own. They are separated at the point of writing '
                f'because a controlled scan is not benign-population evidence')
        if autonomy.calibrator_path and not Path(autonomy.calibrator_path).is_file():
            # Existence only. Whether the artifact is *usable* — the right
            # formula, the right quantity, a conservative bound — is decided at
            # startup by `autonomy/calibrator.py`, which degrades the component
            # rather than refusing to start, because a sensor that will not run
            # without a good calibrator is a sensor that stops observing on the
            # day its calibrator goes stale.
            raise ValueError(f'autonomy.calibrator_path: no file at '
                             f'{autonomy.calibrator_path}')


def load_config(path=None, *, environ=None, validate=True, require_version=False):
    config = Config()
    if path:
        source = Path(path)
        if source.stat().st_size > 65536:
            raise ValueError("configuration exceeds 64 KiB")
        with source.open("rb") as stream:
            raw = tomllib.load(stream)
        if require_version and 'config_version' not in raw:
            raise ValueError('config_version: Configuration version 1 required; found unversioned P0-P5 config; run config migrate to a new file')
        if require_version and (type(raw['config_version']) is not int or raw['config_version'] != CONFIG_VERSION):
            raise ValueError('config_version: Configuration version 1 required in the file; use config migrate, not an environment override')
        for name, values in raw.items():
            if name in ('probes_path', 'config_version'):
                setattr(config, name, values)
                continue
            if name not in {f.name for f in fields(config)} or not isinstance(values, dict):
                raise ValueError(f"unknown configuration section: {name}")
            section = getattr(config, name)
            for key, value in values.items():
                if key not in {f.name for f in fields(section)}:
                    raise ValueError(f"unknown setting: {name}.{key}")
                if isinstance(getattr(section, key), dict) and isinstance(value, dict):
                    getattr(section, key).update(value)
                else:
                    setattr(section, key, value)
        # Old schema-1 configurations that disabled aggregation also disable its new consumer.
        if not config.correlation.enabled and 'decision' not in raw:
            config.decision.enabled = False
        # Resolve file paths relative to the configuration, independent of cwd.
        for obj, key in [(config, "probes_path"), (config.capture, "pcap_path"),
                         (config.capture, "p0f_db"), (config.enrichment, "mmdb_path"),
                         (config.deception, "secret_file"), (config.logging, "file"),
                         (config.ml, 'model_path'), (config.ml, 'manifest_path'),
                         (config.reliability, 'distribution_path'),
                         (config.reliability, 'anomaly_model_path'),
                         (config.reliability, 'anomaly_manifest_path'),
                         (config.reliability, 'registry_path'),
                         (config.reliability, 'review_queue_path'),
                         (config.reliability, 'review_queue_secret_file'),
                         (config.autonomy, 'calibrator_path'),
                         (config.learning, 'jobs_path'),
                         (config.learning, 'workspace_path'),
                         (config.learning, 'audit_log_path'),
                         (config.web, 'access_log_path'),
                         (config.web, 'secret_file'),
                         (config.challenge, 'secret_file'),
                         (config.challenge, 'previous_secret_file')]:
            value = getattr(obj, key)
            if isinstance(value, str) and value:
                setattr(obj, key, str(source.resolve().parent / value))
        if config.api.token_file:
            config.api.token_file = str(source.resolve().parent / config.api.token_file)
        for obj, key in ((config.storage, 'path'), (config.runtime, 'status_file'), (config.capture, 'ipc_socket')):
            value = getattr(obj, key)
            if isinstance(value, str) and value:
                setattr(obj, key, str(source.resolve().parent / value))
        # Last, and after the relative-path pass, so that nothing resolves
        # against a value this line wrote. The privileged helper is started as
        # `--config <path>` and reads its protected networks from that file, so
        # the unprivileged side has to know which file it is running.
        config.runtime.config_path = str(source.resolve())
    environment = os.environ if environ is None else environ
    for name, text in environment.items():
        if not name.startswith('E4E__'):
            continue
        parts = name[5:].lower().split('__')
        target = config
        if len(parts) == 2 and parts[0] in {item.name for item in fields(config)}:
            target = getattr(config, parts.pop(0))
        if len(parts) != 1 or not hasattr(target, '__dataclass_fields__') or parts[0] not in {item.name for item in fields(target)}:
            raise ValueError(f'unknown environment setting: {name}')
        key = parts[0]
        sample = getattr(type(target)(), key)
        try:
            value = text if isinstance(sample, str) else json.loads(text)
        except (ValueError, TypeError) as exc:
            raise ValueError(f'invalid environment setting: {name}') from exc
        if isinstance(sample, dict) and isinstance(value, dict):
            getattr(target, key).update(value)
        else:
            setattr(target, key, value)
    return config.validate() if validate else config


def redacted_config(config):
    result = asdict(config)
    result['challenge']['secret_file'] = '********' if config.challenge.secret_file else ''
    result['challenge']['previous_secret_file'] = (
        '********' if config.challenge.previous_secret_file else '')
    result['deception']['secret_file'] = '********' if config.deception.secret_file else ''
    result['deception']['secret_env'] = '********'
    result['deception']['secret'] = '********'
    result['api']['token_file'] = '********' if config.api.token_file else ''
    result['autonomy']['pseudonym_secret_file'] = (
        '********' if config.autonomy.pseudonym_secret_file else '')
    return result
