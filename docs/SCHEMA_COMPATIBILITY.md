# Schema compatibility

Thirteen stages of development have left about forty version numbers in this
codebase. Most of them are harmless — a stamp on a JSON report so that whoever
reads it knows which shape it is. A few of them are not: if one of those changes
and something old is still on disk, the result is either a refusal to start or,
much worse, a number computed from the wrong columns and reported with
confidence.

This page separates the two, and says what happens on a mismatch. It is checked
by `tests/test_p13_schemas.py`, which fails if a version constant exists in the
code and is not listed here.

---

## The ones that can hurt you

These cross a boundary: something writes them, something else reads them later,
possibly after an upgrade.

| Constant | Value | What carries it | On mismatch |
| --- | --- | --- | --- |
| `decision.features.SCHEMA_VERSION` | 2 | The feature tensor: 23 values + 23 availability flags = 46 float32 columns. Schema 2 (P15.4) **appended** five authentication-outcome columns and redefined none | **Serve what you can, refuse what you cannot.** `decision.features.MODEL_SCHEMAS` lists the schemas this build can serve; a model, anomaly artifact or reference distribution declaring one of them is validated against *its own* schema and fed through `FeatureTransformer.project`, which hands it exactly the columns it was fitted on. A schema outside that table is refused outright. This is the one where a silent mismatch would be worst — the model would run and produce plausible numbers from the wrong columns — which is why the projection is a named, tested function rather than a slice at each call site. **An appended column is safe to project across; a redefined one is not, and must retrain.** |
| `decision.features.CLASSIFIER_SCHEMA_VERSION` | 1 | The schema the shipped classifier was fitted against, and the default target of `FeatureTransformer.project` | **Refuse.** It names a schema that must be in `MODEL_SCHEMAS`; if it is not, this build cannot feed its own classifier and says so at startup rather than projecting to something it invented. |
| `dataset.schema.READABLE_FEATURE_SCHEMA_VERSIONS` | (1, 2) | Which feature schema a stored dataset row may declare | **Read forward.** An older row is loaded with its newer columns explicitly unknown (`features.upgrade`), never zero-filled — "nothing was observed" and "nothing failed" are different claims. A row declaring a newer schema is refused, because this build cannot know what its columns mean. |
| `events.SCHEMA_VERSION` | 3 | `NetworkEvent`, stored as JSON in SQLite | Refuse to parse the row. |
| `storage.sqlite.SCHEMA_VERSION` | 2 | The SQLite database itself | Migrate forward. `storage migrate` applies the steps; `storage info` shows the plan first. A newer database in an older build is refused, not downgraded. |
| `decision.registry.REGISTRY_VERSION` | 1 | `registry.json`, the model pointer and audit trail | Refuse with `unsupported registry_version`. Rollback depends on this file, so guessing is not an option. |
| `config.CONFIG_VERSION` | 1 | The TOML configuration file | An unknown section or setting is refused, not ignored. A typo that loads silently is a setting that is not applied, on a security tool, with no error. |
| `challenge.token.CHALLENGE_TOKEN_VERSION` | 1 | The challenge token, which travels to a browser and back | An unknown version verifies as `unknown_version` — not as valid, and not as an accusation. The client is simply challenged again. |
| `dataset.schema.DATASET_SCHEMA_VERSION` | 2 | Dataset rows on disk | **Read both.** `READABLE_SCHEMA_VERSIONS = (1, 2)`. Version 2 added `site_group`; version 1 files still load, because breaking every dataset on disk to add one optional column would have been a poor trade. |
| `dataset.manifest.MANIFEST_SCHEMA_VERSION` | 1 | `dataset_manifest.json` | Refuse. |
| `decision.distribution.DISTRIBUTION_VERSION` | 1 | `distribution.json`, the OOD reference | Refuse, and run without a reference — which reports `INSUFFICIENT_DATA` rather than pretending to know. |
| `decision.review_queue.REVIEW_QUEUE_VERSION` | 1 | The review queue file | Refuse. |
| `dataset.candidate.CANDIDATE_SCHEMA_VERSION` | 1 | A candidate dataset record | Refuse. |
| `dataset.collectors.pcap.SIDECAR_SCHEMA_VERSION` | 1 | The sidecar written beside a capture | Refuse that capture; others are unaffected. |
| `deception.profiles.CATALOGUE_VERSION` | 2 | Which deception profile maps to which port | Changing this **changes what the machine looks like from outside**, deliberately. It is a controlled change, not a compatibility break, and it is why the value is versioned at all. |
| `web.features.WEB_FEATURE_SCHEMA_VERSION` | 2 | Web behaviour features | Version 2 added `interval_mean_900s`, `interval_cv_900s` and `interval_entropy_900s`, which is what let the P11 risk model see slow enumeration. A version 1 producer is refused. |
| Model `manifest_version` | 1 | Every model manifest | Refuse the model, keep the maths. |
| `decision.onnx_model.MANIFEST_VERSION` | 1 | The shape of the manifest beside an exported model: which keys it carries and what each means. It was an inline literal inside the `expected` dict until P15.5; naming it is what lets `compatibility.py` be asked about it, and a version that nothing can be asked about is a version nobody can check | **Refuse the model, keep the maths.** A manifest this build cannot parse is not guessed at, and the decision path continues on the deterministic engine |
| `training.schema.FEATURE_CONTRACT_VERSION` | 1 | The frozen list of columns a model may see, and their order | Refuse. This is the offline half of the feature schema above: it is what `validation.py` checks a dataset against before anything is trained on it. |
| `dataset.builder.RAW_INDEX_SCHEMA_VERSION` | 1 | The index written beside a raw capture collection | Refuse that collection. |
| `training.jobs.JOB_SCHEMA_VERSION` | 1 | A training job record on disk | Refuse. Jobs are records of what a person ran; a record that cannot be read is not guessed at. |
| `governance.assessment.ASSESSMENT_SCHEMA_VERSION` | 1 | A promotion assessment record in the durable history | Refuse that record. An assessment that cannot be read is not evidence, and promotion falls back to needing a person. |
| `governance.journal.JOURNAL_SCHEMA_VERSION` | 1 | The promotion journal, which says what was in progress when a process died | **Refuse, and freeze promotion.** This is the one file that must never resolve to "nothing was happening", because that reading is exactly what would leave a half-finished promotion in place unnoticed. |
| `governance.guarded.GUARDED_STATE_SCHEMA_VERSION` | 1 | Which model is in a guarded stage, and what it has observed | Refuse. A guarded model whose observation record cannot be read has not earned any authority, and a restart never grants it any. |
| `governance.store.GOVERNANCE_STORE_SCHEMA_VERSION` | 1 | Promotion history and the freeze switch | Refuse, and treat the installation as frozen. An unreadable freeze switch that resolved to "not frozen" would resume automatic promotion after a corruption. |
| `autonomy.journal.JOURNAL_SCHEMA_VERSION` | 1 | The decision journal's *line*: the envelope around one `AutonomousDecisionRecord` — when it was written, and the sanitised record itself. Distinct from `governance.journal.JOURNAL_SCHEMA_VERSION`, which is the promotion journal and answers a different question about a different file | **Refuse that line.** JSONL, so a line this build cannot read costs one entry rather than the file, and a reader skips it rather than interpreting it against the wrong field names. The runtime is unaffected: the journal is read by people and tools, never by the decision path. |
| `autonomy.shadow_export.SHADOW_EXPORT_SCHEMA_VERSION` | 2 | One analytic row per decision, written for independent evaluation: pseudonymous identifiers, a bucketed timestamp, derived features, the probability and its bound, what the system *would* have done, what it did, three empty label fields it never fills in, and — since version 2 (P15S) — a `provenance` block naming the source type, the ingestion mode, the label authority, the collection (`real_shadow` or `controlled_positive`), the sensor placement and the evidence segment | **Refuse that row.** The consumer is an evaluation tool that may be newer or older than the sensor that wrote the file, and a row read against the wrong field names would put a number in the wrong column of an analysis nobody would question afterwards. Version 1 is the sharper case rather than a lenient one: it has no `provenance`, so a reader cannot tell a real deployment's row from a controlled test's, and the safe reading of "absent" is not "real shadow". Refusing one row affects neither the others nor the runtime — §11 is explicit that export never blocks traffic processing. |
| `autonomy.shadow_evidence.SHADOW_EVIDENCE_SCHEMA_VERSION` | 1 | The freeze manifest and the period summary: which export files a result was computed from, their sizes and SHA-256 hashes, the build and configuration that produced them, the profile mapping and its digest, the declared window, the writer's own retention counters, and the counts the evidence supported at the instant it was frozen | **Refuse the manifest.** It is the record that says which bytes a published result was computed from, so a reader who cannot parse it cannot check the result — and a manifest read against the wrong field names would verify the wrong files and report MATCH. Nothing in the runtime reads this; it is written and read by the evaluation commands. |
| `autonomy.shadow_result.SHADOW_RESULT_SCHEMA_VERSION` | 1 | The release numbers computed from a frozen period: false would-blocks per 1,000 reviewed benign sources with its 95% upper bound, would-block precision with its lower bound, the two recalls kept apart, the per-profile breakdown, the sufficiency and degeneracy checks, the verdict and the assumptions it rests on | Refuse the document. It carries a PASS/FAIL/INSUFFICIENT_EVIDENCE verdict and the sample sizes that verdict depends on; a build that read it against the wrong field names could report a verdict with numbers that did not produce it. It is recomputable — rerun `autonomy result` against the freeze manifest — so refusing costs nothing but the rerun. |
| `autonomy.shadow_reconcile.RECONCILE_SCHEMA_VERSION` | 1 | The cross-surface check: the decision journal and the shadow export joined by `decision_id`, what they agree and disagree about, the decisions present in only one of them, and the structural differences between the two files that are not disagreements | Refuse the document. It is a statement about whether two evidence files describe the same decisions, and a reader that misread it could report AGREE for a window whose files had come apart. Like the result, it is recomputable by rerunning `autonomy crosscheck`. Note that this module also refuses individual *journal lines* whose `journal_schema_version` it does not know, for the same reason the export refuses unknown rows. |
| `autonomy.review.REVIEW_VIEW_VERSION` | `shadow-review-view-v1` | The blinded view a labeller sees: an export row with every decision field removed, so that the label a person writes is independent of the decision it is being used to measure (`docs/SHADOW_VALIDATION_PLAN.md`) | **Refuse the pack.** Labels are joined back to decisions by `decision_id`; a join made against field names this build reads differently would attach the wrong label to the right decision, and the false-block rate computed from it would be wrong in a way no reader of the result could see. Nothing in the runtime reads this — it is produced on request and consumed by people. |
| `autonomy.record.DECISION_RECORD_VERSION` | 1 | An `AutonomousDecisionRecord` — the answer to "why was this source blocked", written to the decision journal when one is configured | Refuse that record. Reading it against the wrong field names would produce a confident account of a decision nobody made, which is worse than having no account. Refusing one record affects neither the others nor the runtime. |
| `security.enforcement.ENFORCEMENT_REQUEST_VERSION` | 1 | The value that crosses the privilege boundary: address, family, TTL, decision id, reasons — and no command field | **Refuse.** The privileged helper parses this and nothing else. An unknown version is a request it must not guess at, and an unknown *field* is refused rather than ignored, because a field it does not understand is either newer than it or an attempt to smuggle one in. |
| `security.host_firewall.HOST_FIREWALL_SCHEMA_VERSION` | 1 | The owned nftables table's shape: two timeout sets, one chain, two rules | Refuse to adopt. Ownership is proved by a comment, not a name, so a table this build does not recognise is somebody else's and is left alone. |
| `decision.calibration.CALIBRATION_SCHEMA_VERSION` | 1 | The calibrator artifact on disk: method, source quantity, model binding, knots, and the conservative knots a block is justified with | Refuse to load. A calibrator this build cannot fully validate produces a probability nobody can account for, and the decision path degrades to `CALIBRATION_UNAVAILABLE` — no autonomous block — rather than guessing. |
| `decision.scores.SCORE_CONTRACT_VERSION` | 1 | Which numbers on the decision path are probabilities and which are not. Bumped when a score changes meaning, never when one changes value | Refuse to run the decision path. A units contract a build disagrees about is the P15.1 bug with a version number on it. |

## The ones that are only labels

These are stamped on JSON output so that whatever reads it knows the shape. None
of them is persisted across an upgrade, and none of them gates behaviour. They
exist so that a future change to a report format is visible to its consumer.

`challenge.page.CHALLENGE_PAGE_VERSION`,
`challenge.policy.CHALLENGE_POLICY_VERSION`,
`challenge.service.CHALLENGE_SERVICE_VERSION`,
`decision.candidate.COMPARISON_SCHEMA_VERSION`,
`decision.retraining.RETRAINING_ADVICE_VERSION`,
`sites.baseline.SITE_BASELINE_SCHEMA_VERSION`,
`sites.engine.SITE_ENGINE_SCHEMA_VERSION`,
`sites.models.SITE_MODEL_SCHEMA_VERSION`,
`sites.profile.SITE_PROFILE_SCHEMA_VERSION`,
`sites.state.SITE_STATE_SCHEMA_VERSION`,
`web.doctor.WEB_DOCTOR_SCHEMA_VERSION`,
`web.event.WEB_EVENT_SCHEMA_VERSION`,
`web.gateway.WEB_GATEWAY_SCHEMA_VERSION`,
`web.identity.IDENTITY_SCHEMA_VERSION`,
`web.lab.WEB_LAB_SCHEMA_VERSION`,
`web.nginx.NGINX_READER_VERSION`,
`web.sensor.WEB_DECISION_SCHEMA_VERSION`,
`web.state.WEB_STATE_SCHEMA_VERSION`,
`governance.engine.GOVERNANCE_ENGINE_VERSION`,
`governance.activation.ACTIVATION_SCHEMA_VERSION`,
`governance.monitor.MONITOR_SCHEMA_VERSION`,
`governance_cli.GOVERNANCE_CLI_SCHEMA_VERSION`,
`autonomy.runtime.READINESS_SCHEMA_VERSION`,
`autonomy.selfcheck.SELFCHECK_FIXTURE_VERSION` (which two synthetic vectors the
decision self-check pushes through the pipeline; a verdict about "the loud
vector" is uninformative if the loud vector moved without saying so),
`autonomy_cli.AUTONOMY_CLI_SCHEMA_VERSION`,
`security.firewall_helper.HELPER_SCHEMA_VERSION`,
`security.host_enforcer.HOST_ENFORCER_SCHEMA_VERSION`,
`training.decision_replay.REPLAY_SCHEMA_VERSION`,
`training.evaluation_design.DESIGN_SCHEMA_VERSION`,
`training.p15_2_evaluation.P15_2_EVALUATION_VERSION`,
`training.p15_3_evaluation.P15_3_EVALUATION_VERSION`,
`training.parity_fixture.PARITY_FIXTURE_VERSION`,
`training.invariants.BASELINE_SCHEMA_VERSION`,
`training.p15_5_baseline.P15_5_BASELINE_SCHEMA_VERSION` (the shape of the
P15.5 record of *which parts* are frozen, as distinct from the P15.4 record
of which values may not move),
`training.p15_5_soak.SOAK_SCHEMA_VERSION` (the shape of the bounded
mixed-behaviour resource run: what accumulated and what did not),
`training.p15_5_smoke.SMOKE_SCHEMA_VERSION` (the shape of the whole-system
wiring document: what each stage between a packet and an `EnforcementRequest`
produced, per behaviour),
`training.p15_4_ablation.ABLATION_SCHEMA_VERSION` (the shape of the
authentication, composition and maturity ablation documents),
`training.calibration_unit.CALIBRATION_UNIT_SCHEMA_VERSION`,
`training.p15_4_loso.LOSO_SCHEMA_VERSION`,
`training.p15_4_evaluation.P15_4_EVALUATION_VERSION`,
`training.p15_5_evaluation.P15_5_EVALUATION_VERSION` (the shape of the P15.5
locked measurement; it adds the whole-system smoke verdict to Gate C and the
per-profile block eligibility the gates are read against),
`decision.auth.AUTH_SCHEMA_VERSION` (the shape of a normalised
`AuthenticationEvent`; its five result states are a closed vocabulary and
adding one is a shape change),
`correlation.auth_state.AUTH_STATE_SCHEMA_VERSION` (the bounded per-source
authentication history: counts, and keyed pseudonyms that never leave the
process),
`training.observability.OBSERVABILITY_SCHEMA_VERSION`,
`training.failure_matrix.FAILURE_MATRIX_VERSION`,
`training.calibrate.CALIBRATION_SCHEMA_VERSION` (the comparison document the
fitter writes, not the artifact — that one is below),
`dataset.schema.FEATURE_SCHEMA_VERSION` (an alias of the feature schema above),
`dataset.schema.MODEL_FEATURE_LIST_VERSION`.

## Named algorithm versions

Not compatibility numbers at all. These name a *formula*, so that a decision
record from six months ago can be read against the arithmetic that produced it.
Changing one changes what the system decides, and the old name stays readable in
the record.

| Name | Value | Means |
| --- | --- | --- |
| `decision.math_risk.VERSION` | `math-risk-v4` | The deterministic network risk formula. **v4 (P15.4) changes the shape, not the ingredients**: a weighted sum of features becomes a score per evidence family (`decision.families`) and a composition over those (`decision.composition`). A sum cannot express "several weak independent behaviours are collectively strong" without individual weights large enough to let one ambiguous feature act alone — which is exactly how a weight-3.0 credential-*presence* term blocked 21 of 22 sources of a legitimate authenticated batch client under v3. `evaluate_v3` stays runnable, so a record written under v3 can be recomputed rather than merely believed, and so the composition ablation has something to compare against. **A calibrator fitted to v3 must not be used with v4**: the artifact names the formula it maps, and a mismatch degrades the decision path to `CALIBRATION_UNAVAILABLE` rather than mapping a v4 score through a v3 curve. Earlier: v2 (P15.3) added `deception_60s` and `connections_60s` terms and re-normalised destination breadth, so that `DECEPTION_INTERACTION` and `NETWORK_RATE` became evidence families the engine can produce at all. v3 (P15.3, same cycle) removed the patience discount: the same port count over the 900-second window was normalised against twice the anchor *and* weighted half as much, so identical evidence was worth four times less to a slow source than to a fast one. v3 re-anchors the long window to the short one and splits each family's total weight evenly across the two, leaving every family's total unchanged. It also lowers the destination-breadth ceiling to twice its floor, because the previous ceiling was above the number of addresses the protected host has, so touching all of them could not score full breadth. `WEIGHTS_V1` and `WEIGHTS_V2` stay readable so a record written under either can be interpreted against the arithmetic that produced it |
| `web.risk.WEB_RISK_VERSION` | `web-math-risk-v2` | The web risk formula. v2 let path enumeration and automation timing read the 900-second window, which is what made a patient scanner visible |
| `dataset.manifest.GENERATOR_VERSION` | `dataset-generator-1.0` | Which generator built a dataset |
| `dataset.scenarios.captures.CAPTURE_CORPUS_VERSION` | `1.0` | The labelled capture corpus |
| `dataset.collectors.shadow.SHADOW_WORKLOAD_VERSION` | `1.0` | The shadow replay workload |
| `training.corpus.CORPUS_VERSION` | `synthetic-behavior-v3` | The current training corpus |
| `training.build_dataset.DATASET_VERSION` | `synthetic-behavior-v2` | The frozen earlier corpus, kept only so it stays reproducible. Its `label_source` is deliberately outside the current accepted vocabulary — see `training/schema.py` |
| `training.schema.MODEL_VERSION` | `risk-logreg-v1` | Which model the offline pipeline builds and evaluates by default. Not a compatibility number: it names the artifact, and the registry is what decides which artifact is active |
| `governance.policy.GOVERNANCE_POLICY_VERSION` | `model-governance-v1` | The *shape* of the promotion policy. Bumped when a field is added or removed, never when a threshold changes — a threshold change is caught by the policy's content digest instead, which nobody can forget to update. An assessment reached under a different digest is stale and must be taken again |
| `autonomy.cost.COST_POLICY_VERSION` | `cost-policy-v1` | The *shape* of the cost model: which profiles exist and what fields they carry. Like the governance policy above, a changed **value** is caught by the content digest rather than by this name, and every decision record carries that digest — because "why was this blocked" is asked weeks later, and the answer depends on what a false block was deemed to cost at the time |
| `decision.policy.POLICY_GUARD_VERSION` | `policy-guard-v1` | The reduction algorithm in `PolicyGuard.apply`: which conditions may weaken an action, which address classes refuse one outright, and the invariant that nothing here can ever *raise* an action. Named for the same reason the authority below is — a record saying "PolicyGuard refused" is uninterpretable without knowing which PolicyGuard, and the guard is the last thing standing between a decision and a firewall rule |
| `autonomy.authority.AUTHORITY_VERSION` | `autonomous-decision-authority-v1` | The final ALLOW / TEMP_BLOCK algorithm: the order of its gates and the arithmetic between them. Changing it changes what the system decides, so the old name stays readable in every record it produced |
| `autonomy.pipeline.PIPELINE_VERSION` | `autonomous-decision-pipeline-v1` | The *order* in which a window becomes a decision — scope, calibration, authority, enforcement — and the four separately named refusals between a TEMP_BLOCK record and a firewall request. It carries no arithmetic of its own, which is the point: P15.4 happened because two assemblies of the same correct components disagreed, so `decision_inputs` here is the only copy and both the runtime and `training/decision_replay.py` call it. A changed name means the runtime and the evaluator would build a decision differently, which is the one difference no benchmark can detect from its own results |
| `autonomy.scope.SCOPE_RESOLVER_VERSION` | `autonomy-scope-resolver-v1` | Which cost profile prices a decision: the scope vocabulary (`SITE:<id>`, `SERVICE:<port>/<proto>`, `GLOBAL`) and the rule that the most protective candidate wins when one window belongs to several. It decides *which cutoff a block was taken against*, so a record naming an older resolver was priced by rules this build no longer applies. P15.5 found that every locked benchmark since P15.1 had been priced at one profile because this step did not exist |
| `autonomy.calibrator.CALIBRATOR_LOADER_VERSION` | `autonomy-calibrator-loader-v1` | Which calibration artifact a *running sensor* is entitled to use, as distinct from which artifact is well-formed — that second question is `decision.calibration`'s. The three build-compatibility checks it adds (source quantity, formula version, a conservative bound) are what stand between a monotone, finite, digest-matching artifact fitted on `math-risk-v3` and a probability computed from a quantity this build no longer produces |
| `decision.families.FAMILY_SCORE_VERSION` | `family-scores-v1` | How a feature vector becomes one score per evidence family: which features belong to which family, how each is normalised, how a family combines its own features, and how reliable each family is held to be. It is separate from the composition below because the two answer different questions — *what did this source do* and *what does doing all of it at once mean* — and because changing one without the other is a legitimate change that a reader of an old decision record has to be able to tell apart. The split between families that may **carry** a decision (what a source did: port breadth, protocol behaviour, authentication behaviour, decoy interaction, HTTP discovery) and families that may only **corroborate** (how it did it: rate, timing, persistence) lives here, and it is the reason a monitoring agent with perfectly regular timing cannot be blocked for being regular |
| `decision.composition.COMPOSITION_VERSION` | `evidence-composition-v1` | How family scores become one score: noisy-OR over the carrying families, plus bounded interaction terms for co-occurrences that mean more together than apart. The method, the interaction list, and each interaction's strength are all part of this name, because changing any of them changes what the system decides. Its `audit()` is what checks the composition does not double-count a family through an interaction it already contributed to |
| `autonomy.maturity.MATURITY_SCHEMA_VERSION` | 1 | The shape of an evidence-maturity policy: which paths to maturity exist (standard, long-duration, strong-multi-signal) and what each requires of observation count, elapsed time, data quality, and evidence diversity. Maturity decides **when there is enough evidence to act at all**, never how malicious something is, and `MaturityPolicy.__post_init__` refuses a configuration that weakens the standard floor. A record naming an unknown version is refused rather than read against whichever rules this build happens to have, because "was there enough evidence" is the question every block is defended by |
| `training.p15_4_test_policy.TEST_POLICY_VERSION` | `p15.4-test-policy-v1` | The P15.4 acceptance standard, and a separate name from P15.3's on purpose: the two ask different questions, and a later cycle's policy must never be able to make an earlier result read as though it had cleared this one. Every value in it is imported from the code in force rather than transcribed, so the committed standard and the running system cannot disagree without the digest changing — and the digest is recorded in the freeze commit, before the locked corpus exists |
| `training.p15_5_test_policy.TEST_POLICY_VERSION` | `p15.5-test-policy-v1` | The P15.5 acceptance standard, and a separate name from P15.4's for the same reason P15.4's was separate from P15.3's: a later cycle's policy must never be able to make an earlier result read as though it had cleared this one. It adds one condition no previous policy had — the whole-system smoke test must pass — and it declares profile block eligibility as a *rule* evaluated against the artifact in force, committed before the calibrator was refitted |
| `training.p15_5_calibration_plan.CALIBRATION_PLAN_VERSION` | `p15.5-calibration-plan-v1` | How much new calibration evidence P15.5 committed to collecting, and the arithmetic the amount was derived from, written before any of it existed. A name rather than a shape number because the point of the document is that it was fixed *at a time*: the digest is in the commit that precedes the first generated corpus, so "we generated until the number was convenient" is refutable rather than merely denied |
| `training.test_policy.TEST_POLICY_VERSION` | `p15.3-test-policy-v1` | Which acceptance standard a locked benchmark was scored against. A name rather than a shape number, for the same reason as the two above: a later cycle that writes its own policy must not be able to make an earlier result read as though it had cleared this one. The policy's *content* is caught by its own digest, recorded in the freeze commit before the benchmark is generated |

## The rule for adding one

If the new number gates behaviour or is written to a file that outlives the
process, it belongs in the first table and needs a stated answer to "what
happens when an old one is found". If it is a label on a report, the second
list is enough. Either way it has to appear here, because
`tests/test_p13_schemas.py` reads the source and checks.

## See also

* [FEATURE_SCHEMA.md](FEATURE_SCHEMA.md) — what the 46 columns are
* [STORAGE.md](STORAGE.md) — the database and its migrations
* [MODEL_REGISTRY.md](MODEL_REGISTRY.md) — how model versions and roles are stored
* [UPGRADE.md](UPGRADE.md) — the upgrade procedure
