# Promotion policy

Every number that decides a promotion, where it lives, and who owns it.

## Read this first

**None of these numbers is measured. None of them is derived from a study. None
of them should be read as a validated or recommended value.**

They are a starting point, chosen to be conservative, by people who have never
run this over production traffic. An operator who changes one is making a
judgement about their own site — they are not correcting an error, and they are
not departing from a standard.

This page states that plainly because a table of thresholds in a security tool's
documentation gets copied, and a number that looks authoritative stops being
questioned. §19 of the P14 brief asks for the same thing in the same words:
tolerance is operator policy, not mathematical truth.

## Version and digest

```
eye-for-an-eye model governance policy
```

A policy has a version — `model-governance-v1` — and a SHA-256 digest of its
contents. The version names the *shape*: which fields exist. The digest catches
every value change, including the one somebody forgets to mention.

Every assessment records the digest it was reached under. **An assessment whose
digest does not match the current policy is stale and authorises nothing.** The
candidate goes back to Shadow and is assessed again. Changing a threshold can
never retroactively promote something (§29).

That is why the digest exists rather than a version string alone: a hand-bumped
version fails in exactly the case that matters, where a tolerance is edited
during an incident and nobody updates the label.

## Shadow requirements

How much observation a candidate needs before its evidence counts at all.

| Setting | Default | Meaning |
| --- | --- | --- |
| `minimum_seconds` | 604 800 (7 days) | elapsed observation |
| `minimum_feature_vectors` | 5 000 | scored windows |
| `minimum_source_groups` | 500 | **distinct** sources — volume from four addresses is not a population |
| `minimum_sites_with_activity` | 1 | for site-scoped models |
| `minimum_trusted_outcomes` | 50 | reviewed outcomes; below this, quality gates answer `NEED_MORE_DATA` |
| `maximum_inference_failure_ratio` | 0.001 | it must run reliably before it runs your traffic |
| `maximum_ood_ratio` | 0.5 | context only; never a refusal on its own |

These are configurable per installation on purpose. One event count applied to
every site would be far too strict for a quiet admin panel and far too lax for a
busy API.

## Regression budgets

How much worse a candidate may be, per dimension, and still be accepted.

| Setting | Default | Notes |
| --- | --- | --- |
| `max_false_block_increase_per_1000` | 0.5 | **benign safety — the tightest budget here** |
| `max_hard_negative_regression` | 0.01 | monitoring, proxies, backups and crawlers |
| `max_block_precision_drop` | 0.02 | security quality |
| `max_hard_positive_recall_drop` | 0.05 | it must not buy precision by ignoring patient scanners |
| `max_latency_increase_ratio` | 1.5 | |
| `max_rss_increase_ratio` | 1.5 | |
| `max_model_load_seconds` | 30.0 | activation must not be a visible pause |
| `max_model_size_bytes` | 33 554 432 | |
| `max_onnx_parity_error` | 1e-05 | training and runtime must agree |
| `max_action_distribution_shift` | 0.25 | a big change in behaviour needs a person |

Note what is absent: **no budget requires the candidate to improve anything.** A
candidate that matches the active model on every dimension and is newer, cheaper
or trained on better data is a perfectly good promotion.

The benign-safety budgets are the tightest deliberately. A candidate that catches
more scanners while blocking more ordinary visitors is not an improvement, and
the visitors it blocks are disproportionately people on unusual networks,
unusual clients and unusual schedules — the ones least able to get a block
lifted.

## Promotion budgets

| Setting | Default | Why |
| --- | --- | --- |
| `minimum_promotion_interval_seconds` | 604 800 (7 days) | churn is its own failure mode |
| `max_promotions_per_day` | 2 | per installation |
| `max_promotions_per_site_per_day` | 1 | |
| `max_rollbacks_per_day` | 3 | |
| `max_concurrent_promotions` | 1 | activation costs memory and CPU |
| `failures_before_freeze` | 3 | repeated failure needs a person, not a retry |

## Rollback thresholds

| Setting | Default | Tier |
| --- | --- | --- |
| `max_inference_failure_ratio` | 0.02 | technical |
| `max_consecutive_inference_failures` | 20 | technical |
| `technical_window_seconds` | 900.0 | so a bad first minute is not a withdrawal |
| `max_latency_increase_ratio` | 2.0 | resource |
| `max_rss_increase_ratio` | 2.0 | resource |
| `sustained_seconds_before_resource_rollback` | 600.0 | so a GC pause is not a withdrawal |
| `minimum_reviewed_outcomes_for_quality_rollback` | 20 | quality — the floor below which it will not act |
| `max_reviewed_false_block_increase` | 3 | quality |
| `max_block_precision_drop` | 0.1 | quality |
| `action_surge_ratio` | 3.0 | freezes advancement; never a withdrawal on its own |

## Guarded stages

| Stage | Ceiling | Time | Vectors | Sources | Reviewed | Max disagreement |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `WATCH` | 24h | 2 000 | 200 | 0 | 20% |
| 2 | `RATE_LIMIT` | 72h | 10 000 | 1 000 | 20 | 10% |

A stage cannot permit less than the one before it — the policy refuses to build
if the ceilings are not monotonic — and no guarded stage reaches `TEMP_BLOCK`.

## Changing it

```toml
[model_governance]
minimum_shadow_seconds = 1209600.0     # two weeks instead of one
minimum_trusted_outcomes = 100
promotion_cooldown_seconds = 2592000.0 # one month
```

After any change:

```
eye-for-an-eye config validate
eye-for-an-eye model governance policy
```

The digest will have changed, which means every existing assessment is now stale
and every candidate is re-assessed under the new numbers. That is the intended
behaviour, and it is the reason you can tighten a policy during an incident
without worrying about a verdict reached ten minutes earlier.

## Two combinations that are refused

```toml
auto_promote_enabled = true
guarded_activation_enabled = false     # refused
```

```toml
auto_promote_enabled = true
auto_rollback_enabled = false          # refused
```

Automatic promotion without a guarded stage sends a candidate straight to full
authority on evidence that cannot cover every production case. Automatic
promotion without automatic rollback is a one-way door. Neither is a supported
configuration, and `config validate` says so rather than accepting it quietly.

## See also

- [MODEL_GOVERNANCE.md](MODEL_GOVERNANCE.md)
- [GUARDED_ACTIVATION.md](GUARDED_ACTIVATION.md)
- [AUTO_ROLLBACK.md](AUTO_ROLLBACK.md)
- [CONFIGURATION.md](CONFIGURATION.md)
