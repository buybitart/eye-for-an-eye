# Model Promotion

Promotion is the moment a new model starts making real decisions. It is the most
dangerous step in the whole learning process, so it is the most restricted one.

**There is no automatic promotion.** `auto_promote` is not a setting you can turn
on. There is no code path that promotes a model without a person running a
command with `--yes`.

Status: **Beta.** Threshold values are provisional and expected to change once
there is enough real evaluation data to set them properly.

## Why Promotion Is Manual

A promoted model decides who gets blocked. If promotion were automatic, then
anyone who could shape the training data could eventually shape who gets blocked,
without a person ever seeing it happen. That is not a small risk in a defensive
tool: it is the whole risk.

So the project keeps a plain rule. The system may **recommend**. Only a person
may **promote**.

## The Two Halves

A quality gate produces a **recommendation**. It changes nothing.

```text
evaluate_gate(...)  ->  PASS | PASS_WITH_WARNINGS | FAIL
recommend(...)      ->  PROMOTE | KEEP_ACTIVE | REJECT | NEED_MORE_DATA
```

A person then runs a **command**. That changes the pointer.

```bash
eye-for-an-eye model promote risk-logreg-v2 --yes --reason "shadow reviewed"
```

Without `--yes` the command refuses and prints what it would have done.

`PROMOTE` is a recommendation, not an action. The registry itself refuses a
promotion that does not carry a passing gate.

## Blocking Checks

A blocking check that fails means `FAIL`, which means `REJECT`. There is no
override and no "promote anyway" flag.

| Check | Why it blocks |
| --- | --- |
| `feature_schema_compatible` | a model built for other features would read garbage |
| `onnx_parity` | the exported model must agree with the trained one (max error 1e-5) |
| `model_size` | above zero, at most 32 MiB |
| `dataset_validation` | the training data passed its own validation |
| `no_group_leakage` | the same source is never in both train and test |
| `block_precision` | precision on the block action may not drop by more than 0.02 |
| `false_blocks` | at most 0.5 more false blocks per 1000 sources |
| `hard_negatives` | at most 0.01 regression on traffic that must never be blocked |

`block_precision`, `false_blocks` and `hard_negatives` are the ones that matter
most. They all measure the same thing from different sides: **does this model
block things it should not?**

A better overall score does not buy a pass on any of them. A model with a better
F1 and a worse hard-negative result is rejected. Blocking a legitimate user is
not paid for by being right more often elsewhere.

## Warning Checks

A warning check that fails means `PASS_WITH_WARNINGS`, which means `KEEP_ACTIVE`:
a person should read the warnings before deciding.

| Check | Why it warns |
| --- | --- |
| `hard_positives` | recall on known automation may not drop by more than 0.05 |
| `inference_latency` | at most twice the active model's latency |
| `pr_auc`, `roc_auc`, `calibration_error` | measured against the active model |

## The Shadow Requirement

Before any recommendation to promote, a candidate must have run in shadow
alongside the active model on at least **500 feature vectors**. Fewer than that
gives `NEED_MORE_DATA`.

One shadow result holds promotion back on its own:

> the candidate would block sources the active model allows

Those disagreements are the expensive ones. They are listed so a person can look
at them before anything is promoted.

## What Promotion Actually Does

One atomic write to `registry.json`:

* the named version becomes `ACTIVE`
* the previous active is recorded as the rollback target and becomes `ARCHIVED`
* the candidate pointer is cleared
* the reason is written into the audit history

No file is copied, moved or deleted. The old model is still there, unchanged.

Restart the service for the change to take effect.

## What Promotion Does Not Do

* It does not delete the previous model.
* It does not change any threshold, any policy rule, or any firewall setting.
* It does not enable enforcement. A promoted model in shadow mode is still in
  shadow mode.

## Related

* [MODEL_REGISTRY.md](MODEL_REGISTRY.md): where versions live
* [MODEL_ROLLBACK.md](MODEL_ROLLBACK.md): undoing a promotion
* [MODEL_EVALUATION.md](MODEL_EVALUATION.md): how the numbers are produced
* [SHADOW_MODE.md](SHADOW_MODE.md): running without enforcing
