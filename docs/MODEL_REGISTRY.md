# Model registry

The registry is a local directory that holds model versions and records which one
the sensor loads.

**It is offline.** There is no remote registry, no download, no upload, and no
central server. Everything here is a file on your own disk.

Status: **Beta.**

## Why this exists

Before the registry there was one model path in the configuration file. Changing
the model meant overwriting a file. That has three problems:

* You cannot go back, because the old file is gone.
* You cannot tell what is running, because the file name says nothing.
* A half-written file is a broken sensor.

The registry fixes all three by making one simple rule: **a version directory is
never modified after it is written.**

## Layout

```text
models/
  registry.json            which version has which role, and a history
  versions/
    risk-logreg-v1/
      classifier.onnx      the model
      manifest.json        what it is, what it was trained on
      distribution.json    the reference distribution for drift and OOD
      model-card.md        optional
      evaluation.json      optional
    risk-logreg-v2/
      ...
```

## Roles

A role is a **pointer**, not a copy. The files never move.

| Role | Meaning |
| --- | --- |
| `ACTIVE` | the model the sensor loads |
| `CANDIDATE` | a new model that runs in shadow only |
| `ARCHIVED` | a version that is neither, kept so you can go back |

A candidate **cannot change a firewall**. It can be scored alongside the active
model so you can compare them, and that is all it can do.

Only one version is `ACTIVE` at a time. Only one is `CANDIDATE`.

## Why a version directory is immutable

Because promotion then becomes a single small write.

Changing which model is active means writing one pointer in `registry.json`.
That write is atomic: a temporary file, an `fsync`, then a rename. The operating
system guarantees a rename either happened or did not. There is no moment where
the registry is half-updated, so there is no moment where the sensor can load
half a model.

If a version directory could be edited in place, none of that would hold.

## What is checked before a version is registered

A candidate is written into a staging directory first, checked, and only then
moved into place. If any check fails, nothing is left behind.

| Check | Why |
| --- | --- |
| `classifier.onnx` and `manifest.json` are present | an incomplete version is not a version |
| model size is above zero and at most 32 MiB | a truncated file, or an implausibly large one |
| `manifest.json` parses | a broken manifest is not usable |
| `feature_schema_version` matches this build | a model for other features would read garbage |
| `model_version` matches the directory name | the manifest must describe this directory |
| `feature_order` matches this build | the same features in a different order is a different model |
| `sha256` matches the file, when the manifest states one | the file was changed after it was written |

The version identifier itself must match `[A-Za-z0-9_.-]{1,80}`. Anything with a
path separator, `..`, or an unusual character is refused before it touches the
filesystem.

## Commands

```bash
eye-for-an-eye model list                 # every version and its role
eye-for-an-eye model candidate            # what the candidate is, and where it came from
eye-for-an-eye model promote <version> --yes
eye-for-an-eye model rollback --yes
```

`model list --json` gives the same information for scripts.

## The audit trail

`registry.json` keeps a bounded history of what happened: candidates registered,
promotions, rollbacks, rejections, and the reason given for each. It answers the
question "why is this model running?" months later.

The history does not contain addresses, review identities, or traffic.

## What the registry does not do

* It does not train.
* It does not decide. A quality gate decides, and a person decides after that.
* It does not delete a version you might need. `ACTIVE`, `CANDIDATE` and the
  rollback target are never prunable.
* It does not fetch anything from a network.

## Related

* [MODEL_PROMOTION.md](MODEL_PROMOTION.md) — how a candidate becomes active
* [MODEL_ROLLBACK.md](MODEL_ROLLBACK.md) — how to undo that
* [ONNX_MODEL.md](ONNX_MODEL.md) — the model format and how it is loaded
* [MODEL_EVALUATION.md](MODEL_EVALUATION.md) — how a model is measured
