# Governance

This project is small. This page is short on purpose. There is no committee, and
inventing one would be dishonest.

## Who maintains it

One person: the project owner.

**Bus factor: 1.** This is the largest sustainability risk the project has. See
[Sustainability](SUSTAINABILITY.md).

Project lead: `[OWNER INPUT REQUIRED]`

## How decisions are made

Today: the owner decides, in public, in the issue tracker and the changelog.

If the project gains regular contributors, the intended next step is simple:
changes that touch a security boundary need a second reviewer. Nothing more
formal until the project is large enough to need it.

## What counts as a security-sensitive change

These need extra care whatever the project's size:

* Packet parsing.
* The privilege boundary and the capture helper.
* The policy guard and anything that can cause a block.
* The firewall backend.
* Redaction.
* The model loading path.
* The installer.
* Any change to a default value that makes the system less passive.

A change in this list must state its security impact in the pull request, and
must include a test that fails without the fix.

## Model changes

A model is treated as code, because it changes behaviour. See
[Model governance](#model-governance) below.

## Releases

The owner makes releases. The process, the gates and the current release
blockers are in [Release process](RELEASE.md).

There is no signing infrastructure. There is no CI publishing credential.

## Model governance

| Term | Meaning |
| --- | --- |
| **Active model** | The model file the running system loads. |
| **Candidate model** | A new model being evaluated. It runs in Shadow Mode only. |
| **Model version** | For example `risk-logreg-v1`. In the manifest. |
| **Feature schema version** | Currently 1. Checked at load time. A mismatch refuses the model. |
| **Dataset version** | For example `dataset-v1`. Recorded in the manifest. |

### Promotion

A candidate becomes active only after all of these:

1. Schema compatibility: the feature order and shape match exactly.
2. ONNX and scikit-learn parity: the same input gives the same answer.
3. Quality gates: block precision and false blocks per 1000 benign sources.
4. Leakage checks pass.
5. A shadow comparison against the active model.
6. A model card and an evaluation report exist.
7. **A person decides to install it.**

Step 7 is not automatable and is not going to be automated.

### Rollback

Rolling back is putting the previous model file and manifest back and
restarting. Old model files and their manifests are kept. Because a manifest
carries its own hash, an old model can always be verified before it is restored.

If a model is unhealthy at load time, the system does not fall back to a
different model. It runs with the mathematical engine alone. That is a safe
state.

## Contributions

See [CONTRIBUTING.md](../CONTRIBUTING.md).

There is no contributor licence agreement, because there is no licence yet. This
is one more consequence of the open licence blocker.

## Code of conduct

There is none. One will be added if the project gets a community that needs it,
not to fill a checklist. `[OWNER INPUT REQUIRED]`

## See also

* [Sustainability](SUSTAINABILITY.md)
* [Release process](RELEASE.md)
* [Controlled self-learning](SELF_LEARNING.md)
