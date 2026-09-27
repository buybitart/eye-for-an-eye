# Dataset

The model has to learn from something. This page says what that something is,
where it comes from, and what the rules are.

The full detail is in [the data card](DATA_CARD_v1.md) and
[the dataset report](../reports/DATASET_v1.md). This page is the short version.

## The Hard Safety Rule

Traffic for the dataset is produced **only** in these places:

* `127.0.0.1` (your own machine),
* an isolated Docker network,
* a Linux network namespace,
* a synthetic event generator,
* an offline capture file, replayed from disk.

Never, under any option or flag:

* the public Internet,
* random public addresses,
* someone else's server,
* brute force against a real service,
* denial of service,
* an exploit or a destructive payload.

This is enforced in code. `dataset/safety.py` refuses any target that is not
loopback or an address you explicitly listed as a lab address. It also refuses
documentation ranges and globally routable addresses.

## The Three Sources

Real ground truth and real packets are two different things. One dataset alone
cannot give you both, so the project uses three sources and never pretends they
are equal.

| Source | What it gives | Who decides the label |
| --- | --- | --- |
| `LAB` | Ground truth. You know what the scenario was doing. | The scenario, decided before it ran. |
| `PCAP` | Packet realism: retries, losses, odd flags, IPv6. | A sidecar file next to the capture. |
| `SHADOW_UNLABELED` | Real observation, with no ground truth. | **Nobody. It has no label.** |
| `SHADOW_REVIEWED` | Shadow rows a person looked at. | A human reviewer. |

Two rules follow from this table:

* **A capture file name is never a label.** The label comes from the sidecar,
  which is a separate file with its own provenance.
* **Shadow data is never self-labelled.** The system's own action is context, not
  truth. A shadow row that arrives with a supervised label is rejected by the
  validator.

## One Pipeline

All three sources go through **the same production code**: the same packet
parser, the same correlation engine, the same `FeatureVector`. There is no
second, training-only feature path.

This matters more than it sounds. If training used a different transformation
from the running system, every measured number would be a lie.

## Splitting the Data

The split is **by group**, never by row.

* A LAB group is one scenario run.
* A PCAP group is one whole capture file.
* A shadow group is one pseudonymous source.

If you split by row, two windows from the same scanner run land on both sides,
and the model looks brilliant while having learned nothing. Group splitting
stops that.

The test set is **frozen**. It is written once and reused, so a later model
cannot be tuned against it by accident.

## Leakage Checks

After each build, the pipeline asks whether the model could cheat:

* **Port leakage**: could it win by memorising a port number?
* **Timing leakage**: do the generators have a timing signature?
* **Generator fingerprint**: can you tell which script wrote a row?
* **Source-type leakage**: can you tell LAB from PCAP from SHADOW?
* **Single-feature leakage**: does one feature alone separate the classes?

Results go into `datasets/manifests/dataset-v1-leakage.json`. When a check
fails, the fix is to repair the generator, not to soften the report.

## What a Dataset Row Contains

A row has behaviour numbers, a label, a label source, a group key and
provenance. It does **not** contain payloads, credentials, cookies, tokens,
command text or an IP address.

The complete list of columns that may never become a model input, with a reason
for each, is in `dataset/schema.py` (`NEVER_MODEL_INPUT`) and in
`datasets/model_features_v1.json`.

## Commands

```sh
# build the full dataset from all three sources
python -m dataset.cli build

# check an existing dataset
python -m dataset.cli validate
python -m dataset.cli leakage
python -m dataset.cli stats

# see the safety context of a lab scenario before running it
python -m dataset.cli lab-run --scenario <name>

# export shadow observations, unlabelled
python -m dataset.cli export-shadow

# work through the review queue
python -m dataset.cli review-queue
```

## What Is in the Repository and What Is Not

| Path | In the repository? | Why |
| --- | --- | --- |
| `docs/DATA_CARD_v1.md` | yes | It explains the dataset. |
| `datasets/manifests/*.json` | yes, except the large validation files | Provenance and hashes. |
| `datasets/raw/`, `datasets/processed/` | no | Generated. Rebuild with the CLI. |
| `datasets/unlabeled/` | **never** | It is observation data from a live system. |
| `*.dataset-secret` | **never** | It is a secret. |

## See Also

* [Controlled self-learning](SELF_LEARNING.md)
* [Feature schema](FEATURE_SCHEMA.md)
* [Model training](MODEL_TRAINING.md)
* [Privacy](PRIVACY.md)
