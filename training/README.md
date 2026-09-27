# Offline Research Tools

Not included in the production wheel. Nothing here reads live traffic, opens a network
connection, writes runtime configuration, activates a model or uses a system decision as a
label. See the [training workflow](../docs/MODEL_TRAINING.md), the
[feature schema](../docs/FEATURE_SCHEMA.md) and [datasets](../datasets/README.md).
Python 3.12 with the locked `ml` and `ml-training` extras is required.

| module | purpose |
|---|---|
| `schema.py` | frozen `risk-logreg-v1` model feature contract, exclusions and forbidden columns |
| `corpus.py` | deterministic synthetic scenario families (benign, hard negative, malicious, hard positive) |
| `dataset.py` | versioned dataset build, write and bounded hash-verified load |
| `validation.py` | `validate_dataset()`: columns, schema, ranges, masks, labels, duplicates, balance, leakage |
| `split.py` | group-aware splitting; leakage raises `LeakageError` |
| `train_logreg.py` | controlled LogisticRegression grid, selection, export, parity and quality gate |
| `evaluate.py` | metric functions, threshold table, calibration, coefficients, error analysis |
| `evaluate_model.py` | evaluate an exported artifact without retraining; writes JSON and the report |
| `report.py` | renders `reports/model-<version>.md` from the measured JSON |
| `shadow_replay.py` | replay through the real fusion and policy in shadow; captures disagreements |
| `pcap_evaluate.py` | offline PCAP replay of the labelled lab corpus through features and the model |
| `export_onnx.py` | ONNX export, coefficient widening, manifest write and finalise, tiny fixture |
| `build_dataset.py` | the earlier P7 JSONL corpus generator, kept so `research-v2` stays reproducible |
| `train_baseline.py` | the earlier P7 LR/GBT run, kept for the same reason |

The generated `data/synthetic-v2.jsonl` corpus can be reproduced from `build_dataset.py`;
the fixed small regression subset is retained in `tests/fixtures/p7/regression-v2.json`.
The v1 baseline corpus is `datasets/synthetic-behavior-v3` and is reproducible from
`corpus.py` and `dataset.py` with matching SHA-256 values.
