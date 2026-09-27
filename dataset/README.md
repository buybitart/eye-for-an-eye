# Dataset Generation, Collection and Validation

Offline tooling that turns controlled scenarios into a labelled, validated, split dataset for
local risk models. Not part of the production wheel. Nothing here transmits to a public network,
contacts a public address, exploits anything, or uses a decision this system made as a label.

~~~
network scenarios -> events -> correlation windows -> FeatureVector -> labelled dataset -> validation report
~~~

The middle of that pipeline is production code: the packet parser, the correlation engine and the
feature extractor are the ones the sensor runs. There is no second feature implementation.

| module | purpose |
|---|---|
| `schema.py` | `DatasetSample`, label and confidence vocabulary, the model feature contract and every exclusion reason |
| `manifest.py` | dataset and split manifests, hashes, generator and git provenance, reproduce command |
| `builder.py` | RAW -> NORMALIZED -> FEATURES -> LABELED, snapshot policy, per-scenario caps, bounded collection |
| `validator.py` | schema, ranges, masks, labels, duplicates, groups, manifest consistency, readiness gate |
| `deduplicate.py` | exact and near duplicates, duplicate ids, conflicting labels |
| `statistics.py` | feature distributions, label and scenario coverage, balance, `stats_v1.json` |
| `leakage.py` | port, timing, generator-fingerprint and single-feature separation checks |
| `split.py` | deterministic group split with whole-family holdouts; leakage raises |
| `safety.py` | target policy by `ipaddress`, hard bounds, disk budget, interruption safety |
| `store.py` | CSV read and write with the versioned column contract |
| `review.py` | review-friendly export; a reviewer may answer benign, positive or uncertain |
| `cli.py` | `generate`, `validate`, `stats`, `split`, `manifest`, `leakage`, `lab-run`, `export-shadow`, `review`, `diff` |
| `generators/` | seeded behaviour plans and the PCAP renderer |
| `provenance.py` | per-source provenance builders and the grouping key each source uses |
| `collectors/live.py` | live loopback sessions against the production sensor |
| `collectors/pcap.py` | capture sidecars, offline ingestion, capture-group isolation |
| `collectors/shadow.py` | bounded, default-deny shadow collection and the unlabelled pool |
| `generators/capture.py` | packet-level capture generator: TTL, TCP options, segmentation, IPv6 |
| `scenarios/` | the scenario matrix (`matrix-v1.toml`) and its registry |

## Commands

~~~sh
uv sync --frozen --extra capture --extra test
uv run --frozen python -m dataset build --lab --pcap --shadow --output datasets --freeze
uv run --frozen python -m dataset leakage  --dataset datasets/processed/dataset-v1
uv run --frozen python -m dataset validate --dataset datasets/processed/dataset-v1
uv run --frozen python -m dataset stats    --dataset datasets/processed/dataset-v1
uv run --frozen python -m dataset review-queue --dataset datasets/processed/dataset-v1 \
    --stats datasets/stats_v1.json
uv run --frozen python -m dataset lab-run  --scenario scan/sequential/50-ports
~~~

`lab-run` prints the safety context: target, target policy, bounds, expected label, and that it
transmits nothing, and aborts on any target that is not provably local.

These are development commands. They live here rather than in `eye-for-an-eye` because the
production wheel ships the runtime only; see [the dataset report](../reports/DATASET_v1.md) and
[the data card](../docs/DATA_CARD_v1.md).
