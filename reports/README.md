# Reports published with this repository

Two different kinds of document live here. The difference matters, because one
kind is complete and the other deliberately is not.

## Dataset and model reports

Generated from measured JSON artifacts. Every number comes from a dataset
manifest or a file under `models/`; nothing is written by hand.

- [`DATASET_V1_REPORT.md`](DATASET_V1_REPORT.md) - dataset-v1: LAB, PCAP and shadow telemetry
  through one feature pipeline. READY_FOR_BASELINE_TRAINING; automatic enforcement readiness NO.
- [`DATASET_v1.md`](DATASET_v1.md) - the superseded single-source precursor, dataset-v1.0.
- [`model-risk-logreg-v1.md`](model-risk-logreg-v1.md) - first ONNX risk baseline.
  ENGINEERING BASELINE ONLY, quality gate failed, SHADOW ONLY.

The corpora those reports describe are **not** published - they are generated,
and [`docs/RELEASE_CONTENTS.md`](../docs/RELEASE_CONTENTS.md) says why. The
generators, schema, validators and data cards ship; the data is rebuilt.

## Phase reports, and what they cite

The remaining files are development-phase records, published because the
documentation cites their conclusions by name: the P13 full-system audit, the
P14 scoped auto-promotion report, the P15.1 final report and decision
evaluation, the P15.2 final report, the P15.5 final release validation, and the
P15 final autonomous-defence report - plus four small JSON records that the
published test suite reads.

**These reports cite working evidence from their own phase that is not published
here, and you will not find those files.** There are 27 such references across
five of them: baselines, locked test manifests, evidence freezes, calibration
plans, soak and smoke records, and one runtime-integration report.

Three reasons they are absent, none of them an oversight.

* Most are **per-run working files** - a locked corpus manifest, a calibration
  plan, a soak record. Each describes one run on one machine and is the input to
  a report rather than a second copy of it. The conclusions are in the report
  you are reading.
* One, the P15.5R runtime-integration report, is excluded **deliberately**: it
  quotes the development machine directly - account names, absolute paths, the
  exact privileged commands a run was made with.
  [`docs/VALIDATION_STATUS.md`](../docs/VALIDATION_STATUS.md) carries its
  conclusions instead, because sanitising it line by line would have left a
  report whose commands reproduce nothing.
* Publishing a stale evidence file is worse than omitting it. Each was measured
  against a tree that has since moved, so shipping them would put numbers in
  front of you that do not describe the code in this repository.

For the current status of what has and has not been validated, read
[`docs/VALIDATION_STATUS.md`](../docs/VALIDATION_STATUS.md) rather than any
phase report. The phase reports are history; that page is the present tense.
