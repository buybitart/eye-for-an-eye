# Contributing

Thank you for looking at this project. This page says how to set up your
machine, how to run the checks, and what a good change looks like.

You do not need to be a machine-learning expert. Most useful work here is
ordinary Python, tests and documentation.

## Set up

You need CPython 3.12 and `uv`.

```sh
uv sync --frozen --extra capture --extra enrichment --extra test --extra lint --extra quality
```

## Run the checks

Run all of these before you send a change:

```sh
uv run --frozen ruff check eye_for_an_eye dataset training tests benchmarks scripts --no-cache
uv run --frozen mypy eye_for_an_eye
uv run --frozen pytest -q -m "not linux_lab"
uv run --frozen python scripts/security_scan.py
uv run --frozen pip-audit -r requirements/runtime.txt --disable-pip --no-deps
uv run --frozen pytest tests/test_p5_benchmark_smoke.py -q
```

Notes:

* `mypy` checks declared types across the project, and untyped function bodies
  in a few named modules. It is not strict typing of the whole history.
* Security review exceptions are pinned by exact code hash in
  `security/bandit-reviewed.json`. Never refresh them without a review.

## What you can contribute

| Kind | What it means |
| --- | --- |
| Code | Bug fixes, small features, better error messages. |
| Tests | A failing test for a bug is already a good contribution. |
| Lab scenarios | New safe, local traffic scenarios for the dataset. |
| PCAP fixtures | Small, synthetic, sanitised capture files with a sidecar label. |
| Dataset review | Label shadow samples. `UNCERTAIN` is a valid answer. |
| ONNX models | A model, its manifest, its model card and its evaluation. |
| Documentation | Simpler English, missing steps, wrong facts. |
| Translations | Documentation in other languages. |

## Rules that a change must not break

These are the safety promises of the project:

* Defaults stay passive and loopback-only.
* Every queue, buffer and store keeps a limit.
* Redaction keeps working: no payloads, passwords, cookies or tokens.
* Privileges stay minimal. No new privileged daemon.
* No automatic firewall change.
* No Internet scanning, from any code path.
* No external update check and no telemetry.
* No raw secrets in fixtures. Public test material must be clearly synthetic.
* The model never gets identity data as an input.
* Shadow data is never self-labelled.

## Tests

Tests may use temporary state and finite loopback clients.

Namespace firewall tests need `E4E_RUN_NAMESPACE_LAB=1`, setup privileges and a
throw-away Linux host. Use the separate manual platform-lab workflow. **Never
run them on a production machine.**

## Sending a change

Explain four things:

1. What changes for the operator.
2. What changes at a security boundary.
3. How you verified it.
4. What is still missing or unverified.

Update the version, the migration notes and the changelog when they are
affected.

A review looks at failure paths and cleanup, not only at the happy path.

## Model and dataset changes

A model change is a security-relevant change, like a code change. A pull request
that adds or replaces a model must include:

* the model file and its manifest, with a SHA-256 that matches,
* the model card,
* the evaluation report,
* the dataset version it was trained on,
* the feature schema version.

See [Controlled self-learning](docs/SELF_LEARNING.md).

## What we cannot accept

* Code that attacks a third party, in any form.
* Code that sends user data to an external service by default.
* A model without provenance.
* A capture file with real traffic in it.

## Security problems

Do not open a public issue for a security problem. Read [SECURITY.md](SECURITY.md).

## Release

There is no CI publishing and no signing credential. See
[Release process](docs/RELEASE.md).
