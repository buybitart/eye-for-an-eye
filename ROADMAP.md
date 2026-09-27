# Roadmap

This is the plan. There are no dates. A date will be added only when the project
owner sets one.

Status words used here: **Done**, **In progress**, **Planned**.

## 1. Safe autonomous sensor — Done

Passive observation, bounded queues and storage, privilege separation, a
read-only local API, and safe defaults.

## 2. Local ONNX model — Done, shadow only

A small logistic regression model in ONNX, run locally in a separate process,
with a strict manifest contract. The current model is for watching, not for
blocking.

## 3. Dataset v1 — Done

One reproducible pipeline for three sources: lab traffic, offline capture files
and unlabelled shadow telemetry. Group splits, a frozen test set and leakage
checks.

## 4. Shadow evaluation — In progress

Measure the decision engine on real traffic, in Shadow Mode, on more than one
kind of deployment. Publish what is measured and what is not.

## 5. Open-source release — In progress

Done:

* The licence is chosen: MIT. See [LICENSE](LICENSE).
* The security reporting channel is documented: GitHub Private Vulnerability
  Reporting. See [SECURITY.md](SECURITY.md). The setting itself is enabled by the
  owner once the repository exists.
* One-command install, tested in a clean environment: a release archive with
  `install.sh`, and a Debian package for Ubuntu 24.04.
* Documentation in simple English: [START_HERE.md](START_HERE.md) and
  [docs/BEGINNER_GUIDE.md](docs/BEGINNER_GUIDE.md).

Remaining, and the reason this is still *In progress*:

* The repository has not been published. Creating it, configuring its security
  settings and publishing the release are owner actions; see
  [docs/GITHUB_RELEASE.md](docs/GITHUB_RELEASE.md).
* The release artifacts are unsigned. There is no signing key.

## 6. Limited temporary enforcement — Planned

Today blocking works only inside an isolated Linux network namespace. To make it
useful on a real server it needs:

* a reviewed host-level enforcement path with a hard rollback,
* proof from shadow runs that false blocks are rare,
* a lockout-safe design, so an operator can never lose access to their own
  machine.

## 7. Adaptive local learning — Planned

Make the human-in-the-loop retraining cycle easier to run: better review tools,
model candidate comparison in shadow, and a documented promotion and rollback
process.

## 8. Wider protocol support — Planned

More protocol families in the correlation engine and more decoy profiles.

## Not planned

* Cloud analysis of user traffic.
* A central reputation service.
* Any form of hack-back.
* Automatic promotion of a model without a human decision.

## See also

* [Changelog](CHANGELOG.md)
* [Limitations](docs/LIMITATIONS.md)
