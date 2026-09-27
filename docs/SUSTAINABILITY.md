# Sustainability

Can this project still be alive in three years? This page answers honestly.

## The Short Answer

Not as it is today. One person maintains it, and nothing funds it.

## Bus Factor: 1

One person wrote all of it. If that person stops, the project stops.

What reduces the damage today:

* The code is small: about 7 700 lines in the service.
* The architecture, the maths, the feature schema, the data card, the model card
  and the threat model are all written down.
* There are 353 tests.
* Dependencies are pinned and the base runtime has none.
* Nothing depends on a service only the author can reach.

A new maintainer would have documentation and tests to work from. That is not
the same as having a second maintainer.

**Goal: find one more maintainer.** Nothing else on this page matters as much.

## What Keeps Working Without Maintenance

If development stopped tomorrow, an installed copy would keep running:

* No licence key, no account, no subscription.
* No cloud service to shut down.
* No update check that fails.
* No model download.
* No certificate that expires.

It would slowly become less useful, and eventually a dependency vulnerability
would make it unwise to run. But it would not stop working on a schedule
somebody else controls. For the intended users that is a real property.

## Maintenance Load

| Task | How often | Effort |
| --- | --- | --- |
| Dependency updates | Quarterly | Small. The base runtime has no dependencies. |
| Python version support | Yearly | Medium. Currently pinned to 3.12. |
| Security fixes | As needed | Unpredictable. |
| Model updates | Rarely | Medium. Needs the full offline pipeline. |
| Dataset versioning | With a model update | Medium. |
| Documentation | Continuous | Small. |
| Issue triage | Continuous once there are users | Unknown. Currently zero. |

The Python 3.12 pin (`>=3.12,<3.13`) is a real maintenance debt. It must be
widened before 3.12 leaves support.

## Release Process

Documented in [Release process](RELEASE.md). Gates: tests, lint, type check,
security scan, dependency audit, package smoke test, SBOM, checksums.

Two blockers stop any release today: no licence, and no private security
reporting channel.

## Model and Dataset Sustainability

A model ages as traffic changes. The project's answer is that the model is
optional and the mathematical engine is not: an old model can be removed and the
system still works.

Datasets are versioned, hashed and rebuildable with one command, so a future
maintainer can regenerate everything rather than inheriting a mystery file.

## Community

There is no community yet. Zero contributors, zero users, zero issues.

The plan is ordinary: publish, make contributing easy, answer the first issues
quickly and well, and keep the tests green so a newcomer's change either works
or fails clearly.

## Funding

**None.** No funding history, no grant, no sponsor, no revenue.

`[OWNER INPUT REQUIRED]`: whether the owner intends to seek funding, and for
what.

Options that would not break the local-first promise:

* Grant funding for specific deliverables.
* Paid support or deployment help, with the software staying fully open.
* Sponsorship.

Options the project should not take, because they would break its purpose:

* A hosted service that receives users' traffic.
* A shared reputation network as the default.
* An open-core split where the real detection is closed.

## Honest Risk List for a Funder

* One maintainer.
* No users, so no external pressure to keep it alive.
* An unfinished enforcement path, which is the feature users will want most.
* A model that has not met production traffic.
* No external audit.

None of these is hidden anywhere else in this documentation either.

## See Also

* [Governance](GOVERNANCE.md)
* [Distribution](DISTRIBUTION.md)
* [Risks and limitations](RISKS_AND_LIMITATIONS.md)
