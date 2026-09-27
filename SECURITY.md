# Security policy

Eye for an Eye is **defensive** software. It watches traffic and can, in a test
lab, block a source for a short time. It never attacks anyone.

## How to report a security problem

**Use GitHub Private Vulnerability Reporting.** On the repository page, open the
**Security** tab and choose **Report a vulnerability**. The report stays visible
only to the maintainer until an advisory is published, GitHub handles the
transport, and no address has to be published or kept working.

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**.
3. Fill in the advisory form with the detail listed under *What to put in a
   report* below.

Nothing here invents an email address, a PGP key or a hosted security form. The
channel is a GitHub feature, and it exists exactly as long as the repository
does.

**Status: `OWNER_ACTION_REQUIRED` — not enabled yet.** Private Vulnerability
Reporting is a per-repository setting, enabled by the owner under *Settings → Code
security and analysis → Private vulnerability reporting*. Until it is switched on,
this section describes a workflow rather than an available one, and saying
otherwise would be worse than saying nothing: a reporter who follows a channel
that does not exist discloses to nobody and assumes they have disclosed to
someone.

Until that setting is on:

* Do **not** post credentials, raw traffic, private keys or exploit details in a
  public issue.
* Contact the project owner through an existing private relationship and ask for
  a secure way to send the report.

This repository does not promise a response time.

## What to put in a report

* The version and the schema versions.
* A sanitised way to reproduce the problem.
* The impact.
* The deployment context.

Use a throw-away offline or loopback lab. **Never scan a third party to produce
a report.**

## What is in scope

* Packet and protocol parsing.
* Resource limits and denial-of-service resistance.
* Privacy and redaction.
* Privilege separation, including the capture helper boundary.
* Storage and the read-only API.
* Deployment defaults.
* The model and dataset boundary.
* Supply chain.

The current review target is 0.8.0rc1. There is no approved public support or
security-backport policy. Older P0–P7 versions are not declared supported
releases.

See [Security review scope](docs/SECURITY_REVIEW_SCOPE.md) for the detailed map
an auditor would use.

## Rules for testing this software

* Test only against your own machines.
* Use loopback, an isolated Docker network or a Linux network namespace.
* Never scan the public Internet.
* Never brute-force a service you do not own.
* Never run a denial-of-service test against anyone else.

The dataset tools enforce this in code: a target that is not loopback or an
explicitly listed lab address is rejected.

## Security work done so far

* Internal security review of the source tree, by the project author.
* Static analysis with Bandit. Reviewed findings are pinned by exact code hash
  in `security/bandit-reviewed.json`. Never refresh those hashes without review.
* A narrow secret-pattern scan (`scripts/security_scan.py`).
* Dependency audit with `pip-audit`.

**There has been no external independent security audit.** Do not read the list
above as one.

## Known security boundaries

* The capture helper can see credentials in traffic. It holds `CAP_NET_RAW` and
  nothing else, and it never opens the database.
* Enforcement is lab only and refuses the host network namespace.
* A model file is a security-relevant artefact. It is checked by SHA-256 against
  its manifest before it is loaded.
* The API and metrics endpoints are local only by default. Putting them on a
  public address is your decision and needs authentication and TLS.

## See also

* [Threat model](docs/THREAT_MODEL.md)
* [Security deployment boundary](docs/SECURITY_DEPLOYMENT.md)
* [Privileges](docs/PRIVILEGES.md)
* [Privacy](docs/PRIVACY.md)
