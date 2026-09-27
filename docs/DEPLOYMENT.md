# Deployment Targets

This page lists which platforms and deployment methods are supported, and how to choose one. Read this before you install the project anywhere beyond your own laptop.

## Platform Status

| Target | Status | What was checked |
| --- | --- | --- |
| Linux x86_64, Python 3.12.14 | SUPPORTED for local, unprivileged CLI use, demos, and offline analysis in this release candidate | Full regression test suite run under WSL2 Linux, with a native filesystem |
| Linux live capture + systemd | EXPERIMENTAL, until platform checks ("gates") are done | Unit file syntax and hardening were reviewed; real lifecycle and capture checks were done separately |
| Docker / Compose internal lab | EXPERIMENTAL | A pinned (fixed-version) template and a CI job exist; there is no local Docker engine to test against here |
| Linux arm64 | EXPERIMENTAL, unverified | No arm64 CI, dependency, or runtime evidence exists yet |
| Windows | EXPERIMENTAL, development only | Python regression tests pass; but POSIX capabilities and ACL (access control list) rules do not work the same way as on Linux |
| macOS, FreeBSD, Kubernetes | UNSUPPORTED | No checks and no production guides exist |
| Any Python version other than 3.12 | UNSUPPORTED | The package's own metadata rejects it |

SUPPORTED here does not mean the project is cleared for public release, and it does not mean it is fully ready for production. The [release gates](RELEASE.md) (required checks before release) are still mandatory.

## Choosing a Deployment Method

| Deployment method | Privileges / directories / ports | Updates and rollback |
| --- | --- | --- |
| Manual venv (Python virtual environment) | Runs as a normal user; keeps private local state. The starter honeypot uses loopback (local-only) TCP ports 1234, 8777, and 8778. | Stop the service, make a backup, create a new venv. To roll back, restore the old venv and a matching (compatible) database. |
| systemd sensor | Uses two dedicated user IDs (UIDs). Only the helper process gets `CAP_NET_RAW` (a Linux permission to read raw network packets). Uses `/etc`, `/run`, `/var/lib`. Talks over Unix IPC (local inter-process communication). The API is off in the template config. | See [SYSTEMD.md](SYSTEMD.md). Use a versioned venv and matching UIDs. |
| systemd listener | Runs as one unprivileged user, using `LoadCredential` (a systemd feature for secrets). Keeps its own separate state. Uses loopback port 1234. | See [UPGRADE.md](UPGRADE.md). Restarts are limited (bounded), and logs go to the systemd journal. |
| Compose lab (Docker Compose) | Runs as UID 10001, with no Linux capabilities, a read-only root filesystem, and an internal-only subnet. No ports are published to the host. | See [DOCKER.md](DOCKER.md). Keep the volume and secret files. To update, switch to a new, checked image digest. |
| Docker live sensor | Not supported by the current image. | Use the systemd helper instead. A host-network variant is not provided. |

The runtime config sets the mode: sensor, honeypot, or lab. "Lab" means a short, finite loopback experiment (10 seconds, in the starter config). The Compose setup runs the honeypot on a clearly allowed, private subnet. No profile ever applies firewall rules automatically. The core egress (outgoing traffic) policy is `disabled` by default, which blocks RDAP lookups and active probes. This is a rule enforced by the application itself — it is not an operating-system sandbox that would also block arbitrary future code.

## Recommended Order of Steps

1. Install the software artifact.
2. Create private directories and a service account.
3. Write the config file.
4. Run structural validation on the config.
5. Run the `doctor` check, using the service's user ID.
6. Run with `--check-config`.
7. Start the service.
8. Check local events, health, and storage.
9. Check that shutdown and backup work.

Do not move an old database into production without first reviewing a migration plan.

## See also

- [DOCKER.md](DOCKER.md) — running the project in Docker
- [SYSTEMD.md](SYSTEMD.md) — running the project as a systemd service
- [UPGRADE.md](UPGRADE.md) — how to upgrade a running deployment
- [RELEASE.md](RELEASE.md) — release gates and checks
- [INSTALL.md](INSTALL.md) — install steps
