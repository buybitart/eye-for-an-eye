# Docker and Compose Lab

This page explains how to build and run the project inside Docker, for lab testing only. Read this if you want to try the honeypot in an isolated container.

## What the Image Is For

The current Docker image is built for a finite, unprivileged TCP honeypot. It is not for live packet capture. There is no Docker engine available in the environment used to check this documentation, so a real build, healthcheck, and Compose test are still a required release gate (a check that must pass before release). The CI (continuous integration) pipeline includes these checks, but the existence of a workflow file is not proof that it has actually run successfully.

The base image is Python 3.12.14, `slim-bookworm` variant. A build-only tool, uv 0.12.10, is pinned to a manifest digest (an exact fingerprint), taken from the registries on 2026-09-08. At runtime it uses UID 10001 and GID 10000, has no capture or enrichment dependencies installed, and can run with a read-only root filesystem. The application metadata version is `0.7.0rc1`, and the image tag is `0.7.0-rc.1-lab`. After a build is accepted, record the final image digest and the OS-package SBOM (Software Bill of Materials. A list of what is inside). A Python-package SBOM does not replace a full container SBOM.

## Setting Up the Isolated Lab

You need: Docker Engine, Compose v2 (with support for `--wait`), a free private subnet at `172.28.77.0/24`, and the project's CLI installed to generate a secret. Before starting, check your network routes for conflicts. The Docker network is `internal`. No ports are published, and host networking is not used.

```sh
umask 077
mkdir e4e-lab
eye-for-an-eye config init --profile honeypot --output e4e-lab/config.toml
export E4E_LAB_SECRET="$(pwd)/e4e-lab/config.secret"
chmod 0600 "$E4E_LAB_SECRET"
sudo chown 10001:10000 "$E4E_LAB_SECRET"
docker compose -p e4e-lab -f docker-compose.lab.yml config --quiet
docker compose -p e4e-lab -f docker-compose.lab.yml build
docker compose -p e4e-lab -f docker-compose.lab.yml up -d --wait --wait-timeout 45 honeypot
docker compose -p e4e-lab -f docker-compose.lab.yml --profile test run --rm client
docker compose -p e4e-lab -f docker-compose.lab.yml exec honeypot eye-for-an-eye status --health-only --config /etc/eye-for-an-eye/config.toml
docker compose -p e4e-lab -f docker-compose.lab.yml down
```

Local Compose secrets keep the ownership and permission mode of the original bind-mounted file. Do not rely on the UID or mode set by Compose as a replacement for real host file permissions. Do not make the file world-readable (readable by everyone). Rootless user-namespace remapping (running Docker without root, with remapped user IDs) needs its own separate setup for the mapped UID. This has not been tested here.

Compose uses the file `deploy/container.toml`, which comes from inside the image. The config file you create is only used to safely pass in the secret. The allowed source addresses are explicitly limited to the lab subnet. The listener binds to `0.0.0.0:1234`, but only inside the internal Docker network. The API (port 8777) and metrics (port 8778) stay on loopback, inside the container only. The client makes one single, limited HTTP request. The container uses `cap_drop: ALL` (removes all Linux capabilities), `no-new-privileges`, and limits on memory, process count (PID), and file descriptors (fd). It has one writable named state volume, plus `/run` and `/tmp` as temporary (tmpfs) filesystems. The healthcheck reads the current local status. It does not run the full `doctor` check.

## Stopping, Updating, and Rolling Back

Running `down` keeps the volume and the secret. Before updating, make a storage backup and save the old image digest. Rolling back needs a compatible database and the previous secret. Do not use `down --volumes` if you still need the telemetry data. It will delete it. See [BACKUP_RESTORE.md](BACKUP_RESTORE.md) for backup and restore steps.

This setup never recommends using `--privileged`, adding all Linux capabilities, or a host-network sensor profile. Any production traffic reaching the deception ports needs a separate security review.

## Pinning Strategy

The strategy for pinning (fixing) versions follows the [Docker build guidance](https://docs.docker.com/build/building/best-practices/): update the image digest only through review, an audit, and a smoke test (a quick basic test), never assume a tag always points to the same, unchanged image.

## See Also

- [DEPLOYMENT.md](DEPLOYMENT.md): all supported deployment methods
- [BACKUP_RESTORE.md](BACKUP_RESTORE.md): backup and restore steps
- [SYSTEMD.md](SYSTEMD.md): running the project as a systemd service instead
