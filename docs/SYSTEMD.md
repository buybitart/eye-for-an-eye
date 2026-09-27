# systemd Deployment

This page explains how to install and run Eye for an Eye as a systemd service on Linux. systemd is the standard program that starts, stops, and manages services on most Linux systems. Read this if you plan to install the software on a real Linux server.

## Before you start

The templates in `deploy/systemd` are made for Linux with systemd version 247 or later. They use a systemd feature called `LoadCredential`, which safely passes a secret file to a service.

Check your own Linux distribution too. Checking the syntax of a template does not prove that every kernel (the core of the operating system) restriction will really work on your system. The project has not yet run a full lifecycle test, with all hardening (security-tightening) settings turned on, on its own local machines. A manual CI (continuous integration) test on a lab platform does check that the listener can start, restart, and stop.

## Accounts and files

The `sysusers.d` template creates these system accounts, all without a login shell (`nologin`):

- group `eye-for-an-eye-ipc` = 10000
- analysis user `eye-for-an-eye` = 10001
- capture user `eye-for-an-eye-capture` = 10002

Before applying the template, check that these IDs are free:

```sh
getent passwd 10001
getent passwd 10002
getent group 10000
```

If an ID is already used by something else, pick free IDs instead, and change the `sysusers` file and the `capture` and `analysis` TOML config files to match. Both sides check the IPC (inter-process communication) peer's UID (user ID), so the IDs must agree everywhere.

The administrator does the next steps by hand, on the target host. The application itself never creates accounts and never changes system files:

```sh
sudo systemd-sysusers deploy/systemd/eye-for-an-eye.conf
sudo install -d -m 0750 -o root -g eye-for-an-eye-ipc /etc/eye-for-an-eye
sudo install -m 0640 -o root -g eye-for-an-eye-ipc deploy/analysis.toml deploy/capture.toml deploy/listener.toml /etc/eye-for-an-eye/
sudo install -m 0644 deploy/systemd/*.service /etc/systemd/system/
```

Install the checked Python wheel (a packaged Python program) into `/opt/eye-for-an-eye/.venv`. The code and the venv (Python virtual environment) should belong to `root`, and be read-only for the service user. This is not your system's normal Python installation. Set `capture.interface` to your real network interface name, not the example value `eth0`. Do not start all the systemd units (services) at the same time — first decide which roles you actually need.

For the listener service, create a lasting secret first, in a private staging area, then install only the finished secret file:

```sh
eye-for-an-eye config init --profile honeypot --output staging.toml
sudo install -m 0600 -o root -g root staging.secret /etc/eye-for-an-eye/deception.secret
sudo systemctl daemon-reload
sudo systemctl start eye-for-an-eye-listener.service
sudo journalctl -u eye-for-an-eye-listener.service -n 50 --no-pager
```

`LoadCredential` gives this secret to the service user through a special path (`%d`). The config file only holds a reference to it — the actual secret value is never printed anywhere. Keep the original secret file in a protected backup, in case you need it again.

systemd creates the state and runtime directories for you:

- `/var/lib/eye-for-an-eye` and `/run/eye-for-an-eye` for the analysis service
- the same paths, with a `-listener` suffix, for the listener service

There is no separate `/var/log` directory for this application. The administrator controls how long logs are kept, through `journald` (systemd's own logging system).

For capture, start the analysis service first, and then the capture service. The capture helper program uses `BindsTo` on the analysis service, which means it depends on it directly. After you restart analysis, you must start the helper again yourself, and check that IPC still works. To stop a service, run `systemctl stop` on the relevant unit. Whether to enable the services at boot is a separate decision — make it only after you have checked that start and stop both work correctly.

## Limits and restart behaviour

The analysis and listener services have empty `CapabilityBoundingSet` and `AmbientCapabilities` settings. This means they hold no special Linux "capabilities" (extra permissions) at all. The capture helper has only `CAP_NET_RAW` (permission to build raw network packets), and does not have `CAP_NET_ADMIN` (permission to change network settings). Only the helper is allowed to use `AF_PACKET` (raw packet access).

Other hardening settings applied are:

- `NoNewPrivileges` — the process can never gain new permissions later.
- `PrivateTmp` — it gets its own private `/tmp` folder.
- `ProtectSystem=strict` — most of the filesystem is read-only to it.
- `ProtectHome` — home directories are hidden from it.
- Protection for the kernel and for cgroups. A cgroup (control group) is a Linux feature that limits and groups how much CPU, memory, and other resources a process can use.
- `RestrictSUIDSGID`, `LockPersonality`, and `MemoryDenyWriteExecute` — this last one means memory can never be both writable and executable at once, which blocks a common attack technique.

The allowed network address families include `AF_NETLINK`, which the Scapy library needs for network information. `RestrictNamespaces` and `SystemCallFilter` are not turned on yet, because they still need backend-specific checks first.

Other resource limits: `MemoryMax` is 256 MiB for analysis and 128 MiB for the capture helper. `TasksMax` is 32. `NOFILE` (the maximum number of open files) is 1024. The services can only write to their own state and runtime directories.

If a service fails, systemd restarts it after 3 seconds, up to 3 times within any 60-second window. If the main process exits with code 2, 3, 4, or 6, it is not restarted at all — these codes mean a problem that a restart cannot fix. A failure in `ExecStartPre` (a setup step that runs before the main process starts) also counts toward this same restart limit. The `RestartPreventExitStatus` setting applies only to the main process, and does not replace this overall limit.

If an optional part fails — for example, GeoIP lookups or the API — the service becomes "degraded" (limited, but still running), instead of entering a restart loop. The stop timeout is 12 seconds. This covers a 10-second graceful "drain" wait for the main runtime, plus 3 seconds for the helper.

## Checking your setup

To check the templates without installing them:

```sh
python scripts/verify_systemd.py
```

After installing, on the target machine, check the real, installed service files:

```sh
systemd-analyze verify /etc/systemd/system/eye-for-an-eye*.service
```

Config changes only take effect after a restart. `SIGHUP` and `ExecReload` — ways to reload a config file without a full restart — are not supported.

## See also

- [Installation guide](INSTALL.md)
- [Configuration](CONFIGURATION.md)
- [Deployment](DEPLOYMENT.md)
