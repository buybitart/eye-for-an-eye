# Troubleshooting

This page helps when something does not work. The first part is for anybody; the
rest is for administrators.

Two commands answer most questions:

```sh
eye-for-an-eye check-install     # is the installation complete
eye-for-an-eye doctor            # the full technical report
```

`doctor` only looks. It never repairs, downloads, changes permissions or touches
the firewall.

---

# Part One: Common Problems, Simple Fixes

## Command Not Found

```
eye-for-an-eye: command not found
```

**What it means.** The program is installed, but your shell does not know where to
find it.

**The fix.** Add the directory the installer named to your `PATH`:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

To keep it, put that line at the end of `~/.bashrc` and open a new terminal.

The full path always works:

```sh
~/.local/share/eye-for-an-eye/venv/bin/eye-for-an-eye status
```

## Python 3.12 Is Not Installed

Eye for an Eye needs Python 3.12 exactly, not 3.11 and not 3.13.

On Ubuntu 24.04:

```sh
sudo apt install python3.12 python3.12-venv
```

On Debian 12 or 13 the system Python is a different version. Install
[uv](https://docs.astral.sh/uv/) and run `sh install.sh` again. It finds `uv` by
itself and gets a 3.12 of its own. Or point the installer at one you have:

```sh
sh install.sh --python /usr/bin/python3.12
```

## It Says NEEDS SETUP

The message says which of two things it is.

**"installed but not set up yet"**: there is no settings file:

```sh
eye-for-an-eye setup
```

**"does not know where to watch yet"**: there is a settings file but no traffic
source:

```sh
eye-for-an-eye setup --watch website-log --access-log /var/log/nginx/eye-for-an-eye.log
```

Use your real path. `setup` checks it before it accepts it.

## It Runs but Sees No Visitors

The usual cause is the **log format**, not the path.

Eye for an Eye reads one JSON object per line. A default Nginx `access.log` is not
in that format: every line is thrown away, the sensor keeps running, and the count
stays at zero. That looks like nothing happening rather than an error.

```sh
eye-for-an-eye web log-format
```

Install that block in your Nginx `http` section, add the `access_log` line it
prints, run `nginx -t`, reload Nginx, then point Eye for an Eye at the new file.

To see what the reader is actually doing:

```sh
eye-for-an-eye web doctor
```

It reports lines read and lines it could not parse. Many parse errors and no
events is the format problem above.

Other causes: your server has no visitors yet (load a page yourself); the file is
rotated away (point at the live one); or `start_at_end` is on, which is the
default, so history from before you started is not replayed.

## It Cannot Read My Website Log

```
Eye for an Eye is not allowed to read that file.
```

The account running Eye for an Eye does not own the log. Add it to the group that
owns the log. With Nginx on Debian and Ubuntu that group is usually `adm`:

```sh
ls -l /var/log/nginx/            # see which group owns it
sudo usermod -aG adm "$USER"     # then log out and back in
```

Do **not** `chmod 777` the log and do **not** run Eye for an Eye as root to read
it. Both give away far more than the problem needs.

Under systemd the reader is the `eye-for-an-eye` account, not you. Add that
account to the group instead.

## Watching Network Packets Does Not Work

```
live analysis requires the Linux capture-helper IPC; use --pcap offline
```

Live capture needs Linux **and** a separate helper program holding `CAP_NET_RAW`.
The main program never gets that permission, on purpose.

On Windows or macOS it is not available at all. Use a website log.

On Linux, read [PRIVILEGES.md](PRIVILEGES.md) and [INSTALL.md](INSTALL.md).

To read a saved capture file instead, which needs no privileges:

```sh
eye-for-an-eye analyze-pcap capture.pcap --config <your config>
```

That needs the optional `scapy` extra.

## It Says NOT RUNNING

That is an answer, not an error. Nothing is running, so nothing is blocked.

If you started it in a terminal, that window has to stay open. Under systemd:

```sh
systemctl status eye-for-an-eye.service
journalctl -u eye-for-an-eye.service -n 50
```

The unit validates the configuration before starting, so the journal names the
problem.

## It Refuses a Learning File Over Permissions

```
artifact ownership/write permissions rejected
```

A model or calibration file could be modified by another account, so Eye for an
Eye refused to load it. **This is a safety rule working.** A file that decides how
traffic is scored must not be writable by anyone else.

```sh
chmod 644 <the file it named>
```

Work with a `umask` of `022`.

## Automatic Blocking Will Not Start

```
enforcement.host_enabled requires at least one protected network
```

**A safety rule, and it cannot be skipped.** Eye for an Eye does not know which
addresses you administer this machine from, so it will not start blocking.
Without that list, it could lock you out of your own server.

```sh
eye-for-an-eye autonomy readiness
```

That lists what is still missing. Then read
[AUTONOMOUS_MODE.md](AUTONOMOUS_MODE.md), which shows the settings to add.

Do not get past this by inventing a management network. The list must be the real
addresses you connect from.

Before turning it on at all: real-world validation of autonomous blocking is
**pending**. See [VALIDATION_STATUS.md](VALIDATION_STATUS.md).

## nftables Is Not Available

```
nft is not installed
```

Host blocking uses `nft`. Safe Monitoring does not need it and keeps working.

```sh
sudo apt install nftables
```

Installing `nftables` does not turn blocking on. Nothing does except you.

## Stop Says It Has Not Stopped

Stopping is cooperative: `stop` leaves a request and the watching process notices
the next time it looks, every few seconds. Wait a moment, then:

```sh
eye-for-an-eye status
```

Closing the terminal window that says *watching* always works. On this path Eye
for an Eye installs no background service, so nothing is left running hidden.

`stop` never ends any other program. It asks only its own and never acts on a
process id.

## The Debian Package Refuses to Install

```
eye-for-an-eye depends on python3.12; however: Package python3.12 is not installed.
```

The package is refusing rather than installing something that cannot run. On
Ubuntu 24.04, `sudo apt install python3.12`. On Debian 12 or 13, use the release
archive and `sh install.sh` instead. See
[INSTALL_LINUX.md](INSTALL_LINUX.md).

Do not force it with `--force-depends`. It will install and then fail to run.

## Permission Denied While Installing

The installer names the directory it could not write to. Do **not** re-run the
whole installer under `sudo` to get past it: install for your own account, or use
`sudo sh install.sh --system` if you really want a system-wide install.

---

# Part Two: Administrator Detail

## Exit Codes

| Code | Meaning | What to do |
| --- | --- | --- |
| 0 | Success, or ready | If a component is degraded, read the component list. |
| 1 | Not available, or not ready | Check a fresh `status`, and the `doctor` component. |
| 2 | Bad command line or config | Check the field name, schema 1, and the TOML line and column. |
| 3 | A dependency is missing | Install the right locked extra into the virtual environment. |
| 4 | Permission denied | Check the service user, the directory and the secret file. Do not run everything as root. |
| 5 | Storage error | Check schema, writer lease and disk space. Back up before a migration. |
| 6 | Cannot bind the listener | Check the address and port, and whether the service is already running. |
| 7 | `doctor` found something degraded | Read which check. Often optional data, or a platform limit. |
| 130 | You interrupted the command | Check the state after the interrupt. |

## Common First Problems

**"No configuration found."**
Run `eye-for-an-eye setup`, or `eye-for-an-eye demo` for a finite local example.

**A sensor starts and does nothing.**
A sensor needs `capture.pcap_path` or `capture.ipc_socket`. Give it a source.
Do not fix this by running as root.

**`doctor` says `ml: NOT_CONFIGURED`.**
That is normal. There is no model file. The maths engine works alone.

**`doctor` says `database: DEGRADED, not_created`.**
The database has not been created yet. `eye-for-an-eye setup` creates it. It is
not created by `doctor`.

**A honeypot secret is missing.**
`setup` creates the secret file once and never overwrites it. If you replaced
the config, put the original secret file back.

**A port is in use.**
Nothing is ever killed for you. Find the other process yourself. Note that when
the service is running, its own ports show as busy. That is expected.

**The API or metrics port fails to bind.**
That is an explicit degraded component. The main sensor can keep working. A
failure of the main listener rolls back startup and exits.

## API Problems

| Symptom | Check | Action |
| --- | --- | --- |
| Connection refused | `api.enabled`, address, port, `doctor` ports | Fix the config or the conflict, then restart. |
| `/health` 200 but `/ready` 503 | Queue use, component list | Reduce load or fix the core failure. Raise a limit only after measuring. |
| Overall DEGRADED but ready | Storage, enrichment, logging, API, metrics components | Restore the optional dependency. Readiness is about intake, not storage. |
| 401 | `api.token_file`, `Bearer` header | Send the token in a protected client config, never in the URL. Restart after rotation. |
| 403 | `Host` header, `Origin`, proxy rewriting | Use the configured loopback address. Check proxy auth before changing headers. |
| 400 | Timestamp format, page, range, filter, cursor | Fix the request. A source cursor with redaction expires after 300 s. |
| 413 | Byte limit, size of one record | Ask for less, or raise the limit inside the hard ceiling. |
| 429 or the connection closes | Request budget, connection limits, slow clients | Add client backoff. Do not work around admission control with parallel floods. |
| 503 storage unavailable | `storage info`, reader timeout, schema | Narrow the time window or filters. SQL is never sent to the client. |
| `partial = true` in sources or stats | `max_scan_rows`, window size | Counts are a lower bound of a sample. Use a smaller window. |

## Storage Problems

| Symptom | Check | Action |
| --- | --- | --- |
| `storage_write_failures_total` is rising | Free disk, pressure, pinned WAL, write lease | Free space, or close a long external reader. Never delete a live WAL file. |
| Storage unavailable after a startup I/O failure | `doctor`, owner, path | Fix the cause, then restart. The volatile fallback does not replay the queue. |
| A migration was rejected | Database identity and version, backup | Keep the database, look at it offline. Do not force `ALTER` or delete. |

## Logging Problems

**Fewer log lines than database events.** That is expected. The log has its own
budget and its own sampling. Check the sampled, suppressed and dropped counters.

**No log file at all.** `logging.file = ""` means output goes to stdout or the
journal. Do not add a second rotation on top.

## Status Problems

`status` reads a small file, not HTTP. A snapshot older than 5 seconds, or from
a stopped service, is not "ready". Run diagnostics as the same user, with the
same config and the same environment as the service.

## GeoIP or p0f Unavailable

These are optional local data files that you supply. Nothing is downloaded. Do
not draw identity conclusions from missing data. File age comes from the file's
modification time, which is not the same as the data release date.

## Getting More Detail

Add `--debug` for a traceback. Normal output is bounded and redacted.

Config output and errors never contain secret values. Debug output is for you as
the operator, not for a public bug report.

There is no reload on `SIGHUP`. Changing the config or the secret needs a
restart.

## When You Report a Problem

Include:

* the version,
* `doctor` output with secret paths removed,
* health,
* bounded stats and aggregate metrics.

Never include: persistent keys, bearer tokens, credentials, raw traffic, or your
whole environment.

## What Has and Has Not Been Tested

Verified: Windows localhost sockets, SQLite, a sanitised synthetic corpus, and
child-process shutdown. On Ubuntu 24.04 x86_64, the whole beginner path
(install, setup, start, status, stop, uninstall), and installation and removal of
the Debian package.

**NOT VERIFIED:** Linux live capture, the namespace firewall, `CAP_NET_RAW`,
original destination lookup, systemd units under a running systemd, and container
health probes. These need a separately authorised Linux lab or a machine running
systemd as PID 1. They are not presented as passed.

Real-world validation of autonomous blocking is pending. See
[VALIDATION_STATUS.md](VALIDATION_STATUS.md).

## See Also

* [Install on Linux](INSTALL_LINUX.md)
* [Beginner guide](BEGINNER_GUIDE.md)
* [Operations](OPERATIONS.md)
* [Configuration](CONFIGURATION.md)
* [Storage](STORAGE.md)
* [Privileges](PRIVILEGES.md)
