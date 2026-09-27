# Install

There are three ways to install. Pick the first one unless you have a reason not
to.

Nothing here is published to PyPI or to any package registry. You install from a
local copy of the source, or from a wheel file you built yourself.

## What you need

| Item | Value |
| --- | --- |
| Operating system | Linux x86_64 (tested) |
| Python | 3.12 only (`>=3.12,<3.13`) |
| Disk | about 100 MB |
| Rights | a normal user. No root. |

Windows and macOS work for development only. Live packet capture needs Linux.

The base program has **no** Python dependencies. Extras are optional:

| Extra | What it adds | Needed? |
| --- | --- | --- |
| `capture` | scapy, for live capture and PCAP reading | for live traffic |
| `ml` | onnxruntime, onnx, numpy | to run a model |
| `enrichment` | maxminddb, ipwhois | optional, off by default |
| `test`, `lint`, `quality`, `ml-training` | development only | no |

## 1. The installer (recommended)

```sh
sh scripts/install.sh
```

It finds Python 3.12, makes a virtual environment, installs the program, creates
a safe configuration and creates the empty database.

Useful options:

```sh
sh scripts/install.sh --help
sh scripts/install.sh --dry-run                    # show every step, change nothing
sh scripts/install.sh --prefix ~/apps/e4e          # choose where the program goes
sh scripts/install.sh --data-dir ~/e4e-data        # choose where the data goes
sh scripts/install.sh --profile honeypot           # a different first profile
sh scripts/install.sh --wheel dist/eye_for_an_eye-0.8.0rc2-py3-none-any.whl
sudo sh scripts/install.sh --system                # /opt and /var/lib
```

Default locations for a user install:

| What | Where |
| --- | --- |
| Program | `~/.local/share/eye-for-an-eye/venv` |
| Data and configuration | `~/.local/share/eye-for-an-eye/data` |
| Command | `~/.local/bin/eye-for-an-eye` |

The installer never changes the firewall, never enables blocking, never enables
active probes, and never starts or enables a service.

To remove it:

```sh
sh scripts/uninstall.sh            # keeps your data
sh scripts/uninstall.sh --purge    # deletes your data too
```

## 2. By hand, with a virtual environment

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install .
eye-for-an-eye --version
eye-for-an-eye demo
```

With the optional extras:

```sh
python -m pip install '.[capture,ml]'
```

Do not use `sudo pip` into the system Python.

## 3. A pinned install with uv

The project ships `uv.lock`, so a locked, repeatable install is possible:

```sh
uv sync --frozen --no-dev --extra capture --extra enrichment
uv run --frozen eye-for-an-eye setup
```

`pyproject.toml` gives the allowed version ranges. `uv.lock` pins one exact set.
`requirements/runtime.txt` lists exact versions with SHA-256 hashes for the
capture and enrichment extras and everything they pull in.

Changing the lock file needs a review and a new run of the checks.

## Installing on a machine with no Internet

On a preparation machine with the same operating system, architecture and Python
version:

```sh
python -m pip download --require-hashes --only-binary=:all: \
    -r requirements/runtime.txt -d wheelhouse
python -m build            # produces dist/*.whl
```

Move `wheelhouse/`, the wheel and the checksums over a channel you trust. On the
server:

```sh
python -m pip install --no-index --find-links wheelhouse \
    --require-hashes -r requirements/runtime.txt
sh scripts/install.sh --wheel ./eye_for_an_eye-0.8.0rc2-py3-none-any.whl
```

Notes:

* A hash proves the file did not change. It does not prove where the file came
  from. There is no signing infrastructure yet.
* Do not mix Linux wheels with Windows wheels.
* GeoIP databases, p0f signatures and probe files are obtained and checked by
  you. Nothing is downloaded automatically, ever.

## After the install

```sh
eye-for-an-eye status
eye-for-an-eye doctor  --config eye-for-an-eye.toml
eye-for-an-eye model status
```

Then read [Quickstart](QUICKSTART.md).

## Running it as a service

Unit files are in `deploy/systemd/`. Read [systemd](SYSTEMD.md) first. The
installer does not enable or start anything for you: that stays your decision.

## See also

* [Deployment matrix](DEPLOYMENT.md)
* [Dependencies](DEPENDENCIES.md)
* [Privileges](PRIVILEGES.md)
* [Docker](DOCKER.md)
* [Upgrade](UPGRADE.md)
