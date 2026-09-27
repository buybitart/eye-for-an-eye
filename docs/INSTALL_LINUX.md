# Install on Linux

Linux is the platform Eye for an Eye is built for. Everything it can do, it can
do here.

This page is the one place Linux installation is written down. Other pages link
here rather than repeat it.

**After any of these paths, nothing is blocked.** Blocking is a separate feature
you switch on yourself, later, on purpose. Installing cannot switch it on.

---

## Contents

* [Which Linux](#which-linux)
* [Quick install](#quick-install) — the release archive
* [Debian package](#debian-package)
* [From a checkout](#from-a-checkout)
* [What gets installed, and where](#what-gets-installed-and-where)
* [Privileges](#privileges)
* [Running as a service](#running-as-a-service)
* [Upgrading](#upgrading)
* [Removing it](#removing-it)
* [Developer setup](#developer-setup)

---

## Which Linux

Eye for an Eye needs **Python 3.12**. Not 3.11, not 3.13. That single fact
decides most of this table.

| System | Status | Why |
| --- | --- | --- |
| Ubuntu 24.04 LTS, x86_64 | **Supported and tested** | System Python is 3.12 |
| Ubuntu 24.04 LTS, other architectures | Expected to work, not tested | Nothing in the package is architecture-specific |
| Debian 12 (bookworm) | Archive only | System Python is 3.11. The `.deb` will refuse to install. `install.sh` works if it can get a 3.12 interpreter |
| Debian 13 (trixie) | Archive only | System Python is 3.13. Same as above |
| Fedora, RHEL, Arch, Alpine, openSUSE | Not tested | May well work where Python 3.12 is available. Nobody has run it |

"Archive only" means: use [Quick install](#quick-install), not the Debian
package. The installer can ask [uv](https://docs.astral.sh/uv/) for a Python 3.12
of its own when the system does not have one, which is how it works on a
distribution whose Python is a different version.

Architectures: the Python package contains no compiled code, so the release
archive and the Debian package are architecture-independent. The optional local
model needs `onnxruntime`, which is not available for every architecture.

---

## Quick install

This is the recommended path. It does not need `git`, `pip`, a virtual
environment, or any knowledge of Python.

### 1. Download

Download two files from the release page:

* `eye-for-an-eye-<version>-linux-x86_64.tar.gz`
* `SHA256SUMS`

### 2. Check what you downloaded

```sh
sha256sum -c SHA256SUMS
```

You should see `OK` next to the archive name. If you see `FAILED`, delete the
file and download it again. Do not install it.

### 3. Unpack

```sh
tar xzf eye-for-an-eye-*-linux-x86_64.tar.gz
cd eye-for-an-eye-*/
```

The first things you see are `START_HERE.md` and `install.sh`.

### 4. Install

```sh
sh install.sh
```

No `sudo`. This installs for your account only. It prints
**Installation complete** when it is done, and tells you where everything went.

If `~/.local/bin` is not on your `PATH`, the installer says so. Add it, or use
the full path it prints.

### 5. Choose what to watch

```sh
eye-for-an-eye setup
```

It asks what you want it to watch and checks your answer. See
[Choosing a traffic source](#choosing-a-traffic-source) below.

### 6. Start

```sh
eye-for-an-eye start
```

Leave that terminal open. Closing it stops the watching.

### 7. Check

```sh
eye-for-an-eye status
```

For all of it in one place with more help at each step, read
[BEGINNER_GUIDE.md](BEGINNER_GUIDE.md).

---

## Debian package

For **Ubuntu 24.04 LTS** and derivatives whose system Python is 3.12.

```sh
sudo apt install ./eye-for-an-eye_<version>_all.deb
```

Use the real filename from the release page. The version in the filename uses a
tilde — for example `eye-for-an-eye_0.8.0~rc2-1_all.deb` — which is how Debian
writes "before the final release".

On Debian 12 or 13 this command will refuse, because the package depends on
`python3.12` and those systems do not have it as their Python. That refusal is
correct: use the release archive instead.

The package installs the systemd units and leaves them **disabled**. It creates
no configuration file, changes no firewall rule, and starts nothing.

After installing:

```sh
eye-for-an-eye setup
eye-for-an-eye start
eye-for-an-eye status
```

There is a `README.Debian` in `/usr/share/doc/eye-for-an-eye/` with the exact
list of installed paths.

---

## From a checkout

Only if you already have the source tree, and you are not developing on it:

```sh
sh install.sh
```

`install.sh` at the top of the tree hands over to `scripts/install.sh`, which is
the only installer in the project. Useful options:

```sh
sh install.sh --help          every option
sh install.sh --dry-run       show every step, change nothing
sh install.sh --wheel FILE    install from a .whl, for a machine with no network
sudo sh install.sh --system   install for all users
```

`--system` installs into `/opt/eye-for-an-eye` and puts data in
`/var/lib/eye-for-an-eye`. It still starts no service.

### Why `/opt` for `--system`

`/opt` is the right place for exactly this shape of install: a self-contained
directory holding its own Python virtual environment, managed by this project's
own installer rather than by a package manager. The Debian package, which is
managed by `dpkg`, uses `/usr` instead, as it should.

---

## Choosing a traffic source

There are two, and they are not equally easy.

### A website log — works everywhere

Eye for an Eye reads the file your web server writes about visitors. It only
reads it. It never changes your web server.

**It needs a specific format.** One JSON object per line. A default Nginx
`access.log` is *not* in that format, and pointing Eye for an Eye at one gives
you a sensor that runs happily and sees nothing at all.

To get the right format:

```sh
eye-for-an-eye web log-format
```

That prints the Nginx `log_format` block to install, and the `access_log` line
that uses it. It changes nothing itself. Install it, run `nginx -t`, reload
Nginx, then point Eye for an Eye at the new file:

```sh
eye-for-an-eye setup --watch website-log --access-log /var/log/nginx/eye-for-an-eye.log
```

`setup` checks the file exists, that it can be read, and that the first line is
in the format the reader understands. If the format is wrong it says so and tells
you this command again.

See [WEB_PROTECTION.md](WEB_PROTECTION.md) for the detail, including trusted
proxies and CDNs.

### Packet capture — Linux only, and not a beginner path

This watches network packets directly. It needs a separate helper program holding
`CAP_NET_RAW`, which the installer does not set up for you.

```sh
eye-for-an-eye setup --watch network --interface eth0
```

That records your answer and tells you what is still missing. Read
[PRIVILEGES.md](PRIVILEGES.md) and [INSTALL.md](INSTALL.md) before going further.

---

## What gets installed, and where

### The release archive or a checkout, `--local` (the default)

| What | Where |
| --- | --- |
| The program | `~/.local/share/eye-for-an-eye/venv` |
| The command | `~/.local/bin/eye-for-an-eye` |
| Your settings | `~/.local/share/eye-for-an-eye/data/eye-for-an-eye.toml` |
| Database, journal, exports | `~/.local/share/eye-for-an-eye/data/` |
| Install report | `~/.local/share/eye-for-an-eye/install-report.txt` |
| Install receipt | `~/.local/share/eye-for-an-eye/install-receipt.json` |

The receipt records where everything went. It is how `eye-for-an-eye status`,
`check-install` and `easy uninstall` know what this machine has, instead of
guessing.

### The release archive or a checkout, `--system`

| What | Where |
| --- | --- |
| The program | `/opt/eye-for-an-eye/venv` |
| The command | `/usr/local/bin/eye-for-an-eye` |
| Settings and data | `/var/lib/eye-for-an-eye/` |

### The Debian package

| What | Where |
| --- | --- |
| The command | `/usr/bin/eye-for-an-eye` |
| The program | `/usr/lib/python3/dist-packages/eye_for_an_eye/` |
| systemd units, disabled | `/usr/lib/systemd/system/` |
| Service accounts | `/usr/lib/sysusers.d/eye-for-an-eye.conf` |
| Documentation | `/usr/share/doc/eye-for-an-eye/` |
| Example configs | `/usr/share/eye-for-an-eye/deploy/` |
| Man page | `/usr/share/man/man1/eye-for-an-eye.1.gz` |

The package ships **nothing** under `/etc`. Your configuration is one you write
with `eye-for-an-eye setup`, so no upgrade can ever ask you to merge a policy
file you did not write.

Runtime state for a service lives in `/var/lib/eye-for-an-eye`, which systemd
creates itself through `StateDirectory=`.

---

## Privileges

Least privilege is the design, not an option.

| Component | Needs |
| --- | --- |
| Analysis service, all beginner commands, `setup`, `status`, `doctor`, `demo` | Nothing. A normal user account |
| Live packet capture helper | `CAP_NET_RAW`, and nothing else |
| Host blocking (`nft` commands) | root, separately, and only when you configure blocking |
| Training a model | Refuses to run as root, on purpose |

Nothing runs the whole program as root, and nothing should. If something asks you
for `sudo` that this page did not tell you about, stop and find out what is asking.

`sh install.sh` never needs root. `sudo sh install.sh --system` needs it only to
write into `/opt` and `/usr/local/bin`.

Full detail: [PRIVILEGES.md](PRIVILEGES.md).

---

## Running as a service

systemd is the production deployment method. The units are real and they are
hardened; read [SYSTEMD.md](SYSTEMD.md) before enabling one.

The three units:

| Unit | What it is |
| --- | --- |
| `eye-for-an-eye.service` | The analysis service |
| `eye-for-an-eye-capture.service` | The capture helper, the only part with `CAP_NET_RAW` |
| `eye-for-an-eye-listener.service` | The finite deception listener. Optional |

No installation path enables any of them. Enabling a service is a deliberate act
and it needs a configuration and a traffic source first.

---

## Upgrading

### Release archive or checkout

Run the installer again over the same location. It reuses the virtual
environment, upgrades the program, and **does not touch your configuration** — it
says `Configuration already exists. It was not changed.`

### Debian package

```sh
sudo apt install ./eye-for-an-eye_<newer version>_all.deb
```

Your configuration is not a packaged file, so an upgrade cannot overwrite it.
Your database and decision journal are not touched.

If a future version needs a different configuration schema, the upgrade will not
rewrite your file. `eye-for-an-eye config validate` tells you whether the file
you have is still valid, and `eye-for-an-eye upgrade` writes a migrated copy to a
**new** path, leaving the original alone.

**Downgrading is not tested.** Do not assume a newer database or journal can be
read by an older version.

---

## Removing it

### Release archive or checkout

```sh
sh uninstall.sh
```

That removes the program and the command, and **keeps** your settings, your
database and your records.

To delete those as well:

```sh
sh uninstall.sh --purge
```

`--purge` deletes your data and cannot be undone. The two are deliberately
separate commands and never the same one.

If you no longer have the archive, `eye-for-an-eye easy uninstall` does the same
thing using the install receipt, and lists exactly what it will remove before
removing anything.

### Debian package

```sh
sudo apt remove eye-for-an-eye     # removes the program
sudo apt purge  eye-for-an-eye     # the same; does NOT delete your data
```

Neither deletes your configuration, database or decision journal — the package
does not own those paths. To delete them, do it deliberately:

```sh
sudo rm -rf /etc/eye-for-an-eye /var/lib/eye-for-an-eye
```

Removing Eye for an Eye does not change your firewall. It never changed it unless
you switched blocking on yourself.

---

## Developer setup

This belongs last on purpose. Nobody needs it to use the product.

```sh
git clone <repository>
cd eye-for-an-eye
python3.12 -m venv .venv
./.venv/bin/pip install -e '.[test,lint,ml]'
./.venv/bin/python -m pytest
```

Then [CONTRIBUTING.md](../CONTRIBUTING.md) and [ARCHITECTURE.md](ARCHITECTURE.md).

---

## If something went wrong

[TROUBLESHOOTING.md](TROUBLESHOOTING.md) lists the common Linux problems with the
simple fix first.

Otherwise:

```sh
eye-for-an-eye check-install     # is the installation complete
eye-for-an-eye doctor            # the full technical report
```

If you ask someone for help, send `install-report.txt`. It contains no passwords,
no keys and no visitor traffic.
