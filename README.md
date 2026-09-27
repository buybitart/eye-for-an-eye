# Eye for an Eye

**Open-source security tool for Linux websites and servers.**

Eye for an Eye watches network and web traffic. It looks at how each source
behaves over time and gives it a risk score, using mathematical behaviour
analysis and, optionally, a local machine-learning model.

It runs in **Safe Monitoring** mode by default: it watches, it records, and it
blocks nothing. It can also apply temporary local blocks, but only when you
configure Autonomous Mode deliberately, and only on Linux.

No cloud AI service is required. Nothing is sent anywhere. No account.

> **Status: PUBLIC BETA — version 0.8.0rc1.** Automatic blocking is **off by
> default** and has never run in production. On our own generated test data it
> blocks 120 sources of 203, with **no false blocks** in 546 benign sources —
> and it detects **nothing at all** in six of the behaviour families it is
> supposed to cover, which fails our own release gate. Real-world validation of
> autonomous blocking is pending. See [Project status](#project-status) and
> [docs/VALIDATION_STATUS.md](docs/VALIDATION_STATUS.md).

**Primary platform: Linux.** Windows can watch a website log and run the demo;
it cannot capture packets or block. See [Which platform](#which-platform).

**I want to use it.** [START_HERE.md](START_HERE.md) is one screen, and the
[Beginner guide](docs/BEGINNER_GUIDE.md) is the same steps with help at each one.
No Python, no Git, no programming.

**I want to develop it.** Go to
[Developer setup](docs/INSTALL_LINUX.md#developer-setup), then
[Architecture](docs/ARCHITECTURE.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Quick start

Linux, from a release archive. No Git, no `pip`, no virtual environment, no root.

```sh
sha256sum -c SHA256SUMS
tar xzf eye-for-an-eye-0.8.0rc1-linux-x86_64.tar.gz
cd eye-for-an-eye-0.8.0rc1
sh install.sh
eye-for-an-eye setup
eye-for-an-eye start
```

Then, in another terminal:

```sh
eye-for-an-eye status
```

Six commands, in order:

1. **`sha256sum -c SHA256SUMS`** — checks the file you downloaded is the file
   that was published. You want `OK`.
2. **`tar xzf …`** — unpacks it. The version in the filename is the one you
   downloaded; `0.8.0rc1` is the current release.
3. **`cd …`** — the archive unpacks into one directory of that name.
4. **`sh install.sh`** — installs for your account only. Prints
   **Installation complete**. Changes no firewall rule and starts nothing.
5. **`eye-for-an-eye setup`** — asks what to watch, and checks your answer.
6. **`eye-for-an-eye start`** — begins Safe Monitoring. Leave the terminal open.

To stop it: `eye-for-an-eye stop`. To remove it: `sh uninstall.sh`.

On **Ubuntu 24.04** you can use the Debian package instead of steps 2 to 4:

```sh
sudo apt install ./eye-for-an-eye_0.8.0~rc1-1_all.deb
```

Everything about installing, including other distributions and what goes where:
**[docs/INSTALL_LINUX.md](docs/INSTALL_LINUX.md)**.

---

## Which platform

Linux is the platform with the complete feature set. This table is what is
actually implemented, not a plan.

| Feature | Linux | Windows |
| --- | --- | --- |
| Web access-log monitoring | Yes | Yes |
| Local demo | Yes | Yes |
| Beginner commands: setup, start, status, stop, uninstall | Yes | Yes |
| Packet capture | Yes, with a separate `CAP_NET_RAW` helper | No |
| nftables enforcement | Yes | No |
| Autonomous host blocking | Yes, when deliberately configured | No |
| systemd service | Yes | No |
| Debian package | Ubuntu 24.04 and derivatives with Python 3.12 | No |

Eye for an Eye needs **Python 3.12** exactly. That makes Ubuntu 24.04 LTS the
tested system; Debian 12 and 13 ship a different Python, so there the release
archive works and the Debian package correctly refuses. The full matrix is in
[docs/INSTALL_LINUX.md](docs/INSTALL_LINUX.md#which-linux).

---

## New to this? Two paths

**I want to use it.** You do not need Python, Git, or any programming.

* **[START_HERE.md](START_HERE.md)** — the shortest path, one screen.
* **[Beginner guide](docs/BEGINNER_GUIDE.md)** — the same steps, with help at
  each one.
* **[Install on Linux](docs/INSTALL_LINUX.md)** — every installation option.
* Windows: double-click `Install-EyeForAnEye.cmd`.

Either installer sets up **Safe Monitoring**: it watches, it writes notes, and it
blocks nobody. Installing this software does not enable blocking.

**I want to develop it.** Start at
[docs/INSTALL_LINUX.md#developer-setup](docs/INSTALL_LINUX.md#developer-setup),
then [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
[CONTRIBUTING.md](CONTRIBUTING.md). That path expects Python 3.12, a virtual
environment and a checkout.

---

## Documentation

**Getting started**

* [Start here](START_HERE.md) · [Beginner guide](docs/BEGINNER_GUIDE.md) ·
  [Install on Linux](docs/INSTALL_LINUX.md) ·
  [Troubleshooting](docs/TROUBLESHOOTING.md)

**Running it**

* [Configuration](docs/CONFIGURATION.md) · [Operations](docs/OPERATIONS.md) ·
  [Web protection](docs/WEB_PROTECTION.md) · [Privileges](docs/PRIVILEGES.md) ·
  [systemd](docs/SYSTEMD.md) · [Storage](docs/STORAGE.md)

**Advanced protection**

* [Autonomous mode](docs/AUTONOMOUS_MODE.md) ·
  [Trusted proxies](docs/TRUSTED_PROXIES.md) ·
  [Validation status](docs/VALIDATION_STATUS.md)

**Models, data and privacy**

* [Privacy](docs/PRIVACY.md) · [Models and data](docs/DATA_AND_MODELS.md) ·
  [Dataset](docs/DATASET.md) · [Model governance](docs/MODEL_GOVERNANCE.md)

**Contributing and security**

* [Contributing](CONTRIBUTING.md) · [Architecture](docs/ARCHITECTURE.md) ·
  [Security policy](SECURITY.md) · [Release notes](docs/RELEASE_NOTES.md)

The full index is [docs/README.md](docs/README.md).

---

## Security reports

**Do not open a public issue for a security vulnerability.** Use GitHub Private
Vulnerability Reporting: the repository's **Security** tab, then **Report a
vulnerability**.

Everything else, including what to put in a report and what not to send, is in
[SECURITY.md](SECURITY.md).

---

## What it looks for

A **bot** is a program that visits your server automatically, with no person
behind it. A **scanner** is a bot that tries many ports or addresses to find
something open or old.

Eye for an Eye can detect suspicious automated behaviour such as:

* port scanning — one source touches many ports in a short time;
* service probing — repeated requests looking for known software;
* repeated connection attempts, retries and login-like attempts;
* unusual protocol behaviour, such as odd packet flags or sizes;
* a source that keeps coming back over a long time;
* contact with a decoy port that no real service uses.

It cannot tell you who a person is. An IP address is not a person.

**Example.** A reader opens one page. One connection, one port, a short visit.
The risk stays low.

A scanner opens 40 ports in one minute. The gap between connections is always
the same. It keeps going after a fake service answers. The risk rises.

---

## How it works

```text
Network traffic  (live capture helper, or a saved .pcap file)
      |
      v
Event normalisation -> bounded queue
      |
      v
Correlation per source, in windows of 10 s, 60 s and 900 s
      |
      v
Feature extraction  (18 behaviour numbers + 18 "is this known?" flags)
      |
      +---------------------------+
      v                           v
Maths risk engine          Local ONNX model  (optional)
      |                           |
      +------------+--------------+
                   v
            Decision fusion
                   v
             Policy guard    <- can always refuse a strong action
                   v
  OBSERVE / WATCH / RATE_LIMIT / TEMP_BLOCK
```

Every queue, cache and store has a fixed limit, so a flood cannot make the
defender run out of memory.

---

## Mathematical risk

The system turns behaviour into numbers. How many ports. How many destinations.
How regular the timing is. How many login-like attempts. How long a source keeps
coming back.

Ten of these numbers have a fixed weight:

```text
score = sigmoid(-4.0 + sum(weight * normalised value))
```

The largest weights are port sweeping (3.0) and login-like attempts (3.0). The
bias is -4.0, so with no evidence the score is near zero.

The score is between 0 and 1. **It is not a probability** — the code marks it as
uncalibrated. It only says "more" or "less". Old risk fades: it halves every 60
seconds by default.

Full weight table: [docs/MATH_MODEL.md](docs/MATH_MODEL.md).

---

## Local AI

ONNX is a file format for machine learning models. Eye for an Eye can run such a
model on your own server with ONNX Runtime.

| Fact | Value |
| --- | --- |
| Name | `risk-logreg-v1` |
| Type | Logistic regression |
| File size | 730 bytes |
| Inputs | 36 numbers (18 behaviour values + 18 "is this value known?" flags) |
| Runs | locally, on the CPU, in a separate process |
| Recommendation | **Shadow Mode only** |

* No cloud AI service is used or required.
* The model gets numbers, not text. It never sees a payload, password, cookie or
  raw packet, and never sees the IP address, country, ASN or hosting provider.
* It is optional. With no model file the maths engine works alone, and if the
  model is missing, slow or unsure its weight returns to that engine.
* **The model cannot cause a block on its own.** A strong action also needs the
  maths engine to agree, separately, at its own threshold.
* Before loading, the file's SHA-256 and the whole input contract must match the
  manifest. If not, the model is skipped and the service keeps running.

More: [docs/AI.md](docs/AI.md), [model card](models/MODEL_CARD_risk-logreg-v1.md).

---

## Adaptive learning

The running service does **not** learn. It contains no training code, no
automatic retraining and no automatic model replacement.

Learning is a separate offline process with a person in the middle:

```text
Shadow Mode -> export (unlabelled) -> human review -> dataset
    -> offline training -> quality gates -> you install the model
```

A new model can be trained from reviewed local data. It must pass quality checks
and run in Shadow Mode before anyone uses it for blocking. Shadow data always
leaves **without a label**, so the system never decides its own blocks were
correct.

More: [docs/SELF_LEARNING.md](docs/SELF_LEARNING.md), [docs/DATASET.md](docs/DATASET.md).

---

## Shadow Mode

Shadow Mode is the default. The system decides, records the decision and its
reasons, and does nothing to the traffic.

```text
Risk: 0.91
Decision: TEMP_BLOCK
Enforced: No
Reason: shadow mode
```

This lets you find false positives before anything is blocked. Your monitoring
service, backup job and office network all look a little like automation. Run it
for days and read the results first. More: [docs/SHADOW_MODE.md](docs/SHADOW_MODE.md).

---

## Two production postures

There are two ways to run this in production. Both use the same software and
the same decision path. The only difference is whether a decision is carried
out.

| | `production-shadow` | `production-autonomous` |
|---|---|---|
| Analysis | full | full |
| Decides | yes | yes |
| Blocks | **no** | yes, temporarily |
| Changes your firewall | no | yes |
| Validates as shipped | yes | **no, by design** |
| Where to start | **here** | after Shadow, deliberately |

```sh
eye-for-an-eye config init --profile production-shadow --output shadow.toml
```

Shadow is the recommended first deployment and the one in the Quick start
above. It produces real decisions, a decision journal and a privacy-safe
evidence export, and it denies nobody.

The autonomous profile does not validate as shipped, and that is deliberate. It
turns host blocking on and leaves the list of protected management networks
empty, so the configuration refuses to start until you say which addresses must
never be blocked:

```text
enforcement.host_enabled requires at least one protected network: set
enforcement.management_networks to the addresses you administer this machine
from, or this software can lock you out of it
```

Installing this software does not enable blocking. Selecting that profile and
filling in its prerequisites is a decision you make, on purpose.

**Real-world validation of autonomous blocking is pending.** The decision path
has been tested against a real Linux kernel — a real connection blocked by a
real decision and restored when the block expired — and it has no evidence yet
from a long run on real traffic. Treat autonomous blocking as experimental and
as something to validate on your own site, with Shadow, first.
[docs/VALIDATION_STATUS.md](docs/VALIDATION_STATUS.md) states exactly what has
and has not been tested.

---

## Working automatically

Eye for an Eye can work automatically after setup.

It watches network and web behaviour. It uses mathematical rules and local
machine learning. It can allow traffic or temporarily block a source. A block
expires automatically. The system also checks data quality and model health
before strong actions.

"Automatic" means one thing only: **no person has to approve each decision**. It
does **not** mean the decisions are always right. No security tool can promise
that, and this one does not.

You turn it on yourself. It is off until you do.

```text
eye-for-an-eye doctor
eye-for-an-eye autonomy readiness
eye-for-an-eye autonomy enable
```

`autonomy readiness` checks the machine first: your configuration, the features,
the maths engine, the cost settings, your protected networks, the safety limits,
the clock. If one important check fails it says `AUTONOMOUS_READY: NO` and names
the check. It does not hide it.

Before blocking anything, the system asks:

* What did this source actually do?
* How many different kinds of evidence say the same thing?
* Is my data complete enough to judge?
* Do I know which machine I would be blocking?
* Has my model seen traffic like this before?
* Is my model healthy?
* How sure am I, really?
* What does a wrong block cost on this site?
* What does allowing this cost?
* Is the difference still large when I am careful?
* Does the policy guard allow it?

Only then: allow, or block for a while.

Some things it never does automatically. It never blocks for ever. It never
blocks your management network. It never blocks a shared address such as a CDN
or an office router, because that would cut off everyone behind it. It never
blocks because a model score was high and nothing else. It never uses its own
decisions as training data. And it never attacks back — there is no code in this
project that could.

If too much is blocked at once, or a part of the system breaks, it stops
blocking by itself and keeps watching. It starts again on its own when things are
healthy again. You can also switch it off at any moment with one local command.

Two honest limits. Automatic **blocking** on a real server is new, off by
default, and tested on a disposable machine rather than in production — see
[docs/HOST_ENFORCEMENT.md](docs/HOST_ENFORCEMENT.md). And detection is uneven:
on our own generated test data the system blocked 120 sources of 203 with no
false blocks in 546 benign sources, and detected **nothing at all** in six of
the behaviour families it claims to cover. Six zero-detection families fails our
own generalization gate, and that is the main thing standing between this and a
production release. The measurement is in
[reports/P15_5_FINAL_RELEASE_VALIDATION.md](reports/P15_5_FINAL_RELEASE_VALIDATION.md);
the earlier one it replaced is
[reports/P15_1_DECISION_EVALUATION.md](reports/P15_1_DECISION_EVALUATION.md).

Both numbers come from traffic this project generated itself. Neither is
evidence about real traffic, and
[docs/SHADOW_VALIDATION_PLAN.md](docs/SHADOW_VALIDATION_PLAN.md) says what would
be.

More: [docs/AUTONOMOUS_MODE.md](docs/AUTONOMOUS_MODE.md).

---

## Blocking

Blocking is **off by default**. There are two paths, and each is off separately.

* **Lab namespace** — **experimental and lab-only**. It runs only inside a
  named, throw-away Linux network namespace, and three gates stop it reaching
  your real host firewall. More: [docs/ENFORCEMENT.md](docs/ENFORCEMENT.md).
* **Real host** — new, `enforcement.host_enabled`, off on a fresh installation,
  and a package upgrade cannot turn it on. It adds a temporary source block to
  **one nftables table this project owns**, never to yours, through a separate
  privileged helper that accepts an address and a lifetime and never a command.
  Tested against a real kernel on a machine we could afford to lose, **not in
  production**. More: [docs/HOST_ENFORCEMENT.md](docs/HOST_ENFORCEMENT.md).

Both paths share the same limits:

* Blocks are always temporary: 5 min, 30 min, 2 h, then 12 h. The counter resets
  after 6 quiet hours. `RATE_LIMIT` is recorded but not applied.
* Loopback, local addresses, your management networks, allowlist and trusted
  proxies are never blocked.
* A strong action also needs enough samples, enough time, enough independent
  behaviour categories, and agreement from the maths engine.

Firewall commands are separate and manual, and `firewall dry-run` shows the
change first.

---

## Asking before blocking

A suspicious client is not always an attacker. Instead of blocking one it is
unsure about, Eye for an Eye can send a small local web challenge.

The challenge is a short-lived signed cookie and a redirect. An ordinary browser
answers it by itself. There is no CAPTCHA, no puzzle, no JavaScript, no
fingerprinting and no third-party service — nothing leaves your server.

The result is evidence, not proof. A failed challenge does not prove an attack:
plenty of real people block cookies. A passed challenge does not make a client
trusted: a capable script can pass one, and behaviour afterwards still counts.

This adds one rung to the ladder:

```
OBSERVE → WATCH → SOFT_CHALLENGE → RATE_LIMIT → TEMP_BLOCK
```

Challenges are **off by default**, and shadow mode — decide everything, send
nothing — is the recommended way to start.
More: [docs/CHALLENGE.md](docs/CHALLENGE.md) and
[docs/PROGRESSIVE_DEFENSE.md](docs/PROGRESSIVE_DEFENSE.md).

---

## More than one website

One Eye for an Eye server can protect several local websites. Each site can have
its own behaviour baseline and policy.

This matters because different sites have different normal behaviour. An API
doing 1200 requests a minute is working; an admin panel doing that is not. One
threshold cannot describe both.

Web behaviour is kept separate per site — counters, baselines, thresholds,
challenge keys. Network behaviour is about the whole server and is shared on
purpose: a port scan is a fact about the machine.

Sites come from your configuration, never from a request. A `Host` header can
select a site; it can never create one.

Multi-site is **off by default**, and a single-site owner never needs it. Every
new site starts in Shadow Mode.
More: [docs/MULTI_SITE.md](docs/MULTI_SITE.md).

---

## Testing a new model before it becomes active (optional)

Eye for an Eye can test a new local model before it becomes active.

A new model first runs in Shadow Mode, where it sees real traffic and changes
nothing. If it passes the safety checks, the system can activate it in a limited
mode: it starts contributing to decisions, but on its own it may only raise
attention — it cannot challenge, slow down or block anybody. It gains more
authority only after enough real observations, not after enough time. The old
model is kept. If the new model has a serious technical problem, Eye for an Eye
can return to the old model.

**This is off when you install and stays off when you upgrade.** Turning it on is
a deliberate change to your configuration, and the sensible first step is one
small site rather than everything:

```toml
[model_governance]
auto_promote_enabled = true
auto_promote_sites = ["main"]
```

Two things worth knowing. One site opting in never enables another. And the
shared model used by every site is a separate switch, also off, because
promoting it reaches sites whose owner never asked for this.

```
eye-for-an-eye model governance status
eye-for-an-eye model governance freeze --reason "investigating"
```

Promotion changes which model gives an opinion. It never adds a firewall rule,
never changes a threshold, and never deletes a dataset, a review or the old
model.

Nobody has run this over production traffic yet, including the people who wrote
it. More: [docs/AUTO_PROMOTION.md](docs/AUTO_PROMOTION.md).

---

## Defensive deception

Eye for an Eye can open decoy TCP ports. A decoy answers like a simple service
and records what the visitor does. This is **defensive deception**, also called a
honeypot. There are three fixed profiles: an SSH banner, an FTP control channel
and a small static HTTP server.

Hard limits in the code: no shell, no command execution, fixed answers, and
**no hack-back**. The project never attacks anyone.
More: [docs/DECEPTION.md](docs/DECEPTION.md).

---

## Privacy

* Traffic analysis, model inference, decisions and datasets stay on your machine.
  No telemetry, no update check, no cloud AI.
* Payloads, passwords, cookies, tokens and `Authorization` headers are removed
  before anything is stored, logged or served by the API. Only counts stay, such
  as "payload length: 340".
* You choose how long events are kept. The default is 7 days.
* One optional feature uses the network: RDAP lookup. It is **off** by default,
  and turning it on sends an IP address to a public registry.

More: [docs/PRIVACY.md](docs/PRIVACY.md).

---

## Install

The full instructions are on one page: **[docs/INSTALL_LINUX.md](docs/INSTALL_LINUX.md)**.
The short version is the [Quick start](#quick-start) at the top.

Installing from a source tree, which is what a developer does:

```sh
sh install.sh                      # hands over to scripts/install.sh
sh install.sh --dry-run            # show every step, change nothing
sh install.sh --wheel FILE         # install from a .whl, no network needed
sudo sh install.sh --system        # for all users, into /opt
sh uninstall.sh                    # remove the program, keep your data
sh uninstall.sh --purge            # remove the data too
```

None of these changes your firewall, enables blocking, or starts a service.

## Administrator quick start

The [Quick start](#quick-start) at the top is the short path. This one is for an
administrator who wants to see each component answer for itself.

It is still the safe path. It watches and records. It blocks nothing and it does
not change your firewall.

```sh
sh scripts/install.sh
cd ~/.local/share/eye-for-an-eye/data
eye-for-an-eye config init --profile production-shadow --output shadow.toml
eye-for-an-eye config validate --config shadow.toml
eye-for-an-eye doctor --config shadow.toml
eye-for-an-eye autonomy preflight --config shadow.toml
eye-for-an-eye demo
```

Every command above works on a fresh install with nothing else configured.
`demo` is a small finite local example on loopback; it needs no root and sends
nothing outward.

**To watch real traffic you have to choose a source, and neither is automatic.**

* **A web server's access log.** Set `web.access_log_path` in `shadow.toml` to
  the log your server writes, then use `eye-for-an-eye web doctor` and
  `eye-for-an-eye web status` to read it. See
  [docs/WEB_PROTECTION.md](docs/WEB_PROTECTION.md).
* **Packet capture.** `eye-for-an-eye run` needs `capture.ipc_socket` and a
  separate capture helper holding `CAP_NET_RAW`; it refuses to start without
  one and tells you so. See [docs/PRIVILEGES.md](docs/PRIVILEGES.md) and
  [docs/INSTALL.md](docs/INSTALL.md).

While a sensor runs, `eye-for-an-eye autonomy status --config shadow.toml` says
what it is doing, and `eye-for-an-eye autonomy evidence <export>` summarises
what it has seen.

`doctor` only looks; it never repairs or touches the firewall. On a fresh
install it reports DEGRADED and names what is not configured yet — the access
log to read, and the calibrator file. That is a list of next steps, not a fault.

`autonomy preflight` builds the real decision path and reports the state of
each part of it, instead of repeating what the configuration file said.

Work with a `umask` of `022`. The model loader refuses an artifact that other
accounts could modify, so a group-writable calibrator is reported as
unavailable. That is correct, and puzzling if you do not know the reason.


Reading a saved capture file needs the optional `capture` extra:

```sh
pip install 'scapy>=2.7,<2.8'
eye-for-an-eye analyze-pcap capture.pcap --config eye-for-an-eye.toml
```

More: [docs/QUICKSTART.md](docs/QUICKSTART.md).

---

## Safe defaults

Real values written by `eye-for-an-eye setup`:

| Option | Default |
| --- | --- |
| Shadow Mode | On |
| Automatic blocking | **Off** |
| Cloud AI | Not used |
| Active probes | Off |
| Outgoing network (egress) | Disabled |
| External RDAP lookup | Off |
| UDP replies | Off |
| Management API | Local only (`127.0.0.1`) |
| Metrics | Local only (`127.0.0.1`) |
| Local model required | No |
| Event retention | 7 days |

`scripts/check_safe_defaults.py` checks these and fails if any is unsafe.

---

## Project status

| Component | Status |
| --- | --- |
| Traffic capture and analysis | Stable |
| Event storage and local API | Stable |
| Correlation over time windows | Stable |
| Mathematical risk engine | Stable |
| ONNX model inference | Beta |
| Shadow Mode | Beta |
| Defensive deception | Beta |
| Dataset and training pipeline | Beta |
| Data quality gating | Stable |
| Drift detection | Beta |
| Out-of-distribution detection | Beta |
| Anomaly detection | Beta |
| Automatic blocking, lab namespace | **Experimental, lab-only** |
| Automatic blocking, real host | Implemented, **off by default**, tested on a disposable machine |
| Adaptive learning | **Experimental** (offline, human in the loop) |
| Model governance and auto-promotion | Implemented, **off by default** |
| Autonomous decision authority | Implemented, **off by default**; reaches the real-host path only when `enforcement.host_enabled` is also on |

Known limits: the shipped model has never seen production traffic; scores are
not probabilities; there is no defence against a large volume-based denial of
service. Linux live capture, the namespace firewall, `CAP_NET_RAW` and systemd
hardening are **not verified in the current test environment**.
More: [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

---

## Requirements

* Linux x86_64 for live capture. Windows and macOS for development only.
* Python 3.12 (`>=3.12,<3.13`). About 100 MB of disk.
* A normal user account. **Root is not needed** to install or run the sensor.
  Live capture needs a small helper with the `CAP_NET_RAW` capability, and
  firewall commands need root and are always manual.
* The base program has no Python dependencies. Optional extras: `capture`
  (scapy), `ml` (ONNX Runtime), `enrichment`. Docker files are included.

---

## Every page

The short navigation is [near the top](#documentation); the ordered index is
[docs/README.md](docs/README.md). This is the flat list.

**Start here:** [Quickstart](docs/QUICKSTART.md) · [Install on Linux](docs/INSTALL_LINUX.md) · [Install reference](docs/INSTALL.md) · [Configuration](docs/CONFIGURATION.md) · [Troubleshooting](docs/TROUBLESHOOTING.md)

**How it works:** [Architecture](docs/ARCHITECTURE.md) · [Maths](docs/MATH_MODEL.md) · [AI](docs/AI.md) · [Features](docs/FEATURE_SCHEMA.md) · [Decisions](docs/DECISION_ENGINE.md)

**Knowing when not to act:** [Data quality](docs/DATA_QUALITY.md) · [Out-of-distribution](docs/OOD.md) · [Drift](docs/DRIFT.md) · [Anomaly detection](docs/ANOMALY_DETECTION.md)

**Running it:** [Shadow Mode](docs/SHADOW_MODE.md) · [Enforcement](docs/ENFORCEMENT.md) · [Deception](docs/DECEPTION.md) · [Privacy](docs/PRIVACY.md) · [Backpressure](docs/BACKPRESSURE.md) · [Shadow validation plan](docs/SHADOW_VALIDATION_PLAN.md)

**Websites:** [Website quickstart](docs/WEBSITE_QUICKSTART.md) · [Web protection](docs/WEB_PROTECTION.md) · [Challenge](docs/CHALLENGE.md) · [Progressive defense](docs/PROGRESSIVE_DEFENSE.md) · [API clients](docs/API_CLIENTS.md) · [Trusted proxies](docs/TRUSTED_PROXIES.md)

**Several websites:** [Multi-site](docs/MULTI_SITE.md) · [Site profiles](docs/SITE_PROFILES.md) · [Site baselines](docs/SITE_BASELINES.md) · [Multi-site models](docs/MULTI_SITE_MODELS.md) · [Cross-site security](docs/CROSS_SITE_SECURITY.md) · [Multi-site Nginx](docs/MULTI_SITE_NGINX.md) · [Site datasets](docs/SITE_DATASETS.md)

**Data and models:** [Dataset](docs/DATASET.md) · [Learning](docs/SELF_LEARNING.md) · [Training](docs/MODEL_TRAINING.md) · [Evaluation](docs/MODEL_EVALUATION.md)

**Model lifecycle:** [Auto-promotion](docs/AUTO_PROMOTION.md) · [Model governance](docs/MODEL_GOVERNANCE.md) · [Guarded activation](docs/GUARDED_ACTIVATION.md) · [Automatic rollback](docs/AUTO_ROLLBACK.md) · [Safe mode](docs/MODEL_SAFE_MODE.md) · [Promotion policy](docs/PROMOTION_POLICY.md)

**Working automatically:** [Autonomous mode](docs/AUTONOMOUS_MODE.md) · [Host enforcement](docs/HOST_ENFORCEMENT.md) · [The decision](docs/AUTONOMOUS_DECISION.md) · [Cost policy](docs/COST_SENSITIVE_POLICY.md) · [Decision uncertainty](docs/DECISION_UNCERTAINTY.md) · [Failure and recovery](docs/AUTONOMOUS_FAILURE_RECOVERY.md) · [Safety invariants](docs/AUTONOMOUS_SAFETY_INVARIANTS.md) · [Data curation](docs/AUTONOMOUS_DATA_CURATION.md) · [Module graduation](docs/MODULE_GRADUATION.md) · [Scientific basis](docs/SCIENTIFIC_BASIS.md)

**Before you rely on any of it:** [What actually works](docs/P0_P12_STATUS.md) — every feature, marked IMPLEMENTED, PARTIAL, EXPERIMENTAL, LAB_ONLY or MISSING, with the evidence.

**Project:** [Threat model](docs/THREAT_MODEL.md) · [Security](SECURITY.md) · [Security review scope](docs/SECURITY_REVIEW_SCOPE.md) · [Schema compatibility](docs/SCHEMA_COMPATIBILITY.md) · [Roadmap](ROADMAP.md) · [Changelog](CHANGELOG.md)

---

## Safety

This is **defensive** software. Do not use it for attacking other systems,
denial of service, malware, hack-back, or destructive testing.

Lab traffic must stay on loopback, an isolated Docker network, or a Linux
network namespace. The dataset tools enforce this in code: any target that is
not loopback or a listed lab address is rejected. Only test systems you own or
have written permission to test.

---

## Open source

All source code, tests, documentation, the data card and the model card are in
this repository. You can read the decision logic, inspect every weight, keep
your data local, and train your own model.

**Licence: MIT.** Copyright (c) 2026 Aliaksandr Zasinets. The full text is in
[LICENSE](LICENSE), and the SPDX identifier is `MIT`.

The base package has no dependencies, so a plain install carries nobody else's
code. Optional extras do, and one of them — scapy, used only for live capture —
is GPL-2.0-only. That does not relicense this project, and it does change your
obligations if you bundle it into a container image or a frozen binary. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

**Security reporting** goes through GitHub Private Vulnerability Reporting once
the repository is published; see [SECURITY.md](SECURITY.md) for the workflow and
for what to do before then.

## Contributing

Bug reports, tests, lab scenarios, dataset review, models and documentation are
welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Do not report a security
problem in a public issue — read [SECURITY.md](SECURITY.md) first.
