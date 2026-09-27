# Quickstart

This page takes about 10 minutes. At the end you will have a working install in
Shadow Mode, and you will know how to read it.

You need Linux, Python 3.12, and a normal user account. You do **not** need root.

## 1. Install

From the project folder:

```sh
sh scripts/install.sh
```

You should see:

```
Eye for an Eye is installed.

Mode: SHADOW
AI: Maths only (no model file yet)
Automatic block: OFF
API: Local only
Storage: OK
```

If `~/.local/bin` is not in your `PATH`, the installer says so. Add it, or use
the full path it prints.

## 2. Check the Health

```sh
cd ~/.local/share/eye-for-an-eye/data
eye-for-an-eye doctor --config eye-for-an-eye.toml
```

`doctor` only looks. It never repairs, downloads or changes the firewall.

Normal answers on a fresh install:

| Check | Normal value | Meaning |
| --- | --- | --- |
| `ml` | `NOT_CONFIGURED` | No model file yet. The maths engine works alone. |
| `geoip`, `p0f` | `DISABLED` | Optional local databases are not configured. |
| `database` | `HEALTHY` | The empty database was created by `setup`. |
| `capabilities` | `HEALTHY` on Linux | Nothing needs extra rights yet. |

`doctor` exits with code 0 when nothing is degraded, and 7 when something is.

## 3. Try It Without Any Setup

The fastest way to see it work is the built-in demo. The demo stops on its own.
It starts a local listener. It sends one local HTTP request to itself. It checks
that an event was recorded. Then it cleans up.

```sh
eye-for-an-eye demo
```

No root. No firewall. No open port to the Internet.

## 4. Add a Source of Traffic

The service can watch traffic in three ways.

**(a) A saved capture file.** This needs no setup, and it works offline:

```sh
eye-for-an-eye analyze-pcap capture.pcap --config eye-for-an-eye.toml
```

**(b) A live capture helper.** This is the normal case for a server. It needs a
small helper process with `CAP_NET_RAW`. The main service keeps no extra rights.
It talks to the helper over a Unix socket. See [Privileges](PRIVILEGES.md) and
[Deployment](DEPLOYMENT.md).

**(c) Decoy ports.** This is the honeypot case. Use the `honeypot` profile. See
[Deception](DECEPTION.md).

## 5. Run It

```sh
eye-for-an-eye run --config eye-for-an-eye.toml
```

It stays in the front window. When it starts, it prints what it will do:
the profile, the endpoints, whether outgoing network access is off, whether
active probes are off, and the firewall policy. Press `Ctrl+C` to stop.

To run it as a background service, see [systemd](SYSTEMD.md). Nothing is
installed as a service automatically.

## 6. Read What It Saw

From a second terminal, in the same folder:

```sh
eye-for-an-eye status  --config eye-for-an-eye.toml
eye-for-an-eye events tail --config eye-for-an-eye.toml --limit 10
eye-for-an-eye stats   --config eye-for-an-eye.toml
eye-for-an-eye storage info --config eye-for-an-eye.toml --json
```

The output shows metadata only. It never shows a password or a raw payload.

## 7. Check the Model

```sh
eye-for-an-eye model status --config eye-for-an-eye.toml
```

To use the model that ships with the project, set two paths in your
configuration and restart:

```toml
[ml]
model_path = "models/risk-logreg-v1.onnx"
manifest_path = "models/risk-logreg-v1.json"
```

The model is for **watching only**. Keep `decision.mode = "shadow"`.

## 8. What Next

* Read [Shadow Mode](SHADOW_MODE.md) to understand what a decision means.
* Read [Configuration](CONFIGURATION.md) to change a setting safely.
* Read [Privacy](PRIVACY.md) to see what is stored.
* Read [Enforcement](ENFORCEMENT.md) before you turn blocking on.

## If Something Goes Wrong

See [Troubleshooting](TROUBLESHOOTING.md). Start with:

```sh
eye-for-an-eye doctor --config eye-for-an-eye.toml --json
```
