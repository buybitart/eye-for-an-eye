# Configuration

The configuration file is TOML. `eye-for-an-eye setup` writes a safe one for
you. This page explains the settings you are most likely to change.

Every value below is the real default from the code.

## The Five Settings That Matter Most

```toml
[deployment]
profile = "sensor"        # sensor | honeypot | lab

[decision]
mode = "shadow"           # shadow = decide, never block

[ml]
enabled = true            # use a local model if one is configured

[enforcement]
enabled = false           # no firewall change

[active_probes]
enabled = false           # never send packets back to a source
```

If you change nothing else, the system watches and does not block.

## Rules of the File

* One file, strict TOML. An unknown section or key is an error, not a warning.
* Relative paths are resolved next to the configuration file, not next to your
  shell. So `path = "events.sqlite3"` always means "beside this file".
* `config_version = 1` is required. Use `eye-for-an-eye config migrate` to move
  an older file to a new one. Migration never edits the old file.
* Changing the file needs a restart. There is no reload on `SIGHUP`.
* Environment variables can override values. The name is
  `E4E__SECTION__KEY`, for example `E4E__DECISION__MODE`.

Check a file before you use it:

```sh
eye-for-an-eye config validate --config eye-for-an-eye.toml
eye-for-an-eye config show     --config eye-for-an-eye.toml --source
```

`--source` tells you where each value came from: default, config, environment or
command line. Secrets are never printed.

## Profiles

`eye-for-an-eye setup --profile <name>` writes a starting file.

| Profile | What it is for | Listener | Secret file |
| --- | --- | --- | --- |
| `website` | A normal web server or VPS. Watch only. | none | no |
| `sensor` | Passive analysis from capture or a file. | none | no |
| `honeypot` | Decoy services on chosen ports. | yes | yes |
| `lab` | Loopback-only experiments. | loopback only | yes |

`website` is a friendly name for the `sensor` deployment profile with settings a
website owner wants. It is not a fourth engine mode.

## Sections

### `[deployment]`

| Key | Default | Meaning |
| --- | --- | --- |
| `profile` | `sensor` | Which runtime shape to use. |
| `egress` | `disabled` | Whether any outgoing network call is allowed at all. |

### `[network]`

| Key | Default | Meaning |
| --- | --- | --- |
| `bind_address` | `127.0.0.1` | Where a listener binds. |
| `port` | `1234` | Listener port. |
| `protocol` | `tcp` | `tcp` or `udp`. |
| `udp_responses` | `false` | Never answer UDP. Keep this false. |

### `[capture]`

| Key | Default | Meaning |
| --- | --- | --- |
| `interface` | `""` | Network interface for the helper. |
| `ipc_socket` | `""` | Unix socket to the capture helper. |
| `pcap_path` | `""` | Read a saved capture file instead. |
| `bpf` | `ip or ip6` | Filter for captured packets. |
| `max_frame_bytes` | `8192` | Hard limit on one frame. |

A sensor needs either `ipc_socket` or `pcap_path`. With neither, the service
starts, checks itself and stays idle.

### `[decision]`

| Key | Default | Meaning |
| --- | --- | --- |
| `mode` | `shadow` | `shadow` or `enforce`. |
| `math_weight` | `0.55` | Weight of the maths engine. |
| `ml_weight` | `0.35` | Highest possible weight of the model. |
| `persistence_weight` | `0.10` | Weight of "it keeps coming back". |
| `watch_threshold` | `0.40` | Risk needed for `WATCH`. |
| `rate_limit_threshold` | `0.70` | Risk needed for `RATE_LIMIT`. |
| `block_threshold` | `0.88` | Risk needed for `TEMP_BLOCK`. |
| `hysteresis_margin` | `0.10` | Stops fast flapping between states. |
| `minimum_samples_for_block` | `20` | Fewer samples, no strong action. |
| `minimum_observation_seconds` | `5.0` | Shorter, no strong action. |
| `minimum_quality` | `0.70` | Data quality needed for a strong action. |
| `minimum_categories` | `3` | Independent behaviour categories needed. |
| `minimum_math_risk` | `0.80` | The maths engine must agree. |
| `minimum_ml_confidence` | `0.70` | Below this, the model is not trusted. |
| `half_life_seconds` | `60.0` | Old risk halves this often. |

All thresholds are configurable. The action table follows from them:

| Risk | Action |
| --- | --- |
| 0.00 – 0.40 | `OBSERVE` |
| 0.40 – 0.70 | `WATCH` |
| 0.70 – 0.88 | `RATE_LIMIT` |
| 0.88 – 1.00 | `TEMP_BLOCK` |

### `[ml]`

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Use a model when one is configured. |
| `required` | `false` | If true, the service refuses to start without a healthy model. Keep false. |
| `model_path` | `""` | Path to the `.onnx` file. |
| `manifest_path` | `""` | Path to the `.json` manifest. |
| `max_model_bytes` | `16777216` | Largest model file allowed. |
| `inference_timeout_ms` | `200` | Hard time limit for one inference. |
| `max_pending` | `64` | Longest queue of waiting requests. |
| `cache_ttl_seconds` | `10.0` | How long a result is reused. |

Empty paths mean no model. That is a normal, safe state.

### `[enforcement]`

**Two switches, two blast radii.** Read [Enforcement](ENFORCEMENT.md) and
[Host enforcement](HOST_ENFORCEMENT.md) before you change either.

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | The lab path: nftables inside a named, throw-away namespace. Requires `deployment.profile = "lab"` and `firewall.lab_namespace`, and refuses the host namespace. |
| `host_enabled` | `false` | The host path: a bounded temporary block on **this machine**, through a privileged helper. Refuses the `lab` profile, refuses to run without a protected network, and cannot be combined with `enabled`. **The most consequential setting in this file.** |
| `management_networks` | `[]` | Never block these. Put your own network here first. Required by `host_enabled`. |
| `allowlist` | `[]` | Never block these. |
| `trusted_proxies` | `[]` | Never block these. |
| `max_entries` | `1024` | Largest number of live blocks. |
| `block_seconds` | `[300, 1800, 7200, 43200]` | 5 min, 30 min, 2 h, 12 h. |
| `offense_decay_seconds` | `21600.0` | After 6 quiet hours the counter resets. |

### `[autonomy]`

Decisions taken without a person approving each one. **Off on a fresh
installation**, and `mode = "shadow"` even once it is on. Read
[Autonomous mode](AUTONOMOUS_MODE.md) first; the full cost model and evidence
gates are in [Cost-sensitive policy](COST_SENSITIVE_POLICY.md) and
[Autonomous decision](AUTONOMOUS_DECISION.md).

Autonomy and `enforcement.enabled` are mutually exclusive: when the P15
authority owns TEMP_BLOCK the legacy lab enforcer is not constructed at all.

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Build the P15 decision authority at all. |
| `mode` | `"shadow"` | `shadow` records the decision and acts on nothing. `autonomous` acts, within the budget and the breakers. |
| `calibrator_path` | `""` | **Required when `mode = "autonomous"`**; the configuration will not load without it. Turns a risk score into a probability, which is what a block is taken against. |
| `default_cost_profile` | `"public_website"` | Which cost profile applies where no scope maps to one. |
| `cost_profiles` | `{}` | Scope (`GLOBAL`, `SITE:<id>`, `SERVICE:<port>/<proto>`) to profile name. |
| `decision_margin` | `0.25` | How far past the cutoff the arithmetic must be. |
| `blocks_per_minute` | `10` | New autonomous blocks per minute, all scopes. |
| `max_active_blocks` | `500` | Blocks held at once. |
| `max_block_share` | `0.02` | The mass-block ceiling. There is no setting that turns it off. |

Evidence: the two optional files, both off by default and both local only. What
they cost and what happens when the disk fills is in
[Backpressure](BACKPRESSURE.md).

| Key | Default | Meaning |
| --- | --- | --- |
| `decision_journal_path` | `""` | The forensic record: one full decision per line. A file of behaviour, so keep it local. |
| `journal_include_source` | `false` | Keep the operational address as well as the pseudonym. |
| `journal_required_for_action` | `false` | Whether a decision that could not be journalled may still be acted on. Both answers are defensible; [Backpressure](BACKPRESSURE.md) says which failure each one asks you to prefer. |
| `journal_max_file_bytes` / `_max_files` / `_max_total_bytes` | 8 MiB / 4 / 32 MiB | The journal's disk ceilings. |
| `shadow_export_path` | `""` | Privacy-safe analytic rows for independent evaluation. No address at any setting; timestamps coarsened to the hour; labels never written. |
| `shadow_export_max_file_bytes` / `_max_files` / `_max_total_bytes` / `_max_records` | 8 MiB / 8 / 64 MiB / 100,000 | The export's disk ceilings. |
| `shadow_export_bucket_seconds` | `3600` | How coarse an exported timestamp is. |

### `[deception]`

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Allow decoy answers when a listener runs. |
| `mode` | `sensor` | `sensor` or `lab`. `lab` requires a loopback bind. |
| `decoy_ports` | `[]` | Ports to imitate. |
| `source_allowlist` | `["127.0.0.0/8", "::1/128"]` | Who may reach a decoy. |
| `username_policy` | `redact` | Never store what was typed. |
| `preview_enabled` | `false` | Never store a payload preview. |
| `max_messages` | `12` | Longest decoy conversation. |

### `[storage]`

| Key | Default (website profile) | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Write events to SQLite. |
| `path` | `events.sqlite3` | Beside the config file. |
| `retention_seconds` | `604800.0` | 7 days. |
| `max_events` | `200000` | Row limit. |
| `max_bytes` | `268435456` | 256 MiB limit. |

### `[api]` and `[metrics]`

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` (website profile) | Turn the local endpoint on. |
| `bind_address` | `127.0.0.1` | Local only. |
| `port` | `8777` / `8778` | API and metrics. |

Do not put these on a public address. If you must, put authentication and TLS in
front of them and restrict access. The service prints a warning at start when an
endpoint is not on loopback.

### `[enrichment]`

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Local GeoIP lookup. |
| `rdap_enabled` | `false` | **Sends an address to a public registry.** Off. |
| `mmdb_path` | `""` | Your own local GeoIP database file. |

Nothing is ever downloaded for you. You supply the database file.

### `[limits]`

Bounds for a listener: 256 connections, 8 per address, 4096 request bytes, 1024
response bytes, and timeouts of 2 s (first byte), 5 s (idle) and 10 s (total).

## Example Files

* `config.example.toml`: every key with comments.
* `config.sensor.toml`, `config.honeypot.toml`, `config.lab.toml`: starting points.
* `eye_for_an_eye/templates/*.toml`: what `setup` writes.

## See Also

* [Quickstart](QUICKSTART.md)
* [Service profiles](SERVICE_PROFILES.md)
* [Shadow Mode](SHADOW_MODE.md)
* [Autonomous mode](AUTONOMOUS_MODE.md)
* [Host enforcement](HOST_ENFORCEMENT.md)
* [Backpressure](BACKPRESSURE.md)
* [Troubleshooting](TROUBLESHOOTING.md)
