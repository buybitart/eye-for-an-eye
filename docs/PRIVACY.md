# Privacy

This page says what the system stores, what it never stores, and where the data
goes.

## Where your data goes

Nowhere.

* There is no cloud service.
* There is no telemetry and no usage reporting.
* There is no update check over the network.
* The default `deployment.egress` is `disabled`.
* The API and the metrics endpoint bind to `127.0.0.1`.

The only optional network feature is RDAP lookup (`enrichment.rdap_enabled`).
It is **off** by default. If you turn it on, you send an IP address to a public
registry service. The documentation says so at the point where you turn it on.

## What is never stored

The redaction code (`eye_for_an_eye/security/redaction.py`) removes these before
anything is written to the database, the log file or the API:

* HTTP bodies and any raw payload,
* passwords and usernames,
* `Authorization` headers,
* cookies and session values,
* API keys, tokens and JSON Web Tokens,
* raw packet bytes.

Redaction happens in **one place** and is shared by storage, logs and the API.
There is no second path that writes around it.

Two things replace the removed data:

* `payload_length` — a number, for example 340.
* `credential_like_attempt` — true or false.

That is enough to say "someone tried to log in", without keeping what they typed.

## What is stored

For each event:

* time (UTC),
* source address and port,
* destination address and port,
* transport (TCP or UDP),
* event type,
* classification and confidence,
* safe metadata (counts, lengths, flags).

For each decision:

* the risk score,
* the action,
* the reasons,
* which behaviour numbers contributed.

## The source address

The source IP address **is** stored. A network defender that does not know who
connected cannot work.

But:

* The IP address is **never** given to the model as an input.
* Export can hide it: `--redact-ip` replaces it before writing a CSV or JSONL file.
* An IP address is not a person. The documentation repeats this on purpose.
* GeoIP, when enabled, is an estimate. It is not proof of location.

## How long it is kept

You choose. The website profile keeps 7 days:

```toml
[storage]
retention_seconds = 604800.0
max_events = 200000
max_bytes = 268435456
```

Old rows are deleted when any limit is passed. The database has a hard size
limit, so it cannot fill your disk.

## Deception data

Decoy services record what a visitor did. They do not record what the visitor
typed:

* `username_policy = "redact"` is the default,
* answers come from a fixed, finite list,
* there is no shell and no command execution,
* payload previews are off (`preview_enabled = false`).

## Shadow telemetry and datasets

Data exported from a live system is treated as sensitive:

* `datasets/unlabeled/` is in `.gitignore` and never enters the repository,
* the pseudonymisation secret (`*.dataset-secret`) is in `.gitignore`,
* the exporter drops payloads, credentials and full command text,
* a source hash is never used as a model input.

The data card lists exactly what a dataset row contains:
[DATA_CARD_v1.md](DATA_CARD_v1.md).

## Your rights over your own data

The database is a single SQLite file that you own. You can read it, copy it,
move it or delete it with normal tools. Nothing is encrypted with a key you do
not have, and nothing is hidden from you.

## See also

* [Storage](STORAGE.md)
* [Logging](LOGGING.md)
* [Third-party data](THIRD_PARTY_DATA.md)
* [Threat model](THREAT_MODEL.md)
