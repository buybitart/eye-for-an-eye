# Moving away from the old entry points

This page is for people who still run the old `+something.py` scripts. It
shows the new command for each old script. Read this page before you move an
old deployment to the current version.

## Old scripts are still there, but deprecated

The old scripts `+proto.py`, `+services.py`, `+ip_id.py`, `+nat.py`,
`+uptime.py`, and `+garbage.py` still exist. They now work as "import-safe
wrappers" — thin files that just call the new code, so they do not break if
you import them.

Since phase P6, these old scripts are deprecated (planned for removal) for
new deployments. They will not be removed before version 0.9.0, and only
after a separate public announcement and review. Phase P6 itself does not
remove any of them.

## Old command, new command

| Old command | New CLI replacement |
| --- | --- |
| `python +proto.py 1234 tcp` | `eye-for-an-eye proto 1234 tcp` (a transitional, observe-only listener) |
| `python +services.py ...` | `config init --profile honeypot`, then `run --config` |
| `python +ip_id.py --pcap file` | `analyze-pcap file`, or `run` with a sensor config using PCAP (a saved packet capture file) |
| `python +nat.py` / `python +uptime.py` | `eye-for-an-eye nat` / `eye-for-an-eye uptime`, using passive PCAP or IPC (inter-process communication) |
| `python +garbage.py --lab` | `eye-for-an-eye garbage --lab` — deprecated, finite (bounded, not endless), and lab-only |

## A warning about deception

Do not turn the observe-only `proto` command into a deception tool by
accident. A honeypot answers with a fixed set of TCP profiles (canned
responses that imitate real services). The `proto` command only watches
traffic — it never answers with one of these profiles.

The `run` command for the sensor accepts input from PCAP files or IPC. It
does not open a TCP deception listener on its own. Once you install the
packaged wheel (the standard Python package format), you do not need any of
the old `+*.py` files at all.

## Moving your configuration file

If you have an old, unversioned TOML configuration file, convert it with:

```
config migrate --config old.toml --output new.toml --profile sensor
```

If your old setup used `+services.py`, choose the `honeypot` profile
instead of `sensor`.

After migrating, review these things by hand:

* absolute file paths
* the persistent secret
* the decoy, real, and management ports
* the egress policy (the rule for outbound network traffic)
* the deception catalogue version (the `catalogue_version` setting, which
  is `2` today)

## See also

* [Upgrade](UPGRADE.md)
* [Configuration](CONFIGURATION.md)
* [Install](INSTALL.md)
