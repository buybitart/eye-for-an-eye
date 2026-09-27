# Service Profiles (Deception Catalogue)

This page explains the "service profiles" used by the deception feature. A service profile is a fake network service, like a fake SSH or FTP server, that the system shows to a visitor. Read this page if you set up or check the deception (honeypot) feature. (P2 and P3 are earlier and later development stages of this project.)

## What is a service profile?

A `ServiceProfile` is a fixed data record. In Python, this is called a "frozen dataclass" — its values cannot change after creation. Each profile has:

- `profile_id` and `version`
- `transport` (for example TCP)
- `service_family` (what kind of service it looks like)
- `product` and `version_hint` (the name and version the fake service claims to be)
- `handler` (the code that runs the fake service)
- `max_request_bytes` and `max_response_bytes` (size limits)
- `idle_timeout` and `total_timeout` (time limits)
- `capabilities` (a `frozenset` — a fixed list of items that cannot be changed)
- extra fields: `banner`, `max_messages`, `max_transitions`

All profiles together form a "catalogue". The catalogue is a `tuple` — a fixed, ordered list. Its values do not change after the system loads it. The handler code cannot change what comes in from the network.

## Catalogue v2 profiles

| Catalogue v2 profile | Family / hint | Request / response total | Idle / total | Commands / transitions |
| --- | --- | --- | --- | --- |
| ssh-banner-v2 | SSH / OpenSSH 9.6 identification | 1024 / 1024 B | 2 / 5 s | 1 / 6 |
| ftp-control-v2 | FTP / generic | 4096 / 1024 B | 3 / 10 s | 12 / 40 |
| http-static-v2 | HTTP / Apache-like, no version claim | 4096 / 1024 B | 3 / 5 s | 1 / 6 |

(SSH, FTP, and HTTP are common network protocols. SSH is for secure remote login. FTP is for file transfer. HTTP is for web pages.)

The global request, response, and time limits in the system config can only make these budgets smaller, never bigger. The config file also has message and transition limits, and they work the same way. The greeting message counts as part of the response bytes and the transitions.

If a full response does not fit in what is left of the budget, the system does not send it. Instead, the handler closes the session. It never cuts a message in the middle to make it fit.

## How a profile is chosen (stable selection)

The system picks a profile using a hash function called HMAC-SHA256. A hash function turns input data into a short, fixed-size code, called a "digest". The input to this hash is:

- the text `EFAE-DECEPTION-V1`, followed by one NUL byte (a byte with value zero)
- the catalogue version, as a 4-byte number (`uint32`, big-endian, meaning the most important digits come first)
- the address family byte (4 for IPv4, 6 for IPv6)
- the packed destination IP address (4 bytes for IPv4, 16 bytes for IPv6)
- the destination port, as a 2-byte number (`uint16`, big-endian)
- the transport protocol byte (6 for TCP, 17 for UDP)

The address family byte tells the system how long the address is, so there is no confusion between the fields. A UDP (User Datagram Protocol) version of this input is allowed as part of the data format, but the system does not yet support choosing a profile for UDP traffic.

The digest picks one entry from a fixed, ordered list of candidate profiles. The port policy setting can narrow this list down to profiles from one address family. An explicit port override (a manual setting in the deployment config) is a separate choice made by the operator. The source IP address, meaning the visitor's own address, does not affect the choice. The same destination will always show the same profile, no matter which client connects.

The secret key for the hash comes from a mounted raw file (32 to 4096 bytes long) or from a hex-encoded environment variable. This secret is never included in the source code, and the setup process never creates one for you. The `config show` command hides both the secret value and its file path. There is no automatic fallback and no automatic secret generation. A public test value, `bytes(range(32))`, appears only in tests and in one limited benchmark — never in a real deployment.

## Changing profiles (migration and rotation)

Version P2 of the project used an older mapping system, without a separate catalogue field. Version P3 deliberately introduces catalogue v2, with a new data format. When you upgrade, old endpoint-to-profile mappings may change.

Before upgrading:

1. Save your old configuration and package, so you can roll back if needed.
2. Explicitly accept `catalogue_version=2`.
3. Check the endpoint profiles you need, in a lab environment.

P3 refuses any catalogue version it does not know, or that is too old. It never silently remaps to a different version on its own.

Any later change to the order of profiles, the banners, the capabilities, or their meaning needs a review, a new profile or catalogue version, and a new stability test. Never change the content of a catalogue version that has already been published. To roll back, restore the old package, catalogue, port overrides, and secret all together.

Rotating (changing) the secret is a separate operator action. It can change which profile is chosen for each endpoint, and it changes the pseudonym — a fake, repeatable ID — used for usernames. As long as the secret, the catalogue, and the endpoint configuration do not change, repeated scans and new processes will always choose the same profile and banner. Tests check the binary data format, the unchangeable fields, canonical IPv6 addresses, choosing a profile in a fresh process, and restarting the real service through the CLI (command-line interface).

The product names and version hints shown by these fake services are just a synthetic (made-up) surface. They do not promise any specific CVE (a public ID number for a known security vulnerability). TLS, SMTP, Redis, and MySQL are not part of this catalogue.

## See also

- [Protocol scope](PROTOCOL_EMULATION.md)
- [Deception overview](DECEPTION.md)
- [Deception safety](DECEPTION_SAFETY.md)
