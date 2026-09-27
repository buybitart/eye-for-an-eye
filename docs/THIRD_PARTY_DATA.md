# Third-Party Dependencies and Data

This page lists the external software packages and data files that Eye for an Eye uses, and explains their licence situation. Read this if you plan to package, publish, or legally review the project.

## Licence status

This project is licensed under the **MIT License** (see [LICENSE](../LICENSE)), Copyright (c) 2026 Aliaksandr Zasinets. SPDX identifier: `MIT`.

That settles the licence of this project's own code and nothing else. The base wheel has no dependencies, so it carries nobody else's code; every optional extra does. One of them, scapy, is **GPL-2.0-only**, which does not relicense this project and does change what you owe if you bundle it into a container image or a frozen binary. The package-by-package inventory is in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md); the data files below are separate again, because the licence of a reader is not the licence of what it reads.

No MMDB files (MaxMind's GeoIP data format), p0f signature files, or nmap-service-probes files are included in the Python wheel. The running program never downloads any of these by itself. The PCAP (packet capture) files used in the automated tests are made up ("synthetic") — they are not real captured network traffic.

## Checked Python dependencies

This table shows the licence metadata that was checked for each pinned (fixed-version) dependency:

| Dependency | Version | License metadata |
| --- | --- | --- |
| scapy | 2.7.0 | GPL-2.0-only |
| maxminddb | 3.1.1 | Apache-2.0 |
| ipwhois | 1.3.0 | BSD (metadata without a more precise SPDX expression) |
| dnspython | 2.8.0 | ISC |
| defusedxml | 0.7.1 | PSFL |

(SPDX is a standard way of writing licence names.)

Scapy, and the other optional "enrichment" packages, are not included in the minimal wheel or in the runtime container image. If you build a distribution that includes these extras, you must keep the licence and notice files from those wheels, and check that they are compatible with whatever licence the project chooses. This table is only an inventory of what is used. It is not a legal conclusion about anyone's right to republish this software.

## Data files supplied by the operator

These data files are never included in the software. You, the operator, must supply them yourself:

- **Nmap service probes.** This is a separate file that you provide. Its source, version, and checksum are recorded when you install it. This data belongs to the Nmap project, and follows the Nmap project's own licence terms — see the [Nmap NPSL](https://nmap.org/npsl/). Do not assume this data is public domain (free for anyone to use without restriction).
- **p0f signatures.** p0f is a tool that guesses details about a remote computer from patterns in its network traffic. Its signature file is a separate file that you must get from a trusted p0f source. Check the LICENSE of the exact distribution and version you use, and record where you got it, together with its hash (a checksum that proves the file has not changed). Do not assume a licence for a signature file just because you copied it from somewhere.
- **GeoIP MMDB data.** This is optional data that tells you which country or region an IP address is in. The licence of the software that *reads* this data is not the same as the licence of the data itself. The data vendor's own terms — including any account, download, update, or removal rules — and the data's accuracy must be checked separately. See the [MaxMind GeoLite documentation](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/).

## Checking what you have installed

The built-in diagnostics show the version of the data reader, and where your local data files came from. The `doctor` command, a built-in health check, reads a data file's age from its `mtime` (its last-modified time on disk). This is only a guess about age — it is not proof of the database's real, official release date.

## See also

- [Installation guide](INSTALL.md)
- [Dependencies](DEPENDENCIES.md)
- [Privacy](PRIVACY.md)
