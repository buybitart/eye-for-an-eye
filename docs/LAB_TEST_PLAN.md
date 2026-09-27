# Historic Lab Test Plan (P0)

This page keeps the test plan from an early development phase called "P0." It is history, not a current task list. Read it if you want to know which checks were planned back then, and what evidence each one asked for.

**These checks work only in an isolated test lab. They do not manage your real firewall, and they must not run on a production machine.**

## Status

The status of this whole plan is: **NOT VERIFIED IN CURRENT ENVIRONMENT**.

During P0, nobody actually ran live packet capture, raw ICMP (the network protocol used for tools like "ping"), real firewall changes, external scanning, or real RDAP (domain and address lookup) queries. The checks below were written for a separate, clearly marked-off lab: a virtual machine, a container, or a Linux network namespace, with test peers you fully control yourself.

## Where the Current Information Lives

The current commands and limits are described in [DEPLOYMENT.md](DEPLOYMENT.md), [PRIVILEGES.md](PRIVILEGES.md), and [FIREWALL.md](FIREWALL.md).

Two things changed after this plan was first written:

* Live packet capture used to run directly inside the analysis process. It was replaced by a separate capture helper program, connected over Unix IPC (inter-process communication through a local socket).
* The firewall manager and its opt-in namespace tests (see [FIREWALL.md](FIREWALL.md)) were added later.

Any mention of "future P1" below is now historic. It does not describe a current backlog of work.

## What You Need Before Starting

The operator must supply:

* a Linux lab machine,
* a separate virtual network interface,
* a test TCP peer (another machine or process to test against),
* IPv4 and IPv6 addresses to use,
* an independent packet-capture (pcap) observer, if one is needed.

By default, this lab has no route out to the real internet.

Minimal packet-capture permissions must be set up in advance by the operator. The project itself never grants its own capabilities, and it never reads or changes any firewall on its own. Run the listener as a separate, unprivileged (non-admin) user account. Run the normal regression tests from the README first, before starting any of the checks below.

Do not use the real host's firewall, and do not use production network interfaces for this. If a redirect test is needed, the operator sets those rules up separately, inside a disposable lab. This page itself contains no runnable firewall commands.

## Checks and What Counts as a Pass

| Scenario | Action inside the isolated lab | Expected result / evidence |
| --- | --- | --- |
| AF_PACKET / capture permissions | Run `ip_id` on the lab interface, then run it again without capture permission. | With the right permission, normal events appear. Without it: a clear error, a clean exit, and no worker process left running. |
| BPF (Berkeley Packet Filter, the kernel's packet-filtering language) | Use a working filter, then a broken one. | The working filter picks out the right incoming packets. The broken one exits with an error. |
| Passive-only | Run `nat` with no active flags, then send a few packets from the lab peer. | An independent observer sees no outgoing ICMP, RDAP, or DNS traffic from the process. A base event is still written. |
| Active policy | Turn on `nat --active-path-probe --allow-cidr <LAB_PEER>/32`. | One ICMP request that the policy allowed, plus a LOW or UNKNOWN observation. An address outside the allowed list causes no request to be sent at all. |
| Timeout / negative cache | The peer does not answer. Repeat the same check against the same address for 60 seconds. | Result is UNKNOWN or timeout. A repeated check sends no new ICMP request until the cached entry expires. |
| Wrong ICMP reply | In the lab setup, send back an ICMP error message instead of a normal echo reply. | Result is UNKNOWN or "invalid response." No NAT or VPN claim is made. |
| IPv4 original destination | In a prepared lab redirect setup, compare the connection's address before and after the redirect. | `SO_ORIGINAL_DST` (a way to ask the kernel for the address before redirect) returns the original IPv4 address and port. The HMAC-based fingerprint stays stable for the same original address. The fallback path is checked separately, without any redirect in place. |
| IPv6 loopback listener | Start a TCP listener on `::1` (the IPv6 loopback address) and connect a local test peer to it. | A normal, bounded response, and a clean shutdown. No claim is made about an IPv6 original destination. |
| IPv6 live capture | Test controlled TCP traffic, ICMPv6, extension headers, and fragmented packets. | The outer IP address is treated as the source. A quoted payload inside an ICMP error never becomes its own outer TCP record. Fragments never reach the timestamp or p0f fingerprinting logic. |
| Secondary interface IPs | Send packets to the machine's main address, and separately to its other addresses. | Measure how much is actually seen. The current capture code only reads from one IPv4 and one IPv6 address, so traffic to the other addresses may be missed. |
| Idle capture shutdown | Send no traffic, then press Ctrl+C or send SIGTERM (a normal "please stop" signal). | The process exits after its capture timeout. Cleanup is bounded, and no process is left behind. |
| Slow client | Connect one idle client and one normal, working client. Then add one slow-reading client. | The working client is still served normally. The first-byte, idle, and total time limits close the problem connections. |
| Resource bounds | Send a limited, agreed-upon number of test sources, within the test budget. | Active connections, internal state, and queues all stay inside their configured limits. Measure memory use (RSS), CPU use, open file handles, and drop counters. |
| Long-run capture | Run a time-limited stream of traffic with a known packet count. | Measure the loss caused by reopening the capture every 0.5 seconds, and by sampling. Do not assume the current capture setup loses zero packets. |
| Real MMDB (a common file format for GeoIP location databases) | Use the operator's own real test database file, with one entry known to exist and one known to be missing. | Fields come back normalised, or as `not_found`. A missing locale (language setting) does not crash the process. The file handle is properly closed afterward. |
| RDAP contract (RDAP looks up who owns a domain or IP address, like a modern WHOIS) | Start with the fake test provider already used in the automated tests. Only reach a real, live registry after getting explicit permission. | The base event is written before enrichment happens. Measure the DNS and HTTP behaviour, and the full end-to-end time limit. The result must never be read as revealing a real person's identity. |

## What to Record

For every check: the operating system and kernel version, the Python version, the packet-capture driver (Scapy or otherwise), the configuration used (with secrets removed), hashes of the test input files, the standard output and error text, the exit code, the shutdown time, memory (RSS), file-descriptor and process counts, and a separate, independent packet capture (pcap) file of the test.

## Keep It Honest

Keep losses, budget overruns, and "unknown" statuses as real test results. Do not throw them away. Do not mark any of these checks as "passed" before it has actually been run.

## What Came Next (as Written at the Time)

After running this plan, the team planned to decide separately about "P1" work: a persistent capture handle, IPv6 and original-destination checks, an operating-system-level sandbox and resource limits, a continuous-integration (CI) test matrix across platforms, and delivering operational logs somewhere central. The firewall manager, and any deployment on a public-facing network, were both explicitly out of scope for P0.

## See Also

* [DEPLOYMENT.md](DEPLOYMENT.md): the current, up-to-date deployment commands and limits.
* [PRIVILEGES.md](PRIVILEGES.md): what system permissions each component needs today.
* [FIREWALL.md](FIREWALL.md): the firewall manager and its own lab-only tests, added after this plan.
* [history/README.md](history/README.md): why the phase completion records are not published.
* [RISKS_AND_LIMITATIONS.md](RISKS_AND_LIMITATIONS.md): known limits of this project as a whole.
