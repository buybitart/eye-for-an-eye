# Risks and limitations

This page lists what can go wrong. Each risk has an impact, a mitigation that
exists today, and the part that is still not solved.

## The biggest risks first

### 1. False positive blocking

| | |
| --- | --- |
| **Impact** | A real reader, a customer, or the administrator cannot reach the site. For a news site, this is censorship by accident. |
| **Mitigation** | Shadow Mode is the default. Enforcement is lab-only. A strong action needs 20 samples, 5 seconds, 3 independent behaviour categories, a data-quality score of 0.70, and the maths engine to agree at 0.80. Blocks are temporary and short. Management networks, allowlists, trusted proxies and local addresses are never blocked. |
| **Remaining** | Legitimate automation genuinely looks like hostile automation. The rate has not been measured on real production traffic. |

### 2. Operator lockout

| | |
| --- | --- |
| **Impact** | The administrator blocks their own address and loses access to the server. |
| **Mitigation** | `enforcement.management_networks`, `allowlist` and `trusted_proxies` are checked twice: in the policy guard, and again in the firewall backend against local interface addresses read inside the target namespace. If the interface list cannot be read, no block is made. Enforcement cannot run in the host namespace at all. |
| **Remaining** | The lists are empty by default and the operator must fill them in. Documentation warns, but a warning is not a control. Any future host-level enforcement needs a lockout-safe design first. |

### 3. Distribution shift

| | |
| --- | --- |
| **Impact** | The model was fitted on lab and capture data. A real site's traffic is different, so the scores mean something different. |
| **Mitigation** | Three-source dataset with per-source distribution reporting and PSI-style shift measurement. Out-of-distribution detection. The shipped model is recommended for shadow only. The maths engine does not depend on the dataset. |
| **Remaining** | There is no production traffic in the dataset, because collecting it would mean collecting somebody's real traffic. This is a real and unresolved tension. |

### 4. Evasion

| | |
| --- | --- |
| **Impact** | An attacker who knows the thresholds stays under them: slow probing, distributed sources, one port per source. |
| **Mitigation** | Windows up to 900 seconds. Persistence and timing regularity are separate signals. Multiple independent categories are required, so a single-signal evasion is not enough to trigger, but it is also not enough to hide. |
| **Remaining** | A patient, distributed attacker defeats any per-source behavioural detector. This is a property of the approach, not a bug. |

### 5. Model poisoning or substitution

| | |
| --- | --- |
| **Impact** | A wrong or hostile model file changes decisions. |
| **Mitigation** | SHA-256 against the manifest; strict schema, shape, dtype and feature-order checks; symlink and network-path refusal; permission checks; a size cap; and, decisively, the model can never grant a block on its own. |
| **Remaining** | A poisoned model can still make the system miss attacks. Detecting that needs evaluation, not a hash. |

### 6. Bad manual labels

| | |
| --- | --- |
| **Impact** | A reviewer mislabels shadow samples and the next model learns the mistake. |
| **Mitigation** | `UNCERTAIN` is a valid answer and keeps a sample out of training. Label source and confidence are recorded per row. Leakage checks and a frozen test set. |
| **Remaining** | There is one reviewer. No inter-rater agreement can be measured. |

### 7. Self-reinforcing learning

| | |
| --- | --- |
| **Impact** | A system that learns "blocked means malicious" makes its own errors permanent. |
| **Mitigation** | Shadow rows are exported unlabelled and the validator rejects a shadow row carrying a supervised label. `previous_risk` is excluded from model inputs. There is no training code in the running service at all. |
| **Remaining** | The human step is the control. It does not scale, and it depends on the human. |

### 8. Resource exhaustion

| | |
| --- | --- |
| **Impact** | An attacker makes the defender consume memory or CPU, taking the machine down. |
| **Mitigation** | Every queue, cache, buffer and store has a limit. Drop-newest on the event queue. Bounded decision history with TTL and byte cap. Inference in a separate process with a 200 ms timeout, one at a time. Connection and byte limits on listeners. Storage limits by age, count and bytes. |
| **Remaining** | Under overload the system drops data. It reports this, but it is degraded. |

### 9. Unsafe API exposure

| | |
| --- | --- |
| **Impact** | The read-only API on a public address leaks who visits the site. |
| **Mitigation** | Loopback by default. A start-time warning when an endpoint is not loopback. Token auth and Host/Origin checks are available. The API is read-only and offers no file browsing or download. |
| **Remaining** | An operator can still expose it. |

### 10. The capture helper is a privileged parser

| | |
| --- | --- |
| **Impact** | A bug in packet parsing, in a process with `CAP_NET_RAW`, is a serious vulnerability. |
| **Mitigation** | The helper holds only `CAP_NET_RAW`, opens one non-promiscuous socket, does no analysis, opens no database, and sends bounded JSON over a Unix socket with peer-UID checking. Frame size is capped. The analysis side validates length and version. |
| **Remaining** | It still sees credentials in traffic. It is the first thing an auditor should look at. |

### 11. Supply chain

| | |
| --- | --- |
| **Impact** | A compromised dependency runs with the software's privileges. |
| **Mitigation** | The base runtime has **no** Python dependencies. Extras are optional and pinned in `uv.lock` with hashes in `requirements/runtime.txt`. An SBOM and checksums are produced. `pip-audit` and Bandit run in the checks. |
| **Remaining** | There is no signing infrastructure. A hash proves a file did not change; it does not prove where the file came from. |

### 12. Spoofed source pressure

| | |
| --- | --- |
| **Impact** | An attacker forges source addresses to fill the decision history, or to get a third party blocked. |
| **Mitigation** | Bounded history with TTL. Blocks are temporary. Behind a proxy, `trusted_proxies` prevents blocking the proxy itself. Connection-based signals need a completed handshake, which a blind spoof cannot produce. |
| **Remaining** | Connectionless observations can still be forged. Getting a third party temporarily blocked in a lab namespace is possible. |

### 13. Stale optional data

| | |
| --- | --- |
| **Impact** | An old GeoIP database gives a wrong estimate and someone treats it as fact. |
| **Mitigation** | Off by default. `doctor` reports file age and marks data older than 30 days as degraded. Documentation states repeatedly that GeoIP is an estimate and an IP address is not a person. Enrichment is never a model input. |
| **Remaining** | Operators may still over-read it. |

## Limitations that are not risks, just facts

* Automatic blocking is lab-only.
* Live capture requires Linux and a helper with `CAP_NET_RAW`.
* Windows and macOS are development platforms only.
* Risk scores are not probabilities. The code marks them uncalibrated.
* There is no defence against a volumetric denial of service. That needs
  capacity upstream.
* `RATE_LIMIT` is recorded but not applied.
* The private security reporting channel is prepared but not yet usable: it is
  GitHub Private Vulnerability Reporting, and the public repository does not
  exist yet.
* There has been no external independent security audit.
* There are no known production deployments and no user research.

## See also

* [Limitations](LIMITATIONS.md)
* [Threat model](THREAT_MODEL.md)
* [Security review scope](SECURITY_REVIEW_SCOPE.md)
* [Monitoring and evaluation](MONITORING_EVALUATION.md)
