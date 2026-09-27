# Autonomous safety invariants

Fourteen properties that must stay true, and where each one is enforced.

These are not features. They are the things somebody breaks later by adding one
convenient function, so each is written as a test that fails the build rather
than the deployment. They live in `tests/test_p15_invariants.py`.

## The fourteen

| # | Invariant | Enforced by |
| --- | --- | --- |
| 1 | A candidate model never writes a firewall rule | no module in `decision/`, `governance/`, `autonomy/`, `training/` or `dataset/` imports the firewall; asserted by parsing imports |
| 2 | ML alone cannot bypass PolicyGuard | PolicyGuard only ever weakens an action; a refusal produces ALLOW whatever the model score |
| 3 | OOD never means malicious | a higher OOD score only lowers the conservative estimate; `HIGH_OOD` is a restraint, never support |
| 4 | Anomaly never means malicious | `ANOMALY` is not a behavioural family; an anomaly score alone cannot reach the diversity gate |
| 5 | Drift never means malicious | drift is model health; no code path adds it to a source's score |
| 6 | A block is never training ground truth | `blocked`, `automatically_blocked`, `model_score`, `shadow_decision` and `self_labelled` are in `FORBIDDEN_LABEL_SOURCES`; a row carrying one cannot be constructed |
| 7 | A challenge outcome is never ground truth | no reason code encodes a challenge result as a class; the challenge policy says so in the code |
| 8 | A `Host:` header is never a trusted SiteID | the resolver has no method that adds a site; an unmatched host becomes `UNKNOWN_SITE` |
| 9 | An untrusted proxy header is never client identity | a forwarded header from a peer that is not a configured trusted proxy is ignored, and recorded as ignored |
| 10 | An automatic block always expires | the record refuses a TTL of 0 or one above 43200s; every kernel element carries a timeout |
| 11 | A site-local action cannot reach another site | scope and cost profile are per scope; one mapping does not change another |
| 12 | A client behind a CDN cannot cause the CDN to be blocked | `network_enforceable` is false for any proxy-derived address, and the gate refuses |
| 13 | Unbounded remote state is impossible | every window, table and list is capped by construction; the caps are asserted by filling them |
| 14 | Hack-back cannot be enabled in production | there is no retaliation code to enable, and no setting whose name could turn one on |

## Invariant 14 deserves a paragraph

It is asserted structurally rather than behaviourally, and that is the honest
form. There is no hack-back, no retaliation, no scanner, no exploit code, no
outbound attack path, no shell execution in the request path and no remote
command interface anywhere in this repository. The test reads the source tree and
asserts there is still none.

That is weaker than a runtime refusal and stronger than a policy document.
**You cannot switch off a capability that was never written**, and a class with
no members is the correct outcome for a defensive project.

The one module that ever reaches outward — `active_probes` — is off by default,
requires an explicit CIDR allowlist, is refused outside a lab profile, and is
refused outright when a PCAP is being replayed.

## Adaptive parameters versus safety limits

The system adapts within bounded ranges. It does not adapt the bounds.

**May change autonomously:** which candidate model is active (under P14
governance), statistical baselines (under candidate baseline governance), which
block TTL tier applies, analysis intervals, non-destructive challenge policy.

**May never be changed by any autonomous component:** protected networks, the
maximum block TTL, the mass-block ceiling, firewall ownership, the public API
binding, the hack-back prohibition, the active-probe prohibition, the minimum
data quality for a block, model artifact validation requirements.

The separation is structural, not procedural. The cost model and the block
ceilings live in operator configuration; no code path from `learning/`,
`training/` or `governance/` writes to any of them. A component that could adjust
the price of its own mistakes would be grading its own work.

## No LLM, and no reinforcement learning, in the decision path

**No LLM decides ALLOW or BLOCK.** Network data is never sent to one. An LLM may
help a person write documentation or read a report offline; it has zero
enforcement authority, and nothing in the runtime package imports any client for
one.

**No bandit or RL algorithm chooses between allowing and blocking.**
Epsilon-greedy, Thompson sampling, UCB, Q-learning and deep RL all deliberately
balance exploration against exploitation. Blocking a real visitor is not a safe
exploration action, and `TEMP_BLOCK` is never an arm. If such a thing is ever
built here it stays lab-only against an offline simulator, over a non-destructive
action set — observe, watch, challenge — and it never reaches a firewall.

## Self-generated labels

Still prohibited, all of them:

```
blocked            -> malicious          NO
allowed            -> benign             NO
ML score high      -> malicious          NO
Math score high    -> malicious          NO
challenge failed   -> malicious          NO
challenge passed   -> benign             NO
```

A strong heuristic is still a heuristic. It does not become ground truth by being
good.

The runtime operates autonomously without new labels. Unlabelled production data
feeds drift, OOD, anomaly baselines, distribution monitoring and feature health —
none of which need a label. Supervised retraining needs trustworthy labels, and
if none arrive for six months the system keeps running on the model it has. Model
age alone is not a reason to replace anything.

## See also

- [AUTONOMOUS_DECISION.md](AUTONOMOUS_DECISION.md)
- [AUTONOMOUS_FAILURE_RECOVERY.md](AUTONOMOUS_FAILURE_RECOVERY.md)
- [AUTONOMOUS_DATA_CURATION.md](AUTONOMOUS_DATA_CURATION.md)
- [THREAT_MODEL.md](THREAT_MODEL.md)
- [MODULE_GRADUATION.md](MODULE_GRADUATION.md)
