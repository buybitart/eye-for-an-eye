# Backpressure: What Happens When the Disk Is Slow or Full

Eye for an Eye writes two optional files while it decides: the **decision
journal** (the full forensic record) and the **shadow export** (privacy-safe
analytic rows). Both are off by default.

This page says what happens to your sensor when the disk those files live on
gets slow, gets full, or goes away. Read it before you turn either file on, and
read it again before you change `journal_required_for_action`.

## The Rule, in One Line

**Serving traffic comes first. The journal comes second. The export comes
last.**

Nothing the sensor writes to disk is allowed to stop it from watching traffic.
A storage problem stays a storage problem; it does not become a defence outage,
and it does not become a block nobody can explain.

## There Is No Queue

A slow file could be handled by putting writes on a queue and draining them
from a background thread. Eye for an Eye does not do that.

A queue would add a thread, a shutdown ordering problem, and a new way to lose
records without counting them, and a queue with no maximum is just a slower
way to run out of memory. Instead each writer carries a **deadline**:

* A write that takes longer than the writer's `slow_write_seconds` budget is
  counted as a slow write.
* That trips a **cooling-off period** of `cooldown_seconds`, during which
  writes are dropped and counted instead of attempted.
* When the cooling-off period ends, one write is attempted again.

So the cost of slow storage on the decision path is **one slow write per
cooldown**, not one per decision. With the defaults that is at most one write
every five seconds, whatever the event rate.

The two budgets are different on purpose, and that difference is the priority
order above:

| Writer | Deadline | Meaning |
|---|---:|---|
| Decision journal | 0.25 s | allowed to be patient |
| Shadow export | 0.05 s | gives up first |

## Dropping Is Visible, Never Silent

A file that stops growing looks exactly like a system that stopped deciding.
So every drop is counted and reported rather than inferred:

```text
eye-for-an-eye status
```

and the metrics endpoint carry:

| Counter | What it means |
|---|---|
| `decision_journal_records_total` | records that landed |
| `decision_journal_failures_total` | records that did not |
| `decision_journal_rotations_total` | how often the file rolled over |
| `decision_journal_bytes` | disk currently held by the journal set |
| `shadow_export_rows_total` | rows that landed |
| `shadow_export_failures_total` | rows that did not |
| `shadow_export_dropped_total` | rows dropped during cooling-off |
| `shadow_export_bytes` | disk currently held by the export set |

The health surface reports a configured writer that cannot write as
**DEGRADED**, never as NOT_CONFIGURED. Those are opposite facts ("nobody asked
for this" and "this is broken"), and reporting both with the same word is how a
broken component becomes invisible.

`last_error` in the status output carries the reason, bounded to 200
characters: the errno for a full disk, or the measured duration for a slow one.

The live counters are in the running sensor's status snapshot, under
`decision.autonomous.journal` and `decision.autonomous.shadow_export`, and on
the metrics endpoint under the names above.

### Catching the Mistake Before the First Decision

A journal pointed at a directory that does not exist behaves exactly like a
full disk, except that it is entirely preventable. `eye-for-an-eye doctor`
checks both paths and names whichever one is wrong:

```text
autonomy.evidence_files  DEGRADED
  journal: the directory does not exist or is not writable, so records
  will be counted as failures and dropped
```

This is a permission check and not a write, so it cannot promise the write will
succeed. It catches the configuration mistake, which is the common one.

## The Disk Ceiling

Neither file can grow without limit. Four ceilings apply to each, and all four
are enforced:

| Setting | Journal default | Export default |
|---|---:|---:|
| `*_max_file_bytes` | 8 MiB | 8 MiB |
| `*_max_files` | 4 | 8 |
| `*_max_total_bytes` | 32 MiB | 64 MiB |
| max records per file | 20,000 | 100,000 |

`max_total_bytes` exists because the other three have a product that nobody
computes. Raising `max_files` without thinking about it is the normal way a
log set quietly triples.

When a file reaches its size or record ceiling it is renamed (`decisions.jsonl`
becomes `decisions.jsonl.1`, and so on), and the oldest is deleted. Renaming
rather than copying means a reader holding the old path keeps reading a
complete file, and no record is ever half-moved.

A single record that serialises to more than 256 KiB is refused and counted
rather than written. A record that large is not a record; it is a bug producing
unbounded content, and writing it would be the wrong way to find out.

## When the Disk Is Full

A full disk produces `ENOSPC` on every write. What happens then:

* The decision is **unchanged**. The same traffic produces the same action,
  the same reason codes, the same probability and the same cost profile it
  would have produced with a healthy disk.
* The failure is **counted**, and the journal's health becomes DEGRADED.
* No exception reaches the event loop. The sensor keeps accepting, parsing,
  correlating and deciding.
* Nothing is enforced that would not otherwise have been enforced, and nothing
  already in the firewall is touched.
* The operational log still carries a bounded summary of every decision. The
  decision id, the action, the profile, the probability, the bound and the
  reason codes, so a block stays explainable even when its full record did
  not land.

Records written before the disk filled are kept. A write interrupted partway
leaves one truncated last line, which is counted as a failure and which a
reader skips; every other line still parses on its own.

## `journal_required_for_action`

This is the one setting that changes the answer above, and it is a real choice
rather than a hypothetical one.

```toml
[autonomy]
journal_required_for_action = false   # the default
```

**False (default).** A decision that could not be journalled may still be
acted on. The accountable minimum survives either way, in the operational log.
Nothing in this project's existing policy makes durable auditability a
precondition for acting, and inventing one silently would be inventing policy.

**True.** A block whose record did not land is withheld, and the withholding is
named: `enforcement_withheld = "decision_not_journalled"`. This is safe in the
false-positive direction and it turns a storage problem into a defence outage.
A full disk stops autonomous blocking.

Neither is the silent option. Both name what they did. Pick the failure you
would rather explain.

Note the name. `[autonomy]` is the decision section, and no setting in it may
reach the firewall. The invariant test refuses any name there containing
`firewall`, `nftables`, `namespace` or `enforce`. This setting only ever
*withholds* an action; it can never grant one.

## Turning the Files On

```toml
[autonomy]
enabled = true
mode = "shadow"

# The forensic record. A file of behaviour: keep it local.
decision_journal_path = "/var/lib/eye-for-an-eye/decisions.jsonl"
journal_include_source = false        # pseudonyms only, by default

# The analytic rows. No address at any setting, timestamps coarsened to
# the hour, label fields always empty.
shadow_export_path = "/var/lib/eye-for-an-eye/shadow-export.jsonl"
```

Both files are created mode `0600`. Both are local only: nothing here is sent
anywhere, and moving either off the machine is your deliberate act.

## What This Costs

Measured on one machine, in `reports/P15_5R_PERFORMANCE.json`. At the densest
possible decision rate (every single event triggering a decision window) the
complete autonomous path including both files costs about **0.7 ms per
decision**. At the shipped 2-second decision interval the difference against
the non-autonomous path was inside run-to-run noise.

These are numbers from one machine and not a promise about yours. Repeat them
with:

```text
python -m benchmarks.run --case autonomous --full --output <your-file>.json
```

## Related Pages

* [Autonomous mode](AUTONOMOUS_MODE.md)
* [Shadow mode](SHADOW_MODE.md)
* [Benchmarking](BENCHMARKING.md)
* [Metrics](METRICS.md)
* [Logging](LOGGING.md)
