# Review queue

The review queue is where the system puts behaviour it could **not** decide by
itself, so a person can look at it later.

**A decision is not a label.** Nothing in this project turns a block, a score or
a threshold into training data. A training label exists only where a person
answered a question.

Status: **Beta.** Limits and priority values are provisional.

## Why this exists

A system that learns from its own output stops learning. If "the system blocked
it" became "this is malicious", then every mistake would be taught back to the
next model, and the model would get more certain about the same mistake every
time. This is a well known failure and it is easy to build by accident.

So the queue holds the opposite of what you might expect. A confident decision
the system already acted on is **not** put in front of a person. What is put in
front of a person is the traffic the system was unsure about.

## What gets queued

An entry is admitted only for one of these reasons:

| Reason | Why it needs a person |
| --- | --- |
| the mathematical engine and the model disagree | one of them is wrong and the system cannot tell which |
| the risk landed in the middle | the evidence did not settle it |
| high risk that the policy did not act on | a rule stopped the action; was the rule right? |
| behaviour is outside the training distribution | the model has not seen traffic like this |
| the anomaly model finds this unusual | unusual is not the same as bad, and only a person can say which |

Very little evidence in a window **lowers** the priority. A short, thin window is
usually not worth anyone's time.

A window that was blocked with high confidence earns nothing. Being acted on is
not a reason to review.

## What is stored

Behaviour numbers only. The same 16 behaviour features the model itself sees:

```text
connections_60s, connections_900s, ports_60s, ports_900s, destinations_60s,
families_60s, repetition_60s, sequential_60s, anomaly_60s, credentials_60s,
continuation_60s, persistence_900s, burst_10s, interarrival_mean_60s,
interarrival_cv_60s, deception_60s
```

Plus how much evidence there was, why the entry is here, and what the system
thought at the time. What the system thought is marked as context. It is never a
label and never a model input.

**Not stored:** the address, any payload, any header, any credential, any
username, any cookie.

A source is grouped by a keyed digest (`src-` and 16 hex characters). This lets
a reviewer see the same source twice. It cannot be turned back into an address.
The key is a local file that is never committed.

## Limits

Every limit is a refusal, not a warning.

| Limit | Default | What it stops |
| --- | --- | --- |
| `review_queue_max_entries` | 2000 | the queue growing without bound |
| `review_queue_per_source` | 20 | one source filling the queue |
| `review_queue_per_day` | 500 | one busy day filling the queue |
| `review_queue_ttl_days` | 30 | old unreviewed entries piling up |
| `review_queue_min_observations` | 5 | thin windows nobody can judge |

Two more rules matter:

* The **same behaviour from the same source is one entry.** Values are rounded
  before comparing, so a small change does not buy a second place.
* An entry a person has answered is **never** dropped to make room. A person's
  answer is the scarce thing here. If the queue fills with answered entries, the
  system stops collecting and tells you to export them.

Together these mean an attacker who can make the sensor unsure still cannot
choose what the next dataset looks like.

## Review states

| State | Meaning |
| --- | --- |
| `UNREVIEWED` | waiting for a person; this is the only state the system can write |
| `BENIGN_LIKE` | a person judged this ordinary |
| `MALICIOUS_AUTOMATION_LIKE` | a person judged this automated abuse |
| `UNCERTAIN` | a person looked and could not tell |
| `IGNORE` | not worth anyone's time |

`UNCERTAIN` is a real answer, and it is the right one whenever the evidence does
not settle it. It keeps a row out of supervised training instead of guessing.

`IGNORE` produces **no label at all**. It is not the same as benign.

A reviewed answer is `MEDIUM` confidence at best. `HIGH` is reserved for
deterministic controlled ground truth, which a person reading a summary does not
have.

## Turning it on

The queue is **off by default**. It writes to disk and needs a local secret, so
an operator has to ask for it.

```bash
head -c 48 /dev/urandom | base64 > /etc/eye-for-an-eye/review.secret
chmod 600 /etc/eye-for-an-eye/review.secret
```

```toml
[reliability]
review_queue_enabled = true
review_queue_path = "/var/lib/eye-for-an-eye/review-queue.json"
review_queue_secret_file = "/etc/eye-for-an-eye/review.secret"
```

A missing or short secret leaves the queue closed and counts
`review_queue_unavailable_total`. It never stops the sensor.

## Using it

```bash
eye-for-an-eye review status              # how much is waiting
eye-for-an-eye review list                # what is waiting, most useful first
eye-for-an-eye review show <entry>        # the full behaviour of one entry
eye-for-an-eye review answer <entry> --answer benign --note "nightly backup"
eye-for-an-eye review answer <entry> --answer automation --note "port sweep"
eye-for-an-eye review answer <entry> --answer uncertain
eye-for-an-eye review answer <entry> --answer ignore
eye-for-an-eye review reset <entry>       # take an answer back
eye-for-an-eye review export --out labels.json
```

`review answer` is the only place in this project where a training label is
created, and a person has to type it.

`review export` writes the answered rows. It does not build a dataset, does not
train anything, and does not promote anything. Those are separate steps you
start yourself.

## What this does not do

* It does not train. Answering an entry changes a file, nothing else.
* It does not block anything, ever. The queue is written after the decision is
  already made and cannot change it.
* It does not send anything anywhere. No cloud, no upload, no telemetry.
* It does not identify a person. A label describes behaviour in one window.

## When it fails

A failure to write the queue is counted (`review_queue_failures_total`) and
dropped. Collecting material for later training is a convenience. It is never
allowed to interrupt defending.

## Metrics

| Metric | Meaning |
| --- | --- |
| `review_queue_offered_total` | windows the engine thought were unclear |
| `review_queue_admitted_total` | windows that got a place in the queue |
| `review_queue_failures_total` | writes that failed and were dropped |
| `review_queue_unavailable_total` | the queue was asked for but could not be opened |

## Related

* [SELF_LEARNING.md](SELF_LEARNING.md) — what the project does and does not learn
* [DATASET.md](DATASET.md) — how a dataset is built from labelled rows
* [MODEL_REGISTRY.md](MODEL_REGISTRY.md) — where a trained model goes afterwards
* [PRIVACY.md](PRIVACY.md) — what is stored and what is not
