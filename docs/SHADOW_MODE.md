# Shadow Mode

Shadow Mode is the default and the recommended way to run Eye for an Eye.

In Shadow Mode the system decides, writes the decision down, and then does
nothing to the traffic. Nobody is blocked. Nothing is slowed down.

## Why Start Here

You cannot know how a detector behaves on **your** traffic until you watch it on
your traffic. Your monitoring service, your backup job, your mobile app and your
own office network all look a bit like automation.

Shadow Mode lets you find that out safely. If the system would have blocked one
of your own users, you see it in a report instead of in a support ticket.

## What a Decision Looks Like

```text
Risk: 0.91
Decision: TEMP_BLOCK
Enforced: No
Reason: shadow mode
```

The decision record also carries:

* which behaviour numbers contributed, and how much,
* the maths score and the model score separately,
* whether the two engines disagreed,
* which policy rules were triggered,
* the data-quality score.

So you can always answer "why did it say that?".

## The Settings

This is the default state after `eye-for-an-eye setup`:

```toml
[decision]
enabled = true
mode = "shadow"

[enforcement]
enabled = false

[ml]
enabled = true
required = false
model_path = ""
manifest_path = ""
```

Empty model paths mean the maths engine works alone. `doctor` reports the model
as `NOT_CONFIGURED`, which is a normal state, not an error.

To try a model, set the two paths and keep `mode = "shadow"`.

## Replaying a Capture File

You do not need live traffic to test. `simulate` replays a saved capture through
the same code path:

```sh
eye-for-an-eye simulate sample.pcap \
    --config shadow.toml \
    --output new-events.jsonl \
    --report new-shadow.json
```

Rules for this command:

* No live capture, no enrichment, no active probes, no firewall.
* An enforcing configuration is rejected.
* Output files must be new files. It never overwrites.
* The same byte and packet limits apply as for normal offline analysis.

The report holds at most 10 000 source summaries and says so when it overflows.
It contains the highest action per source, action counts, risk deciles,
disagreements and the maths contributions.

Two honest gaps in a replay report:

* Without independent labels, false positives and block precision cannot be
  computed. They are reported as `null`, not as zero.
* Packet loss in a capture file is unknown, so the default quality gates hold
  strong actions back.

## Reading a Shadow Run

Ask three questions.

**1. Who would have been blocked?** Look at the sources with `TEMP_BLOCK`. Do
you recognise any of them? A monitoring probe, a search engine crawler and an
uptime checker are the usual surprises.

**2. Where did the risk come from?** A block driven only by
`credentials_60s` is a different story from one driven by a wide port sweep.

**3. Did the engines disagree?** A high maths score with a low model score is
recorded as `model_disagreement`. Frequent disagreement means the model does not
fit your traffic yet.

## The Recommended Path

```text
Install
  -> Shadow Mode
  -> collect data for days, not minutes
  -> read the decisions
  -> fix your allowlist and management networks
  -> train and validate a model, if you want one
  -> only then think about enforcement
```

Enforcement today is **lab only**. See [Enforcement](ENFORCEMENT.md).

## What Shadow Mode Does Not Do

* It does not retrain anything. See [Controlled self-learning](SELF_LEARNING.md).
* It does not move a threshold on its own.
* It does not replace a model file.
* It does not label its own data. Shadow rows leave the system unlabelled.
* It does not keep a second unbounded "disagreement database". Disagreement is a
  field on the normal, bounded decision record.

## See Also

* [Decision engine](DECISION_ENGINE.md)
* [Model evaluation](MODEL_EVALUATION.md)
* [Shadow validation plan](SHADOW_VALIDATION_PLAN.md): what a shadow deployment
  has to produce before anyone argues for turning blocking on
* [Backpressure](BACKPRESSURE.md): turning the shadow export on, and what it costs
* [Configuration](CONFIGURATION.md)
