# Controlled Automatic Promotion

This page is for operators. It uses simple English. The precise rules are in
[MODEL_GOVERNANCE.md](MODEL_GOVERNANCE.md).

## In One Paragraph

Eye for an Eye can test a new local model before it becomes active. A new model
first runs in Shadow Mode, where it sees real traffic but changes nothing. If it
passes the safety checks, the system can activate it in a limited mode. The old
model is kept, so the system can go back to it. If the new model has a serious
technical problem, Eye for an Eye can return to the old model on its own.

**This is off when you install the software. It stays off when you upgrade. You
have to turn it on.**

## What This Is Not

It is not "the AI replaces itself with a better AI". The model has no say in
whether it is promoted. A separate part of the program, which the model cannot
reach or influence, checks a list of rules and says yes or no.

It is not "the best model is always chosen automatically". There is no such
thing as the best model here. There is a model that passed a list of checks, and
a list you can read.

It does not remove the need for a person. It removes the need for a person to be
present at the moment a validated model becomes active. Someone still reviews
samples, still decides the policy, and still owns the result.

## The Steps

```
train  →  validate  →  shadow  →  check the gates  →  limited mode
                                                          ↓
                                                      watch it
                                                          ↓
                                                 full mode, or go back
```

1. **Train.** You run training. Training cannot promote what it made.
2. **Validate.** Offline checks: the file matches its hash, the columns are the
   right columns, the dataset passed its own checks, the split is clean.
3. **Shadow.** The new model scores real traffic beside the current one and
   changes nothing. This runs for as long as you configure; a week by default,
   and it needs enough traffic, not just enough days.
4. **Check the gates.** About thirty named checks. If any important one fails,
   the answer is no, and you can read which one.
5. **Limited mode.** If every gate passes, the new model starts working, but it
   may only raise attention. On its own it cannot challenge, slow down or block
   anybody, whatever its score says.
6. **Watch it.** The system compares the new model with the old one on the same
   traffic and counts how often they disagree.
7. **More authority, slowly.** After enough real observations, not after enough
   time. It is allowed to do more. The last step gives it the same authority
   any model has.
8. **Or go back.** If something serious goes wrong, the system returns to the
   old model by itself and tells you why.

## What Can Stop It

Any of these means no promotion:

- the model file does not match its hash, or is for a different site;
- the columns do not match this version of the software;
- it would block more ordinary visitors than the current model;
- it would stop noticing scanners the current model notices;
- it is much slower, or much larger, or uses much more memory;
- there are not enough reviewed examples to judge it fairly;
- it has not run in Shadow Mode for long enough, or on enough traffic;
- there is no old model to go back to;
- something was promoted recently (there is a waiting period);
- you have frozen promotions.

## Turning It On

Turn it on for one small site first. Not for everything, and not for the shared
model.

```toml
[model_governance]
auto_promote_enabled = true
auto_promote_sites = ["main"]
```

Two things to know.

**One site opting in does not affect another site.** A site that is not in
`auto_promote_sites` does not auto-promote, ever.

**The shared model is a separate decision.** `auto_promote_global_enabled` is a
different setting, also off, because the shared model is used by every site on
this machine, including sites whose owner never asked for this.

Check what you have:

```
eye-for-an-eye model governance status
```

## Turning It Off in a Hurry

```
eye-for-an-eye model governance freeze --reason "investigating"
```

Nothing is promoted and nothing advances while frozen. You can still roll back
by hand. Freezing does not undo a promotion that already happened. Use
`eye-for-an-eye model rollback` for that.

## What It Never Touches

Promotion changes **which model gives an opinion**. It does not change what
opinions are allowed to cause.

It never adds a firewall rule. It never changes your thresholds, your challenge
settings or your rate limits. It never deletes a dataset, a review, or the old
model. A promoted model has exactly the authority your policy already gives a
model, and during the limited mode it has less.

## Honest Limits

- This has never run on a production site. Nobody has done this with real
  traffic on a server that mattered, including the people who wrote it.
- The numbers in the policy are starting points chosen to be careful. They are
  not measured, and they are not science. Read
  [PROMOTION_POLICY.md](PROMOTION_POLICY.md) before you rely on them.
- Shadow Mode cannot show you every case. That is why limited mode exists.
- Automatic rollback handles technical failures well and quality problems
  slowly, because a quality problem needs reviewed evidence and reviewed
  evidence takes time.

## See Also

- [MODEL_GOVERNANCE.md](MODEL_GOVERNANCE.md): the exact rules
- [GUARDED_ACTIVATION.md](GUARDED_ACTIVATION.md): what limited mode means
- [AUTO_ROLLBACK.md](AUTO_ROLLBACK.md): when it goes back on its own
- [MODEL_SAFE_MODE.md](MODEL_SAFE_MODE.md): when it stops trying
- [PROMOTION_POLICY.md](PROMOTION_POLICY.md): every threshold, and who owns it
- [SHADOW_MODE.md](SHADOW_MODE.md): the step before any of this
