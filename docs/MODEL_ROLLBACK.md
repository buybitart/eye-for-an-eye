# Model Rollback

Rollback restores the model that was active before the last promotion.

Status: **Beta.**

## Why This Exists

Every model that is good enough to promote is still a model that can be wrong in
a way nobody predicted. The question is not whether that will happen. It is how
long it takes to undo.

Rollback is one command and one atomic write, so the answer is: seconds, and it
does not depend on a backup existing.

## How It Works

Promotion never deletes anything. The previous active version stays on disk and
is recorded as the rollback target. Rolling back swaps the two pointers.

```bash
eye-for-an-eye model rollback --yes --reason "false blocks on the API gateway"
```

Without `--yes` the command refuses and prints which version it would restore.

Restart the service for the change to take effect.

## What You Can Roll Back To

The **previous active** version, and only that one.

This is deliberate. A rollback is something you do when a deployment is going
wrong and you want the state you know worked. Choosing between several old
versions at that moment is a decision you do not want to be making.

To move to an older version than that, promote it by name instead. That is a
normal promotion and goes through the normal gate.

## When to Roll Back

Roll back first, investigate afterwards. The signals worth acting on:

* blocks on traffic you know is legitimate
* a sharp change in how many sources reach `TEMP_BLOCK`
* `model_health` reporting `DEGRADED` or `UNRELIABLE` shortly after a promotion
* a rise in `ood_high_total` that started when the model changed

None of these prove the new model is wrong. They are all good enough reasons to
go back to the one you understand while you find out.

## What Rollback Does Not Do

* It does not unblock sources that are already blocked. Existing blocks expire on
  their own schedule; use the firewall commands if you need them gone now.
* It does not delete the model you rolled back from. It becomes `ARCHIVED` and
  can be promoted again later if the problem turns out to be elsewhere.
* It does not change any configuration, threshold or policy rule.
* It does not disable the mathematical engine, which was never affected by the
  model change in the first place.

## The Audit Trail

Every rollback is written into the history in `registry.json` with its reason and
the version it replaced. Months later this is what explains why an older model is
running.

## If There Is Nothing to Roll Back To

The command refuses. A registry with one promotion in its history has no previous
active version. This is normal on a first deployment.

## Related

* [MODEL_PROMOTION.md](MODEL_PROMOTION.md): how a version became active
* [MODEL_REGISTRY.md](MODEL_REGISTRY.md): how versions and roles are stored
* [TROUBLESHOOTING.md](TROUBLESHOOTING.md): wider operational problems
* [DRIFT.md](DRIFT.md): model health signals
