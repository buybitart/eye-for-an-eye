# Automatic Rollback

When a promoted model is withdrawn without being asked, and when it is not.

## Three Tiers, and They Are Not Interchangeable

| Tier | Example | Speed | Evidence needed |
| --- | --- | --- | --- |
| **Technical** | NaN output, inference failures, model stops loading | fast | the failure itself |
| **Resource** | sustained latency or memory increase, dropped events | fast, after a sustained period | measurements against the previous model |
| **Quality** | more false blocks on reviewed outcomes | slow | reviewed, trusted outcomes, and enough of them |

The asymmetry is deliberate.

**Technical failures withdraw the model quickly** because nothing about them gets
clearer with more observation. A model producing non-finite output is broken, and
every minute it stays is a minute your site is defended by something that does
not work.

**Quality regressions withdraw it slowly** because the evidence is human review
and review takes time. A system that withdrew a model on one ambiguous unlabelled
request would change its model with the weather, and would be wrong far more
often than it was right.

## Technical Rollback

Any of these withdraws the model:

- non-finite outputs (NaN, infinity);
- the model failing to load after activation;
- model health reported as `UNRELIABLE`;
- 20 consecutive inference failures;
- an inference failure rate above 2% sustained over 15 minutes.

The last one has a window on purpose. A model is not withdrawn for a bad first
minute.

## Resource Rollback

Website availability outranks model experimentation. If the new model makes the
site slow, the site is worse off than it would be with no model at all.

- p95 inference latency more than 2× the previous model's, sustained for 10
  minutes;
- resident memory more than 2× the previous model's, sustained;
- any dropped sensor events: the clearest possible signal that the model is
  costing more than it is worth.

The sustained-period requirement means a garbage collection pause does not
withdraw a perfectly good model.

## Quality Rollback

Needs at least 20 reviewed outcomes before it can act at all. Then:

- more than 3 additional reviewed false blocks compared with the previous model;
- block precision fallen by more than 0.10 on reviewed outcomes.

Below the minimum, the monitor reports that it does not have enough reviewed
evidence. It does not guess, and it does not use unlabelled traffic as a
substitute.

## What Does **Not** Trigger a Rollback

**A high out-of-distribution rate.** It says the model recognises less of what it
is currently seeing. The model it would be rolled back to is older and has seen
even less. Rolling back on this alone would reliably swap a model that knows it
is uncertain for one that does not.

**A drifted population.** The traffic moved. That is a fact about the traffic,
not a fault in the model, and the previous model is not less drifted.

**A surge in strong actions.** It may be a regression. It may also be a real
attack wave, which is the system working. The difference is not something to
guess at, so a surge freezes advancement and asks for a person.

All three pause the staircase and get reported. None of them withdraws anything.

## What Rollback Does Not Touch

Rollback changes which model answers. It does not:

- change or remove any firewall rule;
- change any threshold, challenge setting or rate limit;
- delete a dataset, a review label, a training job or an evaluation record;
- delete the withdrawn model, which stays on disk.

The report says so explicitly, because those are the two things an operator most
needs to know at the moment they read it.

## After a Rollback

The withdrawn version is **quarantined**. It does not get to try again on the
next assessment cycle, and releasing it requires an explicit operator action.

That edge exists to prevent an obvious oscillation: promote, regress, roll back,
re-assess, promote the same artifact again, forever. A withdrawn candidate needs
a new evaluation or a new version.

## If Rollback Itself Fails

The system enters [model safe mode](MODEL_SAFE_MODE.md): all promotion stops,
candidate authority stops, and a critical health state is raised. The
mathematical engine and PolicyGuard are unaffected, because neither ever depended
on any of this.

## See Also

- [AUTO_PROMOTION.md](AUTO_PROMOTION.md)
- [GUARDED_ACTIVATION.md](GUARDED_ACTIVATION.md)
- [MODEL_SAFE_MODE.md](MODEL_SAFE_MODE.md)
- [MODEL_ROLLBACK.md](MODEL_ROLLBACK.md): rolling back by hand, always available
