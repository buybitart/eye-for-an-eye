# Guarded Activation

What "limited mode" means, precisely.

## Why It Exists

Offline evaluation and Shadow Mode between them cover a great deal. They do not
cover your visitors.

A model that scored well on every corpus available can still be wrong about the
particular people who read your site. The ones on an old phone, behind a
university proxy, using a screen reader, or reading at three in the morning from
a country the training data barely contains. No amount of offline evidence
reaches them, because they are not in it.

Guarded activation makes that case cheap instead of expensive. The new model
starts working immediately, so it is genuinely being tested on real traffic. But
there is a ceiling on what it may cause **by itself**, and the ceiling starts
below the point where anyone is inconvenienced.

## The Stages

| Stage | The model alone may cause at most | Default requirements to leave |
| --- | --- | --- |
| `GUARDED_ACTIVE_STAGE_1` | `WATCH` | 24h **and** 2 000 feature vectors **and** 200 source groups, with no inference failures and under 20% large disagreement |
| `GUARDED_ACTIVE_STAGE_2` | `RATE_LIMIT` | 72h **and** 10 000 feature vectors **and** 1 000 source groups **and** 20 trusted reviewed outcomes, under 10% disagreement |
| `ACTIVE` | whatever your policy allows any model | - |

A model in stage 1 cannot challenge anybody, cannot slow anybody down, and
cannot block anybody, on its own, however confident it is.

## "On Its Own" Is the Important Phrase

The ceiling limits the **model's own contribution**. It does not switch off the
rest of the system.

If the deterministic mathematical engine and the existing evidence already
justify a block, that block still happens, exactly as it would have before the
promotion. The ceiling prevents the newly promoted model from being the reason an
action escalates, not from participating.

This matters because the alternative would be worse. A guarded stage that
suppressed all strong actions would leave your site less protected during exactly
the period when you are least sure about the new model, which is the wrong
trade in both directions.

## Advancement Is on Observations, Never on Time

This is the part most likely to be misread, so it is worth being blunt about.

**Twenty-four hours on a site that saw eleven requests is not evidence.** A model
that advanced on elapsed time alone would gain full authority fastest on the
quietest sites. The ones where a regression is hardest to notice and where the
handful of affected visitors are least likely to be able to tell you.

So every stage requires elapsed time **and** a number of feature vectors **and** a
number of distinct source groups. A million requests from four addresses does not
advance anything either: volume is not a population.

Stage 2 additionally requires reviewed outcomes, because by that point the model
is asking for the authority to slow real people down, and that should cost some
human attention.

Advancing resets the counters. Stage 1's traffic does not also buy stage 2.

## What Stops Advancement

Any of these holds the model where it is and asks for a person:

- an inference failure: a technical fault is not a slow start, and waiting
  longer will not fix it;
- disagreement with the previous model above the stage's limit;
- a surge in strong actions compared to the previous model;
- a drifted population, or a much higher out-of-distribution rate;
- a governance freeze;
- the stage no longer existing in the policy, because somebody changed the
  policy while a model was guarded.

None of those is an accusation against the model. They are reasons the evidence
is not yet the kind you can advance on.

## Restart

Guarded state is on disk and survives a restart. A restart is **not** progress: a
model comes back in the same stage with the same requirements outstanding, and
the accumulated observation time does not include the time the machine was off.

A system clock jump cannot complete a stage either. Stage time is accumulated
observation, not the difference between two wall-clock readings.

## Comparison With the Previous Model

During the guarded period the previous model can be kept loaded in a
**reference** role and scored on the same feature vectors. It controls nothing:
it cannot cause an action, and it is not consulted for a decision. It exists so
that "how differently is the new model behaving" has a real answer rather than an
estimate.

If memory is tight, this is the first thing to drop. The order of priority is:
the current model, the rollback artifact on disk, and only then parallel
comparison inference.

## See Also

- [AUTO_PROMOTION.md](AUTO_PROMOTION.md): the whole flow, in simple English
- [MODEL_GOVERNANCE.md](MODEL_GOVERNANCE.md): the gates that come before this
- [AUTO_ROLLBACK.md](AUTO_ROLLBACK.md): what happens if it goes wrong anyway
- [PROMOTION_POLICY.md](PROMOTION_POLICY.md): changing these numbers
