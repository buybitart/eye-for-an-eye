# Multi-site models

Which model answers for which site, and why most sites should not have one of
their own.

## Why not a model per site

The obvious multi-site design is one model per website. For most deployments it
is a bad idea.

A small site may see a few hundred requests a day and almost no confirmed
malicious ones. A classifier trained on twenty labelled examples is not a
classifier; it is a memory of twenty examples wearing a confidence score. It
will be confident, it will be wrong, and it will be wrong in a way that looks
like working.

So the order of preference is:

1. one validated **base model**, shared by every site;
2. plus that site's **statistical baseline**, which needs no labels;
3. plus that site's **policy**, which is where operational knowledge belongs;
4. and only then, where a site genuinely has enough trusted labelled data, an
   optional site-specific model.

A site with no model of its own is the normal case, not a deficiency. The CLI
says so, because otherwise it reads as a missing feature.

## Scope

Every model manifest declares one:

```
GLOBAL          the base model, usable by any site
SITE:<site-id>  built for one site, usable only by that site
```

A model with no declared scope is global. Every model written before P12 is
exactly that, so old registries keep working.

## Resolution

```
site has a validated active model of its own?  →  use it
otherwise                                      →  use the base model
otherwise                                      →  the mathematical engine alone
```

The feature schema is checked on every resolution, not just at publication. A
model built against a different feature vector does not fail loudly at
inference — it produces numbers computed from the wrong columns.

The chain always ends somewhere that works. No model at all is not an outage:
the deterministic mathematical engine never depended on a classifier.

## Storage

```
models/
  global/
    versions/
    registry.json
  sites/
    main/
      versions/
      registry.json
    api/
      versions/
      registry.json
```

Each scope has its own pointer file. That is what makes promotion and rollback
naturally site-scoped: rolling site A back is a write to site A's pointer and
cannot touch site B's.

## Wrong-scope models are refused

A model for one site published into another's registry is rejected. So is a
global model published into a site registry, and a site model published into the
global one.

This matters more than most validation because the failure has **no symptom**. A
site-A model loaded for site B accepts the feature vector, returns a score, and
the score is confident and wrong. Nothing downstream can tell.

The resolver checks again at load time, in case the files were changed
underneath the registry.

## Fallback is per site

A site whose model is missing, corrupt, or built for another feature schema
falls back to the base model **and says so**. A site quietly running on the base
model because its own failed looks identical, from the outside, to a site
configured that way — so the difference is recorded and printed.

One site's model failing never affects another site and never stops the sensor.

## Promotion and rollback

Unchanged from P9, and now scoped:

- candidates are shadow-only, for both global and site models;
- promotion requires a passing quality gate;
- promotion names a scope explicitly;
- **`auto_promote` is off**, on every fresh install and after every upgrade.

Rolling back one site leaves every other site and the global model untouched.

### What changed in P14

Through P13, this page said there was no setting that could turn automatic
promotion on. That is no longer true and the sentence has been replaced rather
than softened: `model_governance.auto_promote_enabled` exists, and an operator
can switch it on.

What it does **not** do is make promotion automatic in the sense that phrase
usually carries. A candidate still has to pass every gate; it then enters service
under a reduced action ceiling rather than as the active model, and it earns full
authority only by accumulating real observations. A promotion with no rollback
target is refused outright.

Site scope matters here more than anywhere else on this page:

- `auto_promote_enabled` permits **site-scoped** promotion, and only for sites
  listed by name in `auto_promote_sites`. One site opting in never enables
  another;
- `auto_promote_global_enabled` is a **separate** switch, also off by default,
  because a global model reaches every site on this machine — including ones
  whose operator never opted in;
- a global candidate is judged by its **worst** site, not by an aggregate. An
  average that improves while one small site gets much worse is exactly the
  outcome an average is good at hiding.

See [AUTO_PROMOTION.md](AUTO_PROMOTION.md) and
[MODEL_GOVERNANCE.md](MODEL_GOVERNANCE.md).

## Eligibility for a site-specific model

Before a site gets its own model, it should have: enough trusted labelled
groups, both classes where the model is supervised, hard negatives for that
profile, enough time coverage, a compatible feature schema, and a dataset that
passes the quality gate.

There is no sample count here that could honestly be called sufficient. The
number depends on the site, and anyone quoting one without evidence is guessing.

## Evaluating a global model

Aggregate accuracy hides the thing you need to know. A model can score well
overall and fail badly on one site type — usually the smallest one, which
disappears into the average.

Report precision, recall and false-positive rate **per site**, and highlight the
worst-performing site rather than the mean. Where there are enough sites, train
on some and test on a site the model has not seen: that measures whether it
learned behaviour or learned your deployment.

## Sharing one loaded model

Every site using the base model shares one loaded instance. Loading the same
ONNX file once per site would multiply memory by the number of sites for no
benefit — the file is identical and inference is stateless.

## Commands

```bash
eye-for-an-eye sites models main
```

Shows which model answers for that site, its scope, and — if it fell back — why.
