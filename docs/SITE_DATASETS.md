# Site datasets

How per-site data is stored, and the leakage that having a site identifier
invites.

## Site is metadata, never a feature

A site identifier is the sharpest leakage available to this project.

Hand a model `site_group` and it learns "traffic to the admin site is
malicious". That is a fact about one deployment's shape, not about behaviour. It
scores beautifully on the data it was trained on and is worthless on the first
site it has not seen — and worse, it looks like a good model right up until it
is deployed somewhere new.

So these fields are registered as never-model-input, each with a recorded
reason:

| Field | Why it is excluded |
| --- | --- |
| `site_group` | a model would learn which site rather than what happened |
| `site_id` | site identity, in its configured spelling |
| `domain` | site identity by another name; a domain is not behaviour |
| `host` | client-controlled, and identifies a site rather than behaviour |
| `profile_type` | website, api or admin is a configuration choice |

The reasons are stored alongside the exclusions so they survive a future
contributor asking "why not?".

## One corpus, filtered

A site dataset is a **view**, not a copy:

```
dataset-global-v3          every row
  filtered by site_group   the rows from one site
```

Duplicating rows per site would multiply storage, and would make it possible for
the same window to appear twice in one training set — which is a subtle way to
break a group split.

The manifest records parent datasets, site scope, feature schema, sample groups,
labels and time range.

## Schema compatibility

`site_group` arrived in dataset schema version 2. Version 1 files still load:
the column is optional on read, and its absence means "written before sites
existed" rather than "belongs to no site".

Dropping that compatibility would have stranded every existing corpus, including
the one the shipped model was trained on, for the sake of one metadata column.

## Splitting

The existing group-based split rules apply unchanged, and site adds one more
axis to be careful about.

Do not randomly split adjacent windows from the same site, source or session
across train and test. Rows from one site at one time are correlated, and a
random split lets the model see the answer.

For a global model, the strongest available evaluation is **leave-one-site-out**:
train on sites A, B and C, test on site D. That measures generalisation to a
site the model has never seen, which is the thing you actually want to know and
the thing random row splits cannot tell you.

For a site-specific model, use a chronological and source-group holdout.

## Per-site metrics

Report per site, not only in aggregate:

- precision
- recall
- false-positive rate
- block precision
- hard negatives by profile

A model can score well overall and fail badly on one site type. The smallest
site is the one that disappears into an average, so highlight the
worst-performing site rather than the mean.

## Contributions to a global model

One large site should not dominate a global candidate simply by being large.
Report per-site contributions so the imbalance is visible.

Do not fix imbalance by duplicating a small site's samples. Duplicating rows
does not create information; it creates confidence, which is worse than the
imbalance was.

## Hard negatives by profile

The legitimate traffic most likely to be mistaken for an attack differs by
profile:

| Profile | Hard negatives worth having |
| --- | --- |
| website | crawlers, browser bursts, monitoring |
| api | high-rate legitimate clients, batch jobs |
| admin | human login mistakes |
| webhook | regular machine callbacks |

## Labels

Continue using behavioural classes. Never label a site.

`site-admin = dangerous` is not a label, it is a configuration detail, and a
model that learns it has learned nothing transferable. A site profile is never
attack ground truth.

## Privacy

Full domains are not needed in a dataset. The internal pseudonymous `site_group`
is enough for filtering, splitting and per-site evaluation, and it does not put
your customers' hostnames into a file you might later share.

Identifiers are refused if they contain control characters — the shape of CSV
and log injection in a field the system generates itself.
