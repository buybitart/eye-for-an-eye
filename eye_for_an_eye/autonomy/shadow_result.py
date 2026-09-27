"""The release numbers, computed from frozen evidence and a person's labels.

P15S §35, §36, §52, §53, §54. Committed code rather than a notebook, because a
result nobody can rerun is a result nobody can check.

### What it computes, and on what

The primary metric is §35's: **false would-blocks per 1,000 independent benign
sources**, with its 95% upper bound. Shadow does not block, so `would_action =
TEMP_BLOCK` is evaluated as the counterfactual final action -- what would have
happened to that source if enforcement had been on.

Everything is at the source unit (§18). Every rate excludes unreviewed sources
(§53) and IGNORE'd ones, and both are reported so a reader can see how much of
the period each excluded.

### Three populations, kept apart

* **real_shadow, reviewed benign** -- the false-block denominator, and the only
  thing that can answer "what would it have blocked incorrectly".
* **real_shadow, reviewed malicious-automation** -- naturally observed positives,
  rare, and the only evidence about recall on real traffic.
* **controlled_positive** -- deliberate tests against owned assets. §54: recall
  here is reported separately and never merged with the line above, because a
  scan somebody ran on purpose is not a scan that happened.

### The interval

With *n* reviewed benign sources and *k* false would-blocks, the one-sided 95%
upper bound on the rate comes from the binomial: the largest *p* for which
observing *k* or fewer events in *n* trials still has probability at least 0.05.
For *k* = 0 that reduces to 1 − 0.05^(1/n), the form `docs/SHADOW_VALIDATION_PLAN.md`
derives its 3,000-source target from.

The assumptions are stated with the number, because they are approximations:
sources are treated as independent, a reviewer's label as correct, and the
period as stationary. Each of those makes the true uncertainty wider than the
interval printed, none makes it narrower.
"""
from dataclasses import dataclass
import math

from . import shadow_evidence as ev
from .evaluation import ReleaseThresholds

SHADOW_RESULT_SCHEMA_VERSION = 1

#: §60. Not a pass, not a fail.
INSUFFICIENT_EVIDENCE = 'INSUFFICIENT_EVIDENCE'
PASS = 'PASS'
FAIL = 'FAIL'

#: The sample sizes `docs/SHADOW_VALIDATION_PLAN.md` derives. They are the
#: smallest at which a clean result supports the threshold it is checked
#: against, not the smallest at which a number can be printed.
#:
#: §17, explicitly: `ReleaseThresholds.min_benign_sample` is 500, and 500 is
#: **not** what is used here. Five hundred clean sources are consistent with a
#: true rate of 5.97 per 1000 -- six times the ceiling they would be claimed to
#: establish -- so passing on 500 would be announcing a property the evidence
#: cannot support. The threshold values below are imported, because those are
#: operator policy and have not changed; the sample sizes are derived from them
#: and are larger. A future edit that "aligns" these with `ReleaseThresholds`
#: is the mistake §17 names, and `tests/test_p15s_shadow_result.py` fails it.
MINIMUM_BENIGN_SOURCES = 3000
MINIMUM_BLOCKED_SOURCES = 60


#: Bisection steps. A bisection on [0, 1] reaches the limit of a float in about
#: 52 halvings; 80 is past it with room to spare, and the count matters because
#: each step evaluates a tail whose cost grows with the sample.
_BISECTION_STEPS = 80


def _log_comb(trials, i, *, log_factorial_trials):
    return (log_factorial_trials - math.lgamma(i + 1)
            - math.lgamma(trials - i + 1))


def _tail(p, events, trials, *, log_factorial_trials):
    """P(X <= events) for X ~ Binomial(trials, p), without overflowing.

    The obvious form -- `math.comb(trials, i) * p**i * (1-p)**(trials-i)` -- is
    correct arithmetic and raises `OverflowError` on a real sample: comb(3000,
    1500) is a 900-digit integer, and multiplying it by a float fails before the
    tiny factor beside it can bring it back into range. So each term is built in
    log space and exponentiated once, where it is a probability and cannot
    overflow.

    The sum is taken over whichever tail is shorter and complemented if needed,
    which bounds the work at half the sample rather than all of it.
    """
    if p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 1.0 if events >= trials else 0.0
    log_p, log_q = math.log(p), math.log1p(-p)
    lower = events + 1 <= trials - events
    indices = range(events + 1) if lower else range(events + 1, trials + 1)
    total = 0.0
    for i in indices:
        total += math.exp(_log_comb(trials, i, log_factorial_trials=log_factorial_trials)
                          + i * log_p + (trials - i) * log_q)
    return total if lower else 1.0 - total


def upper_bound(events, trials, *, confidence=0.95):
    """One-sided upper bound on a rate, from the binomial.

    Returns None when there were no trials: a bound over nothing is not a wide
    bound, it is an absent one, and reporting 1.0 there would read as a
    measurement.
    """
    if trials <= 0:
        return None
    if events >= trials:
        return 1.0
    alpha = 1.0 - confidence
    if events == 0:
        return 1.0 - alpha ** (1.0 / trials)

    log_factorial_trials = math.lgamma(trials + 1)
    low, high = events / trials, 1.0
    for _ in range(_BISECTION_STEPS):
        mid = (low + high) / 2
        if _tail(mid, events, trials,
                 log_factorial_trials=log_factorial_trials) > alpha:
            low = mid
        else:
            high = mid
    return (low + high) / 2


def lower_bound_precision(errors, trials, *, confidence=0.95):
    """95% lower bound on precision, from the same arithmetic in reverse."""
    bound = upper_bound(errors, trials, confidence=confidence)
    return None if bound is None else 1.0 - bound


@dataclass(frozen=True, slots=True)
class Population:
    """One labelled group of sources, counted."""

    name: str
    sources: int = 0
    would_blocked: int = 0
    windows: int = 0

    def explain(self):
        return {'population': self.name, 'sources': self.sources,
                'would_block_sources': self.would_blocked, 'windows': self.windows}


def _population(name, chosen):
    return Population(name=name, sources=len(chosen),
                      would_blocked=sum(1 for s in chosen if s.would_blocked),
                      windows=sum(s.windows for s in chosen))


def evaluate(by_source, labels, *, profile=None):
    """The numbers, for one profile or for everything.

    `labels` maps `source_pseudonym` to one of `shadow_evidence.LABELS`. A source
    absent from it is UNLABELED and enters no rate.
    """
    selected = [s for s in by_source.values()
                if profile is None or profile in s.profiles]
    state = {s.pseudonym: labels.get(s.pseudonym, ev.UNLABELED) for s in selected}

    real = [s for s in selected if s.collection == ev.REAL_SHADOW]
    controlled = [s for s in selected if s.collection == ev.CONTROLLED_POSITIVE]

    benign = [s for s in real if state[s.pseudonym] == ev.BENIGN]
    positives = [s for s in real if state[s.pseudonym] == ev.MALICIOUS_AUTOMATION]
    unreviewed = [s for s in selected if state[s.pseudonym] == ev.UNLABELED]
    ignored = [s for s in selected if state[s.pseudonym] == ev.IGNORE]

    false_blocks = sum(1 for s in benign if s.would_blocked)
    rate = (1000.0 * false_blocks / len(benign)) if benign else None
    bound = upper_bound(false_blocks, len(benign))

    # Precision is over *reviewed* would-blocked sources only. A would-block
    # nobody reviewed is neither correct nor incorrect, and putting it in either
    # column would be the self-labelling §14 forbids.
    reviewed_blocked = [s for s in real if s.would_blocked
                        and state[s.pseudonym] in (ev.BENIGN, ev.MALICIOUS_AUTOMATION)]
    wrong = sum(1 for s in reviewed_blocked if state[s.pseudonym] == ev.BENIGN)
    precision = ((len(reviewed_blocked) - wrong) / len(reviewed_blocked)
                 if reviewed_blocked else None)

    return {
        'profile': profile or '(all)',
        'populations': [
            _population('real_shadow', real).explain(),
            _population('real_shadow_reviewed_benign', benign).explain(),
            _population('real_shadow_reviewed_malicious_automation', positives).explain(),
            _population('controlled_positive', controlled).explain(),
            _population('unreviewed', unreviewed).explain(),
            _population('ignored', ignored).explain(),
        ],
        'false_would_blocks': {
            'benign_sources': len(benign),
            'false_would_block_sources': false_blocks,
            'per_1000_benign': None if rate is None else round(rate, 4),
            'upper_bound_95_per_1000': None if bound is None else round(bound * 1000, 4),
        },
        'block_precision': {
            'reviewed_would_block_sources': len(reviewed_blocked),
            'incorrect': wrong,
            'precision': None if precision is None else round(precision, 6),
            'lower_bound_95': (None if not reviewed_blocked else
                               round(lower_bound_precision(wrong, len(reviewed_blocked)), 6)),
        },
        # §54. Kept apart from the line above on purpose.
        'controlled_positive_recall': {
            'sources': len(controlled),
            'would_blocked': sum(1 for s in controlled if s.would_blocked),
            'recall': (round(sum(1 for s in controlled if s.would_blocked) / len(controlled), 6)
                       if controlled else None),
            'note': ('a scan somebody ran on purpose is not a scan that '
                     'happened; this is never merged with naturally observed '
                     'positives'),
        },
        'natural_positive_recall': {
            'sources': len(positives),
            'would_blocked': sum(1 for s in positives if s.would_blocked),
            'recall': (round(sum(1 for s in positives if s.would_blocked) / len(positives), 6)
                       if positives else None),
        },
        # The plan fails a window in which decisions taken while a component was
        # DEGRADED or UNAVAILABLE were left in the population. Counted here so
        # the condition is visible in the numbers rather than only in the rows.
        'degraded_sources': sum(1 for s in selected if s.degraded),
    }


def sufficiency(result):
    """§60. Is there enough evidence to decide anything?

    Answered before any threshold is compared, because "not enough data" is not
    a pass with a caveat and is not a failure of the detector.
    """
    benign = result['false_would_blocks']['benign_sources']
    blocked = result['block_precision']['reviewed_would_block_sources']
    reasons = []
    if benign < MINIMUM_BENIGN_SOURCES:
        reasons.append(
            f'{benign} reviewed benign sources; {MINIMUM_BENIGN_SOURCES} are needed '
            f'for a clean result to support 1.0 false blocks per 1000 '
            f'(500 would be consistent with 5.97 per 1000)')
    if blocked < MINIMUM_BLOCKED_SOURCES:
        reasons.append(
            f'{blocked} reviewed would-blocked sources; {MINIMUM_BLOCKED_SOURCES} '
            f'are needed for a clean result to support a block precision of 0.95')
    return {'sufficient': not reasons, 'reasons': reasons,
            # Kept apart because they do not mean the same thing to a verdict.
            # Too few benign sources is no result at all; too few blocked
            # sources is no *precision* claim, and a system that blocked
            # nothing at all has told us something rather than nothing.
            'benign_sufficient': benign >= MINIMUM_BENIGN_SOURCES,
            'blocked_sufficient': blocked >= MINIMUM_BLOCKED_SOURCES,
            'targets': {'benign_sources': MINIMUM_BENIGN_SOURCES,
                        'reviewed_would_block_sources': MINIMUM_BLOCKED_SOURCES}}


def degeneracy(result):
    """The two systems that measure well and defend nothing.

    `autonomy/evaluation.py`'s `non_degenerate_gate` states the rule and this
    applies it to the shadow population: at least one *correct* would-block, and
    a benign population that is not being would-blocked wholesale. Allow-all
    scores a perfect false-block rate and has protected nobody; block-all scores
    perfect recall and has denied everybody.

    With no reviewed malicious source in the real population there was nothing
    to detect, and an absence of correct blocks is then a gap in ground truth
    rather than a degenerate system. `non_degenerate_gate` makes the same
    exemption, and it matters: without it every quiet window would be reported
    as a defender that defends nothing.

    Assessed on the real population. A controlled scan the system would have
    stopped says the build is not allow-all, and says nothing about traffic that
    arrived on its own -- §54 keeps those apart, and rescuing this gate with a
    test somebody ran themselves is exactly the merge it forbids.
    """
    blocked = result['block_precision']['reviewed_would_block_sources']
    wrong = result['block_precision']['incorrect']
    benign = result['false_would_blocks']['benign_sources']
    false_blocks = result['false_would_blocks']['false_would_block_sources']
    available = result['natural_positive_recall']['sources']
    reasons = []
    if available and blocked - wrong < 1:
        reasons.append('no reviewed would-block was correct: on this evidence the '
                       'system would have stopped nothing it should have stopped')
    if benign and false_blocks == benign:
        reasons.append('every reviewed benign source would have been blocked')
    return {'degenerate': bool(reasons), 'reasons': reasons,
            'correct_would_blocks': blocked - wrong,
            'reviewed_positives_available': available,
            'note': ('with no reviewed malicious source there was nothing to '
                     'detect, so an absence of correct blocks is a gap in ground '
                     'truth rather than a degenerate system; controlled '
                     'positives are not counted here')}


def verdict(result, *, skipped=None):
    """§60. PASS, FAIL or INSUFFICIENT_EVIDENCE, in that order of suspicion.

    Sample size is settled first, and not as a formality. With 100 clean benign
    sources the 95% upper bound is 29 per 1000 and exceeds the 1.0 ceiling on
    arithmetic alone -- so comparing the bound before checking the sample size
    would report FAIL for a flawless result on a short window, which is not a
    finding about the detector. Everything that is not a statement about sample
    size is still computed and listed in `failing_checks`, so an insufficient
    window that is *also* plainly bad does not read as merely quiet.

    The two shortfalls are not interchangeable, and the order below is the whole
    reason they are reported apart. Too few benign sources is no result. Too few
    *blocked* sources usually is too -- but the allow-everything system produces
    exactly zero of them, and answering it with "not enough data" would let the
    one system that is trivially constructible and never useful sit forever in
    the one verdict that asks for nothing. So degeneracy is decided in between:
    once the benign population is large enough to be worth something, blocking
    nothing is a finding.

    A PASS here is a statement about one deployment, one window and one
    configuration. §62: it is not authorisation to enable autonomous blocking,
    and this function deliberately returns no such thing.
    """
    policy = ReleaseThresholds()
    bound = result['false_would_blocks']['upper_bound_95_per_1000']
    precision_floor = result['block_precision']['lower_bound_95']
    enough = sufficiency(result)
    shape = degeneracy(result)
    skipped = dict(skipped or {})

    failing = []
    if bound is not None and bound > policy.max_false_blocks_per_1000_benign:
        failing.append(f'95% upper bound on false would-blocks is {bound} per 1000 '
                       f'benign sources; the ceiling is '
                       f'{policy.max_false_blocks_per_1000_benign}')
    if precision_floor is not None and precision_floor < policy.min_block_precision:
        failing.append(f'95% lower bound on would-block precision is {precision_floor}; '
                       f'the floor is {policy.min_block_precision}')
    failing.extend(shape['reasons'])
    if result['degraded_sources']:
        failing.append(
            f"{result['degraded_sources']} sources have decisions taken while a "
            f'component was DEGRADED or UNAVAILABLE and were not excluded')
    dropped = sum(int(v) for v in skipped.values() if isinstance(v, (int, float)))
    if dropped:
        failing.append(f'{dropped} rows could not be read, so the window is '
                       f'incomplete by an amount nobody can quantify')

    if not enough['benign_sufficient']:
        answer = INSUFFICIENT_EVIDENCE
    elif shape['degenerate']:
        answer = FAIL
    elif not enough['blocked_sufficient']:
        answer = INSUFFICIENT_EVIDENCE
    elif failing:
        answer = FAIL
    else:
        answer = PASS
    return {'verdict': answer, 'sufficiency': enough,
            'failing_checks': failing, 'degeneracy': shape,
            'thresholds': policy.explain(),
            'note': ('a PASS is consistent with the ceiling on this deployment, '
                     'during this window, under this configuration. It is not a '
                     'statement about another site or about traffic that did not '
                     'arrive, and it does not authorise enabling autonomous '
                     'blocking')}


def from_manifest(document, labels, *, root=None, profiles=None):
    """§47, §52. Verify the frozen files first, then compute from them.

    The verification is here and not in the caller on purpose. A result computed
    from files that changed since the freeze is not a result, and a check that
    lives in whichever script somebody ran is a check that is missing from the
    run nobody kept. So this reads the manifest, hashes what it names, and only
    then counts -- and a mismatch fails the window rather than appearing as a
    footnote beside a PASS.

    `root` re-bases the manifest's paths, because evidence is usually analysed
    somewhere other than the machine that wrote it.

    A window whose evidence is known to be incomplete fails rather than
    reporting INSUFFICIENT_EVIDENCE, even when it is also short. The two are
    different offers: a short window is answered by collecting more, and a
    window that lost part of itself cannot be, because the part that is gone is
    gone. Reporting it as "not enough data yet" would invite exactly the wrong
    remedy.
    """
    checked = ev.verify(document, root=root)
    exports = [entry for entry in document.get('files', [])
               if entry.get('role') == 'shadow_export']
    paths = [ev.rebase(entry['path'], root) for entry in exports]
    retention = document.get('retention') or {}
    broken = [reason for reason in (
        (f"the frozen evidence does not verify: {checked['status']}"
         if checked['status'] != 'MATCH' else ''),
        *(retention.get('reasons') or ()),
    ) if reason]

    if any(entry['status'] == 'MISSING' for entry in checked['files']):
        # No numbers at all. Computing a rate from the files that happen to
        # still be there would answer a question about a different period.
        return {'shadow_result_schema_version': SHADOW_RESULT_SCHEMA_VERSION,
                'evidence': checked, 'retention': retention,
                'verdict': {'verdict': FAIL, 'failing_checks': broken,
                            'note': 'evidence named by the manifest is missing; '
                                    'no rate was computed'}}

    result = report(paths, labels, profiles=profiles)
    result['evidence'] = checked
    result['retention'] = retention
    if broken:
        result['verdict'] = {**result['verdict'], 'verdict': FAIL,
                             'failing_checks': broken + result['verdict']['failing_checks']}
    return result


def report(paths, labels, *, profiles=None):
    """§36, §52. Everything, overall and per profile, from frozen files."""
    rows, skipped = ev.read_rows(paths)
    by_source = ev.sources(rows)
    labels = dict(labels or {})
    present = sorted({profile for source in by_source.values()
                      for profile in source.profiles})
    overall = evaluate(by_source, labels)
    return {
        'shadow_result_schema_version': SHADOW_RESULT_SCHEMA_VERSION,
        'rows_read': len(rows),
        'skipped': skipped,
        'summary': ev.summarise(paths, labels=labels),
        'overall': overall,
        'sufficiency': sufficiency(overall),
        'verdict': verdict(overall, skipped=skipped),
        # §36. A safe website result and a dangerous API result are not averaged.
        'per_profile': [evaluate(by_source, labels, profile=profile)
                        for profile in (profiles if profiles is not None else present)],
        'assumptions': [
            'sources are treated as independent; addresses behind one NAT or one '
            'cloud provider are not, which makes the true interval wider',
            "a reviewer's label is treated as correct; reviewers are wrong "
            'sometimes, and more often on the hard cases that matter most',
            'the period is treated as stationary; real traffic is not',
            'a source seen under two cost profiles is counted under both, so the '
            'per-profile rows do not sum to the overall row',
            'each of these widens the true uncertainty beyond the interval '
            'printed here, and none narrows it',
        ],
    }
