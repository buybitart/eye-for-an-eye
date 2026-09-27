"""How much new calibration evidence, decided before any of it exists. §11-§14.

### The problem, stated as arithmetic

A block requires a *conservative lower bound* on P(malicious), not a point
estimate. That bound is a Wilson interval over the calibration data's own
examples in the score band the source landed in, so its width is a fact about
how much evidence was collected, not about the traffic being judged.

The P15.4 artifact tops out at **0.981951**. That number is not arbitrary and it
is worth decomposing, because the decomposition is what makes this plan
predeclarable rather than a guess:

    top score band          math risk >= 0.755895
    sources in it           209 malicious, 0 benign
    wilson_lower(209, 209)  0.981951

The `api` cutoff is **0.987654**. So with that artifact no autonomous block was
possible on an API at any score — not because the evidence was weak, but because
209 examples cannot bound a probability that tightly. `wilson_lower(n, n)` first
clears 0.987654 at **n = 308**.

### Why the target is not 308

308 clears only if the band stays perfectly clean. One benign source in a band of
308 drops the bound to 0.981956 — back below the cutoff, from a single example.
The sizes are:

    308 pure                0.987759   clears
    310 with 1 benign       0.981956   fails
    470 with 1 benign       0.988048   clears
    600 with 2 benign       0.987928   clears

A calibrator that clears the cutoff only on a flawless band is one bad example
away from not clearing it, and this matrix deliberately contains the hard
negatives most likely to supply that example. So the plan targets **600 sources
in the top band**, which tolerates two benign contaminants.

That is the whole reasoning, written down before the data exists, so that the
number cannot be chosen afterwards to suit the answer.

### From the target to N

The four P15.4 calibration corpora put 209 sources in the top band, from 228
malicious sources each: **52 per corpus**. `matrix-p15-5-cal-v1.toml` carries 280
malicious sources per corpus, 1.23x more, so the expected yield is about **64**.
The deficit from 209 to 600 is 391, which is 6.1 corpora, and the estimate is
rough in both directions — the band boundaries move as the sample grows, and an
API-enriched mix is not the mix the 52 was measured on.

**N = 8.** Eight covers the estimate with room for it to be wrong by a fifth.

### The stop rule, which is the part that matters

§13 exists because "generate until the number is convenient" is not a
measurement. So: this plan is committed before the corpora are generated,
exactly eight are generated, the calibrator is fitted **once** on the twelve
corpora (the four from P15.4 and these eight), and the result stands.

If the bound still falls short, §14 is explicit and this module's stop rule
repeats it: **do not add more after seeing the result.** The release reports
`API_AUTONOMOUS_TEMP_BLOCK = NOT_SUPPORTED`, the API profile keeps WATCH,
CHALLENGE and RATE_LIMIT, and that is a policy refusing to act on evidence it
cannot bound — which is the behaviour this project is for, not a failure of it.

### One thing "new sources" cannot mean here

§11 says to use new sources rather than more windows from the same ones. The
generators draw from 762 RFC 5737 documentation addresses and a corpus uses 756
of them, so any two corpora necessarily overlap on almost every *address*. What
a new salt changes is the seed of every scenario and every run: a different draw
of behaviours, different timings, different port choices, different principals.
The calibration unit is `(corpus, source_group)` — `training/calibrate.by_source`
keys on both for exactly this reason — so these are independent sources in the
sense that matters, and identical addresses in a sense that does not. Saying so
here is better than letting a reader discover the overlap and wonder.
"""
import hashlib
import json
from pathlib import Path

from eye_for_an_eye.autonomy.cost import CostPolicy
from eye_for_an_eye.decision.calibration import CONSERVATIVE_BINS, WILSON_Z, wilson_lower

CALIBRATION_PLAN_VERSION = 'p15.5-calibration-plan-v1'

ROOT = Path(__file__).resolve().parents[1]

#: The matrix every new calibration corpus is built from.
MATRIX = 'dataset/scenarios/matrix-p15-5-cal-v1.toml'

#: Exactly eight, named. Generating a ninth after seeing the result is the
#: failure §13 describes, and a committed list is what makes it visible.
SALTS = tuple(f'p15.5-calibration-{index}' for index in range(1, 9))

#: What the P15.4 artifact actually had, recovered from its own lower knots.
#: `wilson_lower(209, 209)` reproduces 0.981951 exactly.
BASELINE_TOP_BAND_POSITIVES = 209
BASELINE_TOP_BAND_BENIGN = 0
BASELINE_BOUND = 0.9819508968171637

#: Sources the top band must hold for the bound to clear the API cutoff while
#: tolerating two benign examples in it.
TARGET_TOP_BAND_SOURCES = 600
CONTAMINATION_TOLERANCE = 2

#: Measured, not assumed: 209 top-band sources over four P15.4 corpora.
OBSERVED_YIELD_PER_CORPUS = BASELINE_TOP_BAND_POSITIVES / 4
#: `matrix-p15-5-cal-v1` carries 280 malicious sources where the P15.4 matrix
#: carried 228. The yield is scaled by that ratio and by nothing else.
MALICIOUS_PER_CORPUS = 280
BASELINE_MALICIOUS_PER_CORPUS = 228


def _required_pure(cutoff):
    """Smallest n where a clean band of n clears `cutoff`."""
    n = 1
    while wilson_lower(n, n) < cutoff and n < 100_000:
        n += 1
    return n


def _required_with(contaminants, cutoff):
    n = contaminants + 1
    while wilson_lower(n - contaminants, n) < cutoff and n < 100_000:
        n += 1
    return n


def document():
    policy = CostPolicy()
    cutoffs = {name: round(profile.threshold, 6)
               for name, profile in sorted(policy.profiles.items())}
    api = policy.profiles['api'].threshold
    expected = OBSERVED_YIELD_PER_CORPUS * MALICIOUS_PER_CORPUS / BASELINE_MALICIOUS_PER_CORPUS
    body = {
        'calibration_plan_version': CALIBRATION_PLAN_VERSION,
        'written': 'before any P15.5 calibration corpus was generated or fitted',
        'objective': ('raise the conservative lower bound in the top score band '
                      'above the api cutoff by collecting more independent '
                      'source-level calibration evidence, or report that it '
                      'cannot be raised'),
        'forbidden': ['lowering the api cutoff',
                      'generating more corpora after seeing the fitted bound',
                      'more windows from the same sources instead of new sources',
                      'refitting until a number is convenient'],
        'cost_cutoffs': cutoffs,
        'baseline': {
            'artifact': 'models/mathrisk-cal-v4-isotonic.json',
            'maximum_conservative_bound': BASELINE_BOUND,
            'top_band_begins_at_math_risk': 0.755895,
            'top_band_positives': BASELINE_TOP_BAND_POSITIVES,
            'top_band_benign': BASELINE_TOP_BAND_BENIGN,
            'derivation': ('wilson_lower(209, 209) = 0.981951, which is the '
                           'artifact bound exactly; the band composition is '
                           'recovered from the artifact rather than assumed'),
            'api_reachable': BASELINE_BOUND >= api,
        },
        'requirement': {
            'wilson_z': WILSON_Z,
            'conservative_bins': CONSERVATIVE_BINS,
            'api_cutoff': round(api, 6),
            'sources_needed_if_band_is_clean': _required_pure(api),
            'sources_needed_tolerating_one_benign': _required_with(1, api),
            'sources_needed_tolerating_two_benign': _required_with(2, api),
            'target_top_band_sources': TARGET_TOP_BAND_SOURCES,
            'contamination_tolerance': CONTAMINATION_TOLERANCE,
            'why_not_the_minimum': ('a clean band of 308 clears the cutoff and a '
                                    'single benign example in it returns the bound '
                                    'to 0.981956. Sizing for the minimum makes the '
                                    'release depend on the band being flawless, and '
                                    'this matrix contains the hard negatives most '
                                    'likely to spoil it'),
        },
        'plan': {
            'new_corpora': len(SALTS),
            'matrix': MATRIX,
            'seed_salts': list(SALTS),
            'runs_per_corpus': 756,
            'benign_sources_per_corpus': 476,
            'malicious_sources_per_corpus': MALICIOUS_PER_CORPUS,
            'observed_yield_per_p15_4_corpus': OBSERVED_YIELD_PER_CORPUS,
            'expected_yield_per_new_corpus': round(expected, 1),
            'expected_top_band_total': round(
                BASELINE_TOP_BAND_POSITIVES + len(SALTS) * expected, 1),
            'fitted_with': ['dataset-p15-4-cal-v1', 'dataset-p15-4-cal2-v1',
                            'dataset-p15-4-cal3-v1', 'dataset-p15-4-cal4-v1',
                            *(f'dataset-p15-5-cal{index}-v1'
                              for index in range(1, len(SALTS) + 1))],
            'independence': ('a new salt reseeds every scenario and every run, so '
                             'the behaviours are independently drawn. The 762-address '
                             'documentation pool means two corpora share almost every '
                             'address, which is why the calibration unit is '
                             '(corpus, source_group) rather than the address'),
        },
        'api_families_represented': [
            'benign authenticated API', 'batch API', 'service account',
            'high-rate legitimate API', 'stale credential client',
            'API credential spray', 'patient account walk',
            'credential automation', 'mixed API behaviour'],
        'stop_rule': {
            'fits': 1,
            'after_the_fit': ('if the maximum conservative bound is below the api '
                              'cutoff, report API_AUTONOMOUS_TEMP_BLOCK = '
                              'NOT_SUPPORTED and add no further calibration data '
                              'this cycle'),
            'what_api_keeps': ['WATCH', 'CHALLENGE', 'RATE_LIMIT'],
            'not_a_model_failure': ('a policy that refuses to act on evidence it '
                                    'cannot bound is behaving as designed'),
        },
    }
    body['digest'] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return body


def write(path):
    Path(path).write_text(json.dumps(document(), indent=1) + '\n', encoding='utf-8')
    return path


if __name__ == '__main__':
    print(write(ROOT / 'reports' / 'P15_5_CALIBRATION_PLAN.json'))
