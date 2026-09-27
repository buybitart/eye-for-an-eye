"""Deterministic web risk. No model, no training, no opaque score.

P10 works without any new machine learning, and this is the reason. A weighted
sum of bounded behavioural terms is not clever, but it can be read, argued with,
and shown to an operator as a sentence. That matters more than accuracy here,
because the first question anyone asks about a block is "why", and "the model
said so" is not an answer.

Three properties are deliberate:

**Nothing scores on one signal.** Each term is capped, and the strong terms are
capped low enough that no single one reaches the block threshold alone. A source
that only requests quickly is a busy client, not a scanner.

**Diversity is rewarded explicitly.** Independent families of evidence agreeing
is worth more than one family shouting. A separate diversity term makes that
visible instead of hiding it inside the weights.

**Every term explains itself.** `contributions` says what each family added, and
`reasons` turns the top terms into sentences with real numbers in them.
"""
from dataclasses import dataclass, field
import math

#: v2 lets the enumeration and timing terms read the quarter-hour window as
#: well as the minute, so that a source pacing itself below the per-minute
#: thresholds is still described. Weights and bias are unchanged.
WEB_RISK_VERSION = 'web-math-risk-v2'

#: Weights. Provisional: chosen so that no single term can reach the block
#: threshold on its own, and so that the families a scanner triggers together add
#: up to something a person would also call suspicious.
#:
#: The largest single weight is 1.6. With the logistic curve below, one maximal
#: term alone reaches about 0.35 — comfortably below WATCH. Three families at
#: once is where it starts to mean something.
WEIGHTS = {
    'path_enumeration': 1.6,
    'http_errors': 1.5,
    'auth_failure': 1.5,
    'sensitive_probing': 1.2,
    'request_rate': 1.0,
    'automation_timing': 1.0,
    'method_anomaly': 0.8,
    'session_quality': 0.6,
    'persistence': 0.7,
    'host_enumeration': 0.5,
}
BIAS = -4.0

#: Extra credit for independent families agreeing. Capped, so it can sharpen a
#: real case without inventing one.
DIVERSITY_WEIGHT = 0.9
DIVERSITY_FLOOR = 3


@dataclass(frozen=True)
class WebRiskResult:
    """A score, what produced it, and how to say it out loud."""

    score: float
    contributions: dict = field(default_factory=dict)
    reasons: tuple = ()
    families: int = 0
    observations: int = 0
    model_version: str = WEB_RISK_VERSION

    @property
    def usable(self):
        """False when there is too little to say anything. Not the same as zero."""
        return self.observations >= 5

    def explain(self):
        return {'web_risk_version': self.model_version,
                'score': round(self.score, 6),
                'usable': self.usable,
                'observations': self.observations,
                'families_with_evidence': self.families,
                'contributions': {name: round(value, 5)
                                  for name, value in sorted(self.contributions.items(),
                                                            key=lambda pair: -pair[1])
                                  if value > 0},
                'reasons': list(self.reasons),
                'meaning': ('behaviour that resembles automated probing; not proof of an '
                            'attack and not an identity')}


def _clamp(value):
    return min(1.0, max(0.0, float(value)))


def _path_enumeration(values):
    """Many different resources, few of them working, changing quickly.

    Deliberately not "many paths". A crawler visits many paths and they work;
    what separates enumeration is that most of the guesses fail.

    "Fail" is broader than 404 on purpose. A source working through a list of
    methods collects 405s, and one working through admin paths collects 403s.
    All three are the same behaviour — guessing, and being told no — so the term
    keys on "did not succeed" with 404 weighted highest.

    Breadth is read over both windows and the stronger reading wins. Judged on
    the minute alone, a scanner that waits twenty seconds between guesses shows
    three paths and scores nothing, while having worked through forty-five in a
    quarter of an hour. Patience is not innocence, and it should not be the
    cheapest evasion available.
    """
    unique = max(_clamp(values['unique_paths_60s'] / 40),
                 _clamp(values.get('unique_paths_900s', 0.0) / 120))
    fresh = _clamp(values['path_request_ratio'])
    unsuccessful = _clamp(0.6 * values['http_404_ratio']
                          + 0.4 * (1.0 - _clamp(values['http_2xx_ratio'])))
    # Multiplying means all three must be present. A site with a broken asset
    # produces failures without path diversity and scores near zero here.
    return _clamp(unique * (0.35 + 0.65 * fresh) * (0.25 + 0.75 * unsuccessful))


def _http_errors(values):
    """Errors as a share of responses, weighted towards the reconnaissance ones.

    404, 403 and 401 carry the most, because they are what discovery produces.
    The remaining client errors — 405, 400, 429 and the rest — still count for
    something: a source collecting them in bulk is being refused repeatedly, and
    that is worth a little even when it is not a classic probe.
    """
    named = (values['http_404_ratio'] + values['http_403_ratio']
             + values['http_401_ratio'])
    other_4xx = max(0.0, _clamp(values['http_4xx_ratio']) - named)
    # Each code carries how discovery-shaped it is. A source whose every response
    # was 404 reaches 1.0, because that is as much as this family can say.
    return _clamp(1.00 * values['http_404_ratio']
                  + 0.80 * values['http_403_ratio']
                  + 0.70 * values['http_401_ratio']
                  + 0.50 * other_4xx)


def _auth_failure(values):
    """Repeated failed authentication, scaled by how much of the traffic it is."""
    count = _clamp(values['failed_auth_60s'] / 20)
    ratio = _clamp(values['auth_failure_ratio'])
    return _clamp(count * (0.4 + 0.6 * ratio))


def _sensitive_probing(values):
    """Requests to configuration, admin, backup and version-control paths.

    Counted by *category*, not by request: ten requests to one admin URL is a
    person with a bookmark; one request to each of five categories is somebody
    working through a list.
    """
    categories = _clamp(values['sensitive_category_count'] / 4)
    hits = _clamp(values['sensitive_probe_count'] / 10)
    return _clamp(0.65 * categories + 0.35 * hits)


def _request_rate(values):
    """Rate alone. Kept small on purpose: a fast client is not a hostile one."""
    return _clamp(values['request_rate_per_minute'] / 240)


def _window_timing(requests, mean, cv, entropy, floor, ceiling):
    """Regularity in one window, or zero when the sample is too small to say."""
    if requests < floor or mean <= 0:
        return 0.0
    regularity = _clamp(1.0 - _clamp(cv / 1.2))
    predictable = _clamp(1.0 - entropy)
    evidence = _clamp(requests / ceiling)
    return _clamp(evidence * (0.6 * regularity + 0.4 * predictable))


def _automation_timing(values):
    """Regular gaps between requests, read over a minute and over a quarter hour.

    Low variation is the signal. A person browsing produces irregular gaps; a
    loop does not. It needs enough requests to mean anything, so each window
    fades out when its sample is small.

    Two windows because one was a blind spot with a number on it. The minute
    window needs six requests, so anything slower than six a minute scored a
    hard zero here no matter how mechanical it was — and metronomic pacing is
    the clearest thing a slow scanner does. The quarter-hour window asks for
    twenty requests before it says anything, which a person browsing for fifteen
    minutes can certainly produce; what they do not produce is a steady gap, and
    that is what the term actually measures.
    """
    minute = _window_timing(values['requests_60s'], values['interval_mean_60s'],
                            values['interval_cv_60s'], values['interval_entropy_60s'],
                            floor=6, ceiling=20)
    quarter = _window_timing(values.get('requests_900s', 0.0),
                             values.get('interval_mean_900s', 0.0),
                             values.get('interval_cv_900s', 0.0),
                             values.get('interval_entropy_900s', 1.0),
                             floor=20, ceiling=60)
    return max(minute, quarter)


def _method_anomaly(values):
    """Methods the service does not expect, and unusually many distinct methods."""
    unexpected = _clamp(values['unexpected_method_ratio'])
    diversity = _clamp((values['method_diversity'] - 2) / 4)
    unknown = _clamp(values['unknown_method_count'] / 5)
    return _clamp(0.5 * unexpected + 0.25 * diversity + 0.25 * unknown)


def _session_quality(values):
    """Traffic that does not look like a browser using a site.

    No referer, no user agent, no static assets. Each is weak — an API client
    looks exactly like this — which is why the weight is small and why it can
    only ever be a supporting term.
    """
    no_referer = _clamp(values['no_referer_ratio'])
    no_agent = _clamp(values['no_user_agent_ratio'])
    no_assets = _clamp(1.0 - values['static_resource_ratio'])
    changing = _clamp(values['agent_change_rate'] * 4)
    return _clamp(0.3 * no_referer + 0.3 * no_agent + 0.2 * no_assets + 0.2 * changing)


def _persistence(values):
    """How long this has been going on. Slow and patient is still a pattern."""
    return _clamp(values['persistence_900s'] / 600)


def _host_enumeration(values):
    """Many Host values from one source: virtual host discovery."""
    return _clamp((values['host_diversity'] - 1) / 6)


TERMS = {
    'path_enumeration': _path_enumeration,
    'http_errors': _http_errors,
    'auth_failure': _auth_failure,
    'sensitive_probing': _sensitive_probing,
    'request_rate': _request_rate,
    'automation_timing': _automation_timing,
    'method_anomaly': _method_anomaly,
    'session_quality': _session_quality,
    'persistence': _persistence,
    'host_enumeration': _host_enumeration,
}


def _sentence(name, values, term):
    """One term as a sentence with a real number in it."""
    if name == 'path_enumeration':
        return (f'{int(values["unique_paths_60s"])} different paths in 60 seconds, '
                f'{values["http_404_ratio"]:.0%} of responses were not found')
    if name == 'http_errors':
        return (f'{values["http_4xx_ratio"]:.0%} of responses were client errors '
                f'({values["http_404_ratio"]:.0%} not found)')
    if name == 'auth_failure':
        return (f'{int(values["failed_auth_60s"])} failed sign-in attempts in 60 seconds '
                f'({values["auth_failure_ratio"]:.0%} of attempts)')
    if name == 'sensitive_probing':
        return (f'{int(values["sensitive_probe_count"])} requests across '
                f'{int(values["sensitive_category_count"])} sensitive path categories')
    if name == 'request_rate':
        return f'about {values["request_rate_per_minute"]:.0f} requests per minute'
    if name == 'automation_timing':
        return (f'requests arrived on a regular timer (variation '
                f'{values["interval_cv_60s"]:.2f}, mean gap '
                f'{values["interval_mean_60s"]:.1f}s)')
    if name == 'method_anomaly':
        return (f'{values["unexpected_method_ratio"]:.0%} of requests used a method this '
                f'service does not expect')
    if name == 'session_quality':
        return ('requests did not look like a browser using the site '
                f'({values["no_referer_ratio"]:.0%} with no referer, '
                f'{values["static_resource_ratio"]:.0%} static assets)')
    if name == 'persistence':
        return f'activity continued for {values["persistence_900s"] / 60:.0f} minutes'
    if name == 'host_enumeration':
        return f'{int(values["host_diversity"])} different host names from one source'
    return f'{name} contributed {term:.2f}'


class WebMathRisk:
    """Deterministic web risk. Same input, same output, always."""

    def __init__(self, weights=None, *, bias=BIAS, minimum_observations=5):
        self.weights = dict(WEIGHTS)
        if weights:
            unknown = set(weights) - set(WEIGHTS)
            if unknown:
                raise ValueError(f'unknown web risk weights: {sorted(unknown)}')
            self.weights.update(weights)
        self.bias = float(bias)
        self.minimum_observations = max(1, int(minimum_observations))

    def evaluate(self, features):
        """Score one source's behaviour and say why."""
        values = dict(features.values)
        if features.observations < self.minimum_observations:
            return WebRiskResult(
                score=0.0, observations=features.observations,
                reasons=(f'only {features.observations} requests observed; too few to judge',))

        terms, contributions, total = {}, {}, 0.0
        for name, function in TERMS.items():
            term = _clamp(function(values))
            terms[name] = term
            weighted = self.weights[name] * term
            contributions[name] = weighted
            total += weighted

        # Independent families agreeing is itself evidence. Counted from terms
        # that actually contributed, so it cannot be produced by one loud signal.
        active = sum(1 for term in terms.values() if term >= 0.15)
        diversity = max(0, active - DIVERSITY_FLOOR + 1) / 4.0 if active >= DIVERSITY_FLOOR else 0.0
        diversity = _clamp(diversity)
        contributions['evidence_diversity'] = DIVERSITY_WEIGHT * diversity
        total += contributions['evidence_diversity']

        score = 1.0 / (1.0 + math.exp(-(self.bias + total)))
        ranked = sorted(((name, term) for name, term in terms.items() if term >= 0.15),
                        key=lambda pair: -self.weights[pair[0]] * pair[1])
        reasons = [_sentence(name, values, term) for name, term in ranked[:5]]
        if active >= DIVERSITY_FLOOR:
            reasons.append(f'{active} independent kinds of evidence agree')
        return WebRiskResult(score=score, contributions=contributions,
                             reasons=tuple(reasons), families=active,
                             observations=features.observations)
