"""P9 candidate shadow inference: run a new model beside the active one.

A candidate model scores the same behaviour the active model scores, at the same
moment, on the same feature vector. It cannot change an action, cannot reach the
firewall, and cannot be reached by the enforcement path at all: nothing in this
module returns anything the policy consults.

That distinction matters and is easy to get wrong. A canary in most systems means
"send some real traffic to the new thing". Here it means **parallel inference,
never parallel enforcement**. No fraction of decisions is ever routed to a
candidate, because a candidate has no deployment authority to route anything to.

What this produces is a comparison: where the two models agree, where they
disagree, and — the expensive case — where the candidate would block a source the
active model allows. Those are handed to a person, not acted on.
"""
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path

COMPARISON_SCHEMA_VERSION = 1

#: A score gap this size or larger is worth a person's attention.
LARGE_GAP = 0.30

#: How many disagreeing windows the ledger keeps for review. Bounded so a busy
#: sensor cannot turn the comparison into a memory leak.
MAX_EXAMPLES = 200


class CandidateError(Exception):
    """The candidate could not be prepared or scored. The active model is unaffected."""


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def _stamp(moment=None):
    return (moment or _now()).isoformat().replace('+00:00', 'Z')


@dataclass
class Comparison:
    """One window scored by both models."""

    active_score: float | None
    candidate_score: float | None
    active_action: str
    candidate_action: str
    gap: float = 0.0
    kind: str = 'agree'

    def explain(self):
        return {'active_score': self.active_score, 'candidate_score': self.candidate_score,
                'active_action': self.active_action, 'candidate_action': self.candidate_action,
                'gap': round(self.gap, 6), 'kind': self.kind}


def classify(active_score, candidate_score, active_action, candidate_action):
    """Name the relationship between two opinions.

    The names are chosen so a report reads as a statement about models rather
    than about traffic. `candidate_blocks_active_allows` is the one that matters:
    it is the only kind that means a promotion could start blocking somebody who
    is not blocked today.
    """
    gap = 0.0
    if active_score is not None and candidate_score is not None:
        gap = abs(float(active_score) - float(candidate_score))

    acting = ('RATE_LIMIT', 'TEMP_BLOCK')
    candidate_blocks = candidate_action == 'TEMP_BLOCK'
    active_blocks = active_action == 'TEMP_BLOCK'
    candidate_acts = candidate_action in acting
    active_acts = active_action in acting
    if candidate_blocks and not active_blocks:
        kind = 'candidate_blocks_active_allows'
    elif active_blocks and not candidate_blocks:
        kind = 'active_blocks_candidate_allows'
    elif candidate_acts and not active_acts:
        kind = 'candidate_acts_active_does_not'
    elif active_acts and not candidate_acts:
        kind = 'active_acts_candidate_does_not'
    elif active_action != candidate_action:
        kind = 'action_differs'
    elif gap >= LARGE_GAP:
        kind = 'large_score_gap'
    else:
        kind = 'agree'
    return Comparison(active_score=active_score, candidate_score=candidate_score,
                      active_action=active_action, candidate_action=candidate_action,
                      gap=gap, kind=kind)


@dataclass
class ComparisonLedger:
    """Bounded running tally of how the two models differ.

    Counts only. No address, no payload. The stored examples carry the two scores
    and the two actions, which is what a person needs to decide whether a
    disagreement matters.
    """

    active_version: str = ''
    candidate_version: str = ''
    started_at: str = field(default_factory=_stamp)
    feature_vectors: int = 0
    scored_by_both: int = 0
    kinds: Counter = field(default_factory=Counter)
    active_actions: Counter = field(default_factory=Counter)
    candidate_actions: Counter = field(default_factory=Counter)
    gap_sum: float = 0.0
    candidate_failures: int = 0
    sources: set = field(default_factory=set)
    examples: list = field(default_factory=list)
    max_examples: int = MAX_EXAMPLES
    max_sources: int = 10_000

    def observe(self, comparison, *, source_key=''):
        self.feature_vectors += 1
        self.kinds[comparison.kind] += 1
        self.active_actions[comparison.active_action] += 1
        self.candidate_actions[comparison.candidate_action] += 1
        if comparison.active_score is not None and comparison.candidate_score is not None:
            self.scored_by_both += 1
            self.gap_sum += comparison.gap
        if source_key and len(self.sources) < self.max_sources:
            self.sources.add(source_key)
        # Only the disagreements are worth keeping, and the expensive kind first.
        if comparison.kind == 'agree':
            return
        if len(self.examples) < self.max_examples:
            self.examples.append(comparison)
        elif comparison.kind == 'candidate_blocks_active_allows':
            for index, existing in enumerate(self.examples):
                if existing.kind != 'candidate_blocks_active_allows':
                    self.examples[index] = comparison
                    break

    def record_failure(self):
        self.candidate_failures += 1

    @property
    def agreement(self):
        if not self.feature_vectors:
            return None
        return self.kinds['agree'] / self.feature_vectors

    @property
    def mean_gap(self):
        return (self.gap_sum / self.scored_by_both) if self.scored_by_both else None

    @property
    def new_blocks(self):
        """Sources the candidate would block that the active model does not."""
        return self.kinds['candidate_blocks_active_allows']

    def explain(self):
        return {'comparison_schema_version': COMPARISON_SCHEMA_VERSION,
                'active': self.active_version or 'none',
                'candidate': self.candidate_version or 'none',
                'started_at': self.started_at,
                'feature_vectors': self.feature_vectors,
                'scored_by_both': self.scored_by_both,
                'distinct_sources': len(self.sources),
                'agreement': None if self.agreement is None else round(self.agreement, 4),
                'mean_score_gap': None if self.mean_gap is None else round(self.mean_gap, 6),
                'kinds': dict(self.kinds),
                'active_actions': dict(self.active_actions),
                'candidate_actions': dict(self.candidate_actions),
                'candidate_would_block': self.candidate_actions.get('TEMP_BLOCK', 0),
                'active_would_block': self.active_actions.get('TEMP_BLOCK', 0),
                'candidate_blocks_active_allows': self.new_blocks,
                'candidate_failures': self.candidate_failures,
                'examples': [item.explain() for item in self.examples[:50]],
                'authority': ('shadow only; a candidate never changed an action and never '
                              'reached the firewall')}


class CandidateModel:
    """A candidate scored beside the active model, with its own failure budget.

    If the candidate fails repeatedly it is switched off and only the candidate
    is switched off. The active model, the mathematical engine and the policy are
    all untouched, because none of them ever read anything from here.
    """

    def __init__(self, *, enabled=False, model_path='', manifest_path='',
                 distribution_path='', version='', max_failures=5, sample_every=1):
        self.enabled = bool(enabled) and bool(model_path)
        self.model_path = model_path
        self.manifest_path = manifest_path
        #: A candidate is measured against the distribution of *its own* training
        #: data. Judging it by the active model's baseline would describe the
        #: wrong model.
        self.distribution_path = distribution_path
        self.version = version
        self.max_failures = max(1, int(max_failures))
        self.sample_every = max(1, int(sample_every))
        self.failures = 0
        self.seen = 0
        self.disabled_reason = ''
        self.model = None

    @property
    def loaded(self):
        return self.model is not None and not self.disabled_reason

    def load(self, config_factory):
        """Load the candidate. A failure disables the candidate and nothing else."""
        if not self.enabled:
            return False
        try:
            from .onnx_model import IsolatedModel
            self.model = IsolatedModel(config_factory(self.model_path, self.manifest_path))
            self.model.start()
            return True
        except Exception as exc:
            self.model = None
            self.disable(f'the candidate model could not be loaded: {type(exc).__name__}')
            return False

    def disable(self, reason):
        """Turn the candidate off. Never turns anything else off."""
        self.disabled_reason = str(reason)[:200]
        self.enabled = False

    def should_score(self):
        """Sampling, so a candidate cannot cost the sensor its traffic budget.

        Under load an operator can raise `sample_every` and the candidate simply
        sees fewer windows. Reducing candidate inference is always the right
        trade against dropping traffic.
        """
        if not self.loaded:
            return False
        self.seen += 1
        return self.seen % self.sample_every == 0

    def score(self, tensor):
        """Score one window, or return None. Never raises into the decision path."""
        if not self.loaded:
            return None
        try:
            result = self.model.predict(tensor)
        except Exception:
            self.failures += 1
            if self.failures >= self.max_failures:
                self.disable(f'the candidate failed {self.failures} times and was switched off')
            return None
        if getattr(result, 'status', '') != 'healthy':
            self.failures += 1
            if self.failures >= self.max_failures:
                self.disable(f'the candidate failed {self.failures} times and was switched off')
            return None
        return result

    def close(self):
        try:
            if self.model is not None:
                self.model.close()
        except Exception:
            pass
        finally:
            self.model = None


def write_report(ledger, path, *, duration_hours=None, recommendation='', reasons=()):
    """The §115 shadow report, as a file a person can read and keep."""
    document = dict(ledger.explain())
    document['duration_hours'] = duration_hours
    document['recommendation'] = recommendation or 'NEED_MORE_DATA'
    document['reasons'] = list(reasons)
    document['written_at'] = _stamp()
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return {'file': str(target), 'recommendation': document['recommendation']}


def render(ledger, *, duration_hours=None, recommendation='', reasons=()):
    """The same report as plain text, in the layout the P9 brief asks for."""
    data = ledger.explain()
    agreement = 'not enough data' if data['agreement'] is None else f'{data["agreement"]:.1%}'
    duration = 'unknown' if duration_hours is None else f'{duration_hours:.1f} hours'
    lines = ['CANDIDATE SHADOW REPORT', '',
             f'Active:\n{data["active"]}', '',
             f'Candidate:\n{data["candidate"]}', '',
             f'Duration:\n{duration}', '',
             f'FeatureVectors:\n{data["feature_vectors"]}', '',
             f'Agreement:\n{agreement}', '',
             f'Large disagreement:\n{data["kinds"].get("large_score_gap", 0)}', '',
             f'Candidate would-block:\n{data["candidate_would_block"]}', '',
             f'Active would-block:\n{data["active_would_block"]}', '',
             f'Candidate blocks that the active model allows:\n{data["candidate_blocks_active_allows"]}', '',
             f'Candidate failures:\n{data["candidate_failures"]}', '',
             f'Recommendation:\n{recommendation or "NEED_MORE_DATA"}']
    if reasons:
        lines += ['', 'Reasons:'] + ['  ' + reason for reason in reasons]
    lines += ['', 'Authority:', 'Shadow only. The candidate never changed an action.']
    return '\n'.join(lines)
