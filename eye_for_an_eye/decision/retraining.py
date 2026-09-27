"""P9 retraining advice. It advises. It never trains.

No code path here starts a training job. This module reads a few numbers,
decides whether a person might want to consider retraining, and says why in
words a person can argue with.

An earlier version of this docstring said "there is no `auto_train` setting in
this project". That was wrong, and the correction matters more than the sentence
did. `LearningConfig.auto_train` and `LearningConfig.auto_prepare_dataset` both
exist, both default to `False` -- and **neither is read by any code that could
act on it**. `learning status` reports `auto_train`; nothing else in the codebase
consults either one. They are reserved names, not switches, and `config.py` and
`docs/RETRAINING.md` now say so in those words.

The distinction is worth the paragraph. A setting that does nothing is safe in
one direction and misleading in the other: nobody can turn automatic training on
by accident, but somebody who sets `auto_train = true` and believes the system is
now retraining itself would be wrong, and would find out late. Denying the
setting exists is how that stays hidden.

The reason it stops there is worth stating plainly. Retraining changes what the
system will block. If the system could decide on its own when to retrain, and
promotion were ever automated alongside it, then the loop from "traffic arrives"
to "who gets blocked changes" would close with no person in it. Every part of
P8 and P9 exists to keep that loop open.

What it will *not* do is equally deliberate:

* Drift is never read as a source being hostile. A drifted population means the
  model knows less than it used to, which is a fact about the model.
* A high out-of-distribution rate is not evidence of attack. It is evidence of
  unfamiliar traffic, and unfamiliar is not malicious.
* Nothing here counts blocks. How much the system acted says nothing about
  whether its model is right, and using it would close the loop through the back
  door.
"""
from dataclasses import dataclass, field

RETRAINING_ADVICE_VERSION = 1

NO_ACTION = 'NO_ACTION'
COLLECT_MORE = 'COLLECT_MORE'
CONSIDER_RETRAINING = 'CONSIDER_RETRAINING'
WAIT_COOLDOWN = 'WAIT_COOLDOWN'
SYSTEM_BUSY = 'SYSTEM_BUSY'

RECOMMENDATIONS = (NO_ACTION, COLLECT_MORE, CONSIDER_RETRAINING, WAIT_COOLDOWN, SYSTEM_BUSY)


class RetrainingError(ValueError):
    """A policy or signal set that does not make sense."""


@dataclass(frozen=True)
class RetrainingPolicy:
    """When it is worth a person's time to think about retraining.

    Every value is a floor, not a trigger. Reaching all of them produces the words
    "you could consider retraining", and nothing else happens.
    """

    #: Reviewed labels needed since the last training run.
    min_new_labels: int = 200
    #: Reviewed labels of each supervised kind.
    min_new_per_label: int = 50
    #: Distinct sources those labels must come from.
    min_new_sources: int = 20
    #: Days that must pass between training runs.
    cooldown_days: int = 14
    #: One-minute load average per core above which the machine is considered busy.
    max_load_per_core: float = 0.70
    #: Free disk in MiB needed to hold a training run's outputs.
    min_free_disk_mib: int = 2048

    def __post_init__(self):
        if not 1 <= self.min_new_labels <= 1_000_000:
            raise RetrainingError('min_new_labels is out of range')
        if not 0 <= self.min_new_per_label <= self.min_new_labels:
            raise RetrainingError('min_new_per_label is out of range')
        if not 0 <= self.min_new_sources <= 100_000:
            raise RetrainingError('min_new_sources is out of range')
        if not 0 <= self.cooldown_days <= 3650:
            raise RetrainingError('cooldown_days is out of range')
        if not 0 < self.max_load_per_core <= 64:
            raise RetrainingError('max_load_per_core is out of range')
        if not 0 <= self.min_free_disk_mib <= 10_000_000:
            raise RetrainingError('min_free_disk_mib is out of range')

    def explain(self):
        return {'min_new_labels': self.min_new_labels,
                'min_new_per_label': self.min_new_per_label,
                'min_new_sources': self.min_new_sources,
                'cooldown_days': self.cooldown_days,
                'max_load_per_core': self.max_load_per_core,
                'min_free_disk_mib': self.min_free_disk_mib}


@dataclass(frozen=True)
class RetrainingSignals:
    """What is known right now. Every field is optional and unknown means unknown.

    An unknown signal is never guessed and never treated as favourable. A missing
    drift reading does not become "no drift"; it becomes a sentence saying the
    reading is missing.
    """

    new_benign_labels: int = 0
    new_malicious_labels: int = 0
    new_uncertain_labels: int = 0
    new_label_sources: int = 0
    days_since_training: float | None = None
    drift_status: str = ''
    ood_rate: float | None = None
    model_health: str = ''
    load_per_core: float | None = None
    free_disk_mib: float | None = None

    @property
    def new_labels(self):
        return self.new_benign_labels + self.new_malicious_labels

    def explain(self):
        return {'new_benign_labels': self.new_benign_labels,
                'new_malicious_labels': self.new_malicious_labels,
                'new_uncertain_labels': self.new_uncertain_labels,
                'new_label_sources': self.new_label_sources,
                'days_since_training': self.days_since_training,
                'drift_status': self.drift_status or 'unknown',
                'ood_rate': self.ood_rate,
                'model_health': self.model_health or 'unknown',
                'load_per_core': self.load_per_core,
                'free_disk_mib': self.free_disk_mib}


@dataclass(frozen=True)
class RetrainingAdvice:
    """Words, not an action.

    `next_step` is the command a person could choose to run. Nothing in this
    project runs it for them.
    """

    recommendation: str
    reasons: tuple = ()
    blockers: tuple = ()
    signals: dict = field(default_factory=dict)
    policy: dict = field(default_factory=dict)

    @property
    def would_train(self):
        """Always False. Kept so callers can assert on it rather than assume."""
        return False

    @property
    def next_step(self):
        if self.recommendation != CONSIDER_RETRAINING:
            return ''
        return 'eye-for-an-eye review export --out labels.json'

    def explain(self):
        return {'advice_version': RETRAINING_ADVICE_VERSION,
                'recommendation': self.recommendation,
                'reasons': list(self.reasons), 'blockers': list(self.blockers),
                'signals': self.signals, 'policy': self.policy,
                'next_step': self.next_step,
                'authority': ('advice only; this project has no automatic training and no '
                              'automatic promotion')}


def evaluate(signals, policy=None):
    """Turn signals into advice. Pure: it reads nothing and writes nothing.

    The order is deliberate. Hard blockers come first, because a machine that is
    busy or short of disk is not a machine to start a long job on, whatever the
    data looks like. Then the cooldown, which stops a model being rebuilt every
    few days on barely-changed data. Only then does the amount of new evidence
    matter.
    """
    policy = policy or RetrainingPolicy()
    if not isinstance(signals, RetrainingSignals):
        raise RetrainingError('retraining advice needs a RetrainingSignals')
    reasons, blockers = [], []

    if signals.load_per_core is not None and signals.load_per_core > policy.max_load_per_core:
        blockers.append(f'the machine is busy (load {signals.load_per_core:.2f} per core, '
                        f'limit {policy.max_load_per_core:.2f})')
    if signals.free_disk_mib is not None and signals.free_disk_mib < policy.min_free_disk_mib:
        blockers.append(f'only {signals.free_disk_mib:.0f} MiB free, '
                        f'{policy.min_free_disk_mib} MiB needed')
    if blockers:
        return RetrainingAdvice(SYSTEM_BUSY, reasons=('defending comes first; training can wait',),
                                blockers=tuple(blockers), signals=signals.explain(),
                                policy=policy.explain())

    if (signals.days_since_training is not None
            and signals.days_since_training < policy.cooldown_days):
        remaining = policy.cooldown_days - signals.days_since_training
        return RetrainingAdvice(
            WAIT_COOLDOWN,
            reasons=(f'the model was trained {signals.days_since_training:.0f} days ago; '
                     f'{remaining:.0f} days of the cooldown are left',
                     'rebuilding a model on barely changed data mostly reproduces its mistakes'),
            signals=signals.explain(), policy=policy.explain())

    missing = []
    if signals.new_labels < policy.min_new_labels:
        missing.append(f'{signals.new_labels} new reviewed labels, '
                       f'{policy.min_new_labels} needed')
    if signals.new_benign_labels < policy.min_new_per_label:
        missing.append(f'{signals.new_benign_labels} new benign labels, '
                       f'{policy.min_new_per_label} needed')
    if signals.new_malicious_labels < policy.min_new_per_label:
        missing.append(f'{signals.new_malicious_labels} new malicious-automation labels, '
                       f'{policy.min_new_per_label} needed')
    if signals.new_label_sources < policy.min_new_sources:
        missing.append(f'labels come from {signals.new_label_sources} sources, '
                       f'{policy.min_new_sources} needed')

    # Model health is context for a person, never a reason on its own. A drifted
    # population says the model knows less than it did. It says nothing about who
    # is sending the traffic, and it cannot make thin evidence sufficient.
    if signals.drift_status in ('DRIFTED', 'WARNING'):
        reasons.append(f'the traffic distribution has moved ({signals.drift_status.lower()}); '
                       'the model knows less about current traffic than it used to')
    elif not signals.drift_status:
        reasons.append('no drift reading is available')
    if signals.ood_rate is not None and signals.ood_rate >= 0.30:
        reasons.append(f'{signals.ood_rate:.0%} of recent observations are outside the training '
                       'distribution, which means unfamiliar, not hostile')
    if signals.model_health in ('DEGRADED', 'UNRELIABLE'):
        reasons.append(f'model health is {signals.model_health.lower()}; the mathematical engine '
                       'is unaffected and still running')
    if signals.new_uncertain_labels:
        reasons.append(f'{signals.new_uncertain_labels} entries were answered uncertain and are '
                       'deliberately excluded from supervised training')

    if missing:
        return RetrainingAdvice(COLLECT_MORE, reasons=tuple(reasons), blockers=tuple(missing),
                                signals=signals.explain(), policy=policy.explain())

    reasons.insert(0, f'{signals.new_labels} new labels from {signals.new_label_sources} sources '
                      'have accumulated since the last training run')
    reasons.append('nothing has been started; building a dataset, training and promoting are '
                   'three separate steps a person runs')
    return RetrainingAdvice(CONSIDER_RETRAINING, reasons=tuple(reasons),
                            signals=signals.explain(), policy=policy.explain())


def system_signals():
    """Best-effort machine load and free disk. Unknown values stay unknown."""
    import os
    import shutil
    load, free = None, None
    try:
        load = os.getloadavg()[0] / max(1, os.cpu_count() or 1)
    except (OSError, AttributeError):
        load = None
    try:
        free = shutil.disk_usage(os.getcwd()).free / (1024 * 1024)
    except OSError:
        free = None
    return {'load_per_core': load, 'free_disk_mib': free}
