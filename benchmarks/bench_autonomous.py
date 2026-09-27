"""What the autonomous decision path costs the runtime that carries it. P15.5R §23.

Four configurations, one process, one workload, back to back, so the only thing
that differs between them is how much of the P15 stack is attached:

    legacy              autonomy off -- `DecisionFusion` -> `PolicyGuard`, the
                        path `reports/P15_5R_RUNTIME_BEFORE.md` traced
    authority           autonomy on, nothing persisted
    journal             ... and the canonical decision journal (§2-§7)
    journal_and_export  ... and the analytic shadow export (§8-§11)

Run back to back in one child because the comparison is the measurement. A
number from this machine is worth little; the *difference* between two numbers
taken 200 milliseconds apart on the same machine is worth something, and the
difference is what §23 asks for.

### Two decision densities, because one of them would be a lie either way

The autonomous path runs once per decision *window*, not once per packet:
`DecisionEngine.observe` refuses to evaluate a source again until
`decision.interval_ms` has passed. So the per-packet cost of autonomy is mostly
zero and the per-window cost is not, and a single average over a realistic
stream hides both.

    per_window          `interval_ms = 0` -- every event is a decision window.
                        Deliberately the densest possible stream and not a
                        realistic one. It isolates the cost of one decision.
    shipped_interval    the shipped 2000 ms. What a stream at this event rate
                        actually pays, which is much less and is not a claim
                        about any other event rate.

`measure` records per-call latency, so the shipped-interval percentiles are
bimodal on purpose: p50 is a packet that only updated correlation state and max
is a packet that triggered a decision.

### What this does not measure

No enforcer is attached in any configuration. Enforcement costs a subprocess
and is bounded by `HostEnforcer`'s own timeout; measuring it here would measure
process spawn on this machine and nothing about the decision path.

There is no assertion in this file. Benchmarks report; `tests/` decides.
"""
import gc
import json
from pathlib import Path
import tempfile

from benchmarks.common import config, configuration, measure, resources
from benchmarks.workloads import event
from eye_for_an_eye.analysis import EventAnalysis

REPOSITORY = Path(__file__).resolve().parents[1]
CALIBRATOR = REPOSITORY / 'models' / 'mathrisk-cal-v4-isotonic.json'

#: Four sources probing many ports: the same shape `bench_correlation` calls
#: `scanner`, chosen so the authority has something to decide about rather than
#: a stream it refuses on observation count alone.
SOURCES = 4

CASES = ('legacy', 'authority', 'journal', 'journal_and_export')


def _settings(case, directory, *, interval_ms):
    settings = config()
    settings.decision.interval_ms = interval_ms
    settings.storage.enabled = False
    settings.autonomy.enabled = case != 'legacy'
    settings.autonomy.mode = 'shadow'
    if settings.autonomy.enabled:
        settings.autonomy.calibrator_path = str(CALIBRATOR)
    if case in ('journal', 'journal_and_export'):
        settings.autonomy.decision_journal_path = str(directory / f'{case}-journal.jsonl')
    if case == 'journal_and_export':
        settings.autonomy.shadow_export_path = str(directory / f'{case}-export.jsonl')
    return settings


def _one(case, directory, *, count, interval_ms):
    settings = _settings(case, directory, interval_ms=interval_ms)
    analysis = EventAnalysis(settings, offline=True)
    analysis.start()
    try:
        before = resources()
        timing = measure(count, lambda i: list(analysis.process(event(i, SOURCES))))
        pipeline = analysis.decisions.autonomy
        row = {
            'case': case,
            'autonomy_attached': pipeline is not None,
            'measurement': timing,
            'rss_start_bytes': before['rss_bytes'],
            'decision_metrics': dict(analysis.decisions.metrics),
            'counters': dict(pipeline.counters) if pipeline else None,
            'journal': pipeline.journal.status() if pipeline and pipeline.journal else None,
            'shadow_export': (pipeline.shadow_export.status()
                              if pipeline and pipeline.shadow_export else None),
        }
    finally:
        analysis.close()
    del analysis
    gc.collect()
    return row


#: Below this many decisions, an added-cost-per-decision figure is the
#: difference of two wall-clock totals divided by a small number, which is
#: run-to-run variance wearing a unit. It is left unreported rather than
#: printed with a caveat nobody reads.
MINIMUM_DECISIONS_FOR_A_UNIT_COST = 100


def _sweep(directory, *, count, interval_ms):
    rows = [_one(case, directory, count=count, interval_ms=interval_ms)
            for case in CASES]
    baseline = rows[0]['measurement']['seconds']
    for row in rows:
        decisions = (row['counters'] or {}).get('decisions', 0)
        added = row['measurement']['seconds'] - baseline
        row['added_seconds_vs_legacy'] = added
        row['added_ratio_vs_legacy'] = (
            row['measurement']['seconds'] / baseline if baseline else None)
        usable = decisions >= MINIMUM_DECISIONS_FOR_A_UNIT_COST
        row['added_ms_per_decision'] = (added * 1000 / decisions) if usable else None
        row['added_ms_per_decision_withheld'] = (
            '' if usable else f'{decisions} decisions is below the '
                              f'{MINIMUM_DECISIONS_FOR_A_UNIT_COST}-decision floor '
                              f'for a per-decision figure')
    return rows


def _overhead_summary(rows):
    """The one sentence a reader of this case wants, computed rather than written."""
    last = rows[-1]
    counters = last['counters'] or {}
    return {'events': last['measurement']['operations'],
            'decisions': counters.get('decisions', 0),
            # Stated because it bounds the claim: this is the cost of the ALLOW
            # path. A TEMP_BLOCK record is journalled a second time after the
            # enforcement attempt, and no enforcer is attached here.
            'blocks': counters.get('blocks', 0),
            'full_stack_ratio_vs_legacy': last['added_ratio_vs_legacy'],
            'full_stack_added_ms_per_decision': last['added_ms_per_decision'],
            'withheld': last['added_ms_per_decision_withheld']}


def run(full=False):
    count = 3000 if full else 800
    with tempfile.TemporaryDirectory() as workspace:
        directory = Path(workspace)
        per_window = _sweep(directory / 'dense', count=count, interval_ms=0)
        shipped = _sweep(directory / 'shipped', count=count,
                         interval_ms=2000)
        written = {path.name: path.stat().st_size
                   for path in sorted(directory.rglob('*.jsonl'))}
    settings = _settings('journal_and_export', Path('.'), interval_ms=0)
    return {
        'configuration': configuration(settings),
        'workload': {'events': count, 'sources': SOURCES,
                     'calibrator': CALIBRATOR.name,
                     'enforcer_attached': False,
                     'mode': 'shadow'},
        'per_window': per_window,
        'per_window_summary': _overhead_summary(per_window),
        'shipped_interval': shipped,
        'shipped_interval_summary': _overhead_summary(shipped),
        'bytes_written': written,
        'note': ('interval_ms=0 makes every event a decision window and is not a '
                 'realistic stream; it is the density at which one decision can '
                 'be measured. No enforcer is attached in any case.'),
    }


if __name__ == '__main__':
    print(json.dumps(run(), indent=2, default=str))
