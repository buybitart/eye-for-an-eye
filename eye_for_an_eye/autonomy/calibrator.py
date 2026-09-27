"""Loading the one calibrator this deployment decides with. P15.5R §9, §10.

`decision/calibration.py` knows how to read and validate a calibration artifact.
This knows which artifact a *running sensor* is entitled to use, which is a
different question and the one P15.5 found unanswered: the module was not
imported by a sensor at all, and `config.py` had no key that named a file.

### What is checked, and why each check is here rather than in the loader

`calibration.load` refuses a malformed artifact — bad method, non-monotone
knots, an infinite coefficient, a digest that does not match the contents. Those
are properties of the *file*. What it cannot know is whether the file belongs to
this build, and three of P15's worst near-misses live in that gap:

* **Formula version.** A calibrator fitted on `math-risk-v3` scores maps a
  quantity this build no longer computes. The numbers are all finite, the curve
  is monotone, and every probability it returns is wrong. P15.3 changed the
  formula and P15.4 refitted for exactly this reason.
* **Source quantity.** An artifact fitted on `model_score` handed a `math_risk`
  score produces a plausible number from the wrong units. `Calibrator.calibrate`
  already refuses by name; this refuses earlier and says so out loud.
* **A conservative bound.** An artifact with no `lower_knots` has stated a point
  estimate and not how sure it is. The authority treats that as
  `CALIBRATION_UNAVAILABLE` and cannot block, which is correct — but silently,
  and an operator who turned autonomous mode on deserves to be told at startup
  rather than to discover it as a recall of zero.

### The one thing this must never do

§10: a failed calibrator does not promote the raw `MathRisk` score to a
probability. `MathRisk` is explicitly uncalibrated; its score and a probability
are different quantities that happen to share an interval. So a failure here
produces a state — `UNAVAILABLE` or `DEGRADED` — in which observation continues
and autonomous blocking cannot happen, and never a fallback estimate.
"""
from dataclasses import dataclass, field
import hashlib
from pathlib import Path

from ..decision import calibration as cal
from ..decision.math_risk import VERSION as MATH_RISK_VERSION

CALIBRATOR_LOADER_VERSION = 'autonomy-calibrator-loader-v1'

#: Component states, shared with `pipeline.health()` and §20's four names.
NOT_CONFIGURED = 'NOT_CONFIGURED'
HEALTHY = 'HEALTHY'
DEGRADED = 'DEGRADED'
UNAVAILABLE = 'UNAVAILABLE'

#: The quantity a runtime calibrator must map. The classifier has its own
#: calibrators (`models/classifier-cal-*`); they are not this.
REQUIRED_SOURCE = 'math_risk'

#: §48 of P15.4: a source-level fit. A window-level artifact answers a different
#: question — "is this window malicious" rather than "is this source" — and the
#: conservative bound that the cost test consumes is computed over whichever
#: unit the artifact was fitted on. Loading a window-level artifact is not
#: refused, because it is not *wrong*, but it cannot support a block.
PREFERRED_UNIT = cal.SOURCE


@dataclass(frozen=True, slots=True)
class CalibratorState:
    """One calibrator, its status, and what it is allowed to be used for."""

    status: str
    path: str = ''
    reason: str = ''
    calibrator: object = None
    version: str = ''
    source: str = ''
    model_version: str = ''
    unit: str = ''
    samples: int = 0
    positives: int = 0
    digest: str = ''
    file_sha256: str = ''
    #: Whether this state may produce the calibrated probability an autonomous
    #: TEMP_BLOCK requires. False for every status but `HEALTHY`.
    supports_autonomous_block: bool = False
    #: What was checked, so a `doctor` reader can see the reasoning rather than
    #: a verdict. Ordered as the checks ran.
    checks: tuple = field(default_factory=tuple)

    @property
    def configured(self):
        return self.status != NOT_CONFIGURED

    @property
    def usable(self):
        return self.calibrator is not None

    def explain(self):
        return {'calibrator_loader_version': CALIBRATOR_LOADER_VERSION,
                'status': self.status, 'path': self.path, 'reason': self.reason,
                'calibrator_version': self.version, 'source': self.source,
                'model_version': self.model_version, 'unit': self.unit,
                'samples': self.samples, 'positives': self.positives,
                'artifact_digest': self.digest[:16],
                'file_sha256': self.file_sha256[:16],
                'supports_autonomous_block': self.supports_autonomous_block,
                'checks': [dict(check) for check in self.checks]}


def _check(name, passed, detail):
    return {'check': name, 'passed': bool(passed), 'detail': detail}


def _file_digest(path):
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return ''


def load_for(config, *, formula_version=MATH_RISK_VERSION):
    """The calibrator this configuration entitles the runtime to use.

    Never raises. A configuration problem, a missing file and an artifact from
    the wrong formula are all *states*, because the sensor's job on a bad day is
    to keep observing and refuse to act, not to fail to start.
    """
    settings = getattr(config, 'autonomy', None)
    path = str(getattr(settings, 'calibrator_path', '') or '') if settings else ''
    if not path:
        return CalibratorState(
            status=NOT_CONFIGURED,
            reason='no calibrator is configured; autonomy.calibrator_path is empty',
            checks=(_check('configured', False, 'autonomy.calibrator_path is empty'),))

    checks = [_check('configured', True, path)]
    try:
        calibrator = cal.load(path)
    except cal.CalibrationError as exc:
        checks.append(_check('artifact_valid', False, str(exc)[:200]))
        return CalibratorState(status=UNAVAILABLE, path=path, reason=str(exc)[:200],
                               file_sha256=_file_digest(path), checks=tuple(checks))
    except OSError as exc:
        detail = f'{type(exc).__name__}: the calibrator could not be read'
        checks.append(_check('artifact_valid', False, detail))
        return CalibratorState(status=UNAVAILABLE, path=path, reason=detail,
                               checks=tuple(checks))
    checks.append(_check('artifact_valid', True,
                         'method, monotonicity, finiteness and digest checked by '
                         'decision.calibration.load'))

    common = {'path': path, 'calibrator': None, 'version': calibrator.version,
              'source': calibrator.source, 'model_version': calibrator.model_version,
              'unit': calibrator.unit, 'samples': int(calibrator.samples),
              'positives': int(calibrator.positives), 'digest': calibrator.digest,
              'file_sha256': _file_digest(path)}

    # -- the three build-compatibility checks --------------------------------

    if calibrator.source != REQUIRED_SOURCE:
        detail = (f'this artifact maps {calibrator.source!r}; the runtime '
                  f'calibrates {REQUIRED_SOURCE!r}')
        checks.append(_check('source_quantity', False, detail))
        return CalibratorState(status=UNAVAILABLE, reason=detail,
                               checks=tuple(checks), **common)
    checks.append(_check('source_quantity', True, calibrator.source))

    if calibrator.model_version != formula_version:
        detail = (f'fitted on {calibrator.model_version!r}; this build computes '
                  f'{formula_version!r}. A calibrator maps the scores of one '
                  f'formula and means nothing against another')
        checks.append(_check('formula_version', False, detail))
        return CalibratorState(status=UNAVAILABLE, reason=detail,
                               checks=tuple(checks), **common)
    checks.append(_check('formula_version', True, formula_version))

    # -- what it is allowed to be used for -----------------------------------

    if not calibrator.lower_knots:
        detail = ('this artifact carries no conservative bound, so it states a '
                  'point estimate and not how sure it is; observation continues '
                  'and no autonomous block is possible')
        checks.append(_check('conservative_bound', False, detail))
        return CalibratorState(status=DEGRADED, reason=detail, checks=tuple(checks),
                               **{**common, 'calibrator': calibrator})
    checks.append(_check('conservative_bound', True,
                         f'{len(calibrator.lower_knots)} bound knots'))

    if calibrator.unit != PREFERRED_UNIT:
        detail = (f'fitted per {calibrator.unit}; an autonomous decision is about '
                  f'a {PREFERRED_UNIT}, and a bound computed over the wrong unit '
                  f'is a bound on a different question')
        checks.append(_check('fitting_unit', False, detail))
        return CalibratorState(status=DEGRADED, reason=detail, checks=tuple(checks),
                               **{**common, 'calibrator': calibrator})
    checks.append(_check('fitting_unit', True, calibrator.unit))

    return CalibratorState(status=HEALTHY, reason='', checks=tuple(checks),
                           supports_autonomous_block=True,
                           **{**common, 'calibrator': calibrator})


def calibrated_probability(state, *, math_risk):
    """The probability this state supports, or `None`. Never a raw score (§10).

    `None` is not a gap to be filled. It reaches the authority as
    `calibrated=False`, whose `calibrated_estimate` gate refuses every block —
    which is the whole of §10 expressed where it cannot be forgotten.
    """
    if state is None or not state.supports_autonomous_block or state.calibrator is None:
        return None
    return state.calibrator.calibrate(math_risk, model_version=MATH_RISK_VERSION)
