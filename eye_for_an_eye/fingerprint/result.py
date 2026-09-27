"""Common measured-evidence/hypothesis contract. P2 has no calibrated HIGH rules."""
from dataclasses import dataclass, field, asdict


@dataclass(slots=True)
class FingerprintResult:
    feature: str
    status: str = 'unknown'
    observations: dict = field(default_factory=dict)
    hypothesis: dict | None = None
    confidence: str = 'UNKNOWN'
    evidence: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def __post_init__(self):
        if self.confidence not in ('UNKNOWN', 'LOW', 'MEDIUM'):
            raise ValueError('HIGH requires future independently calibrated rules')
        if not isinstance(self.observations, dict) or self.hypothesis is not None and not isinstance(self.hypothesis, dict):
            raise ValueError('fingerprint sections must be objects')

    def to_dict(self):
        return asdict(self)

    # Read-only compatibility with P0 dictionary results; canonical serialization
    # always uses the separate observations/hypothesis sections above.
    def __getitem__(self, key):
        if key == 'reason':
            return self.reason
        if key in ('status', 'confidence'):
            return getattr(self, key)
        if key in self.observations:
            return self.observations[key]
        if self.hypothesis and key in self.hypothesis:
            return self.hypothesis[key]
        raise KeyError(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key):
        return key in self.observations or key in (self.hypothesis or {}) or key in ('status', 'confidence', 'reason')

    @property
    def reason(self):
        return self.evidence[0] if self.evidence else 'insufficient_evidence'

    @property
    def os_family(self):
        return (self.hypothesis or {}).get('name')

    @property
    def os_version(self):
        return (self.hypothesis or {}).get('flavor')

    @property
    def fuzzy(self):
        return self.observations.get('fuzzy')

    @property
    def distance(self):
        return (self.hypothesis or {}).get('distance')
