"""HTTP behaviour as numbers, grouped into families a person can argue with.

The families exist so that evidence has to be *diverse* before it counts for
much. A source with a high request rate and nothing else is a busy client. A
source with a high rate, and many distinct paths, and a 404 ratio near one, and
metronomic timing, and fifteen minutes of persistence has five independent
things wrong with it, and that is a different claim entirely.

Every feature here is bounded to [0, 1] after normalisation, derives from
counters rather than content, and is named so that it can appear in a sentence
shown to an operator.
"""
from dataclasses import dataclass

from .state import interval_statistics, rate_per_minute

#: 2 adds the long-window timing statistics. A source that paces itself at
#: one request every twenty seconds produces too few requests a minute for
#: any 60-second timing feature to say anything, which made the most
#: patient scanners the least visible ones. Nothing was removed: the
#: 60-second features are unchanged and still carry fast traffic.
WEB_FEATURE_SCHEMA_VERSION = 2

#: The families. A family with no evidence contributes nothing; the point is how
#: many families have something to say at once.
FAMILIES = ('RATE', 'PATH_DISCOVERY', 'AUTHENTICATION', 'HTTP_ERRORS', 'METHOD_BEHAVIOUR',
            'TIMING', 'SESSION', 'PROTOCOL_QUALITY', 'PERSISTENCE')

#: name -> (family, ceiling, unit). The ceiling is what counts as "as much as
#: this feature can say"; values above it saturate rather than dominating.
SPEC = (
    ('requests_10s', 'RATE', 60, 'requests'),
    ('requests_60s', 'RATE', 300, 'requests'),
    ('requests_900s', 'RATE', 2000, 'requests'),
    ('request_rate_per_minute', 'RATE', 240, 'requests per minute'),

    ('unique_paths_60s', 'PATH_DISCOVERY', 40, 'distinct paths'),
    ('unique_paths_900s', 'PATH_DISCOVERY', 64, 'distinct paths'),
    ('path_request_ratio', 'PATH_DISCOVERY', 1, 'fraction'),
    ('repeated_path_ratio', 'PATH_DISCOVERY', 1, 'fraction'),
    ('path_entropy_mean', 'PATH_DISCOVERY', 1, 'normalised entropy'),
    ('sensitive_probe_count', 'PATH_DISCOVERY', 12, 'requests'),
    ('sensitive_category_count', 'PATH_DISCOVERY', 6, 'categories'),

    ('failed_auth_60s', 'AUTHENTICATION', 20, 'failures'),
    ('failed_auth_900s', 'AUTHENTICATION', 60, 'failures'),
    ('auth_failure_ratio', 'AUTHENTICATION', 1, 'fraction'),

    ('http_404_ratio', 'HTTP_ERRORS', 1, 'fraction'),
    ('http_401_ratio', 'HTTP_ERRORS', 1, 'fraction'),
    ('http_403_ratio', 'HTTP_ERRORS', 1, 'fraction'),
    ('http_4xx_ratio', 'HTTP_ERRORS', 1, 'fraction'),
    ('http_5xx_ratio', 'HTTP_ERRORS', 1, 'fraction'),
    ('http_2xx_ratio', 'HTTP_ERRORS', 1, 'fraction'),

    ('method_diversity', 'METHOD_BEHAVIOUR', 6, 'distinct methods'),
    ('unexpected_method_ratio', 'METHOD_BEHAVIOUR', 1, 'fraction'),

    ('interval_mean_60s', 'TIMING', 60, 'seconds'),
    ('interval_cv_60s', 'TIMING', 2, 'coefficient of variation'),
    ('interval_entropy_60s', 'TIMING', 1, 'normalised entropy'),
    # The same three over a quarter of an hour, so that clockwork slow traffic
    # is describable at all. A ceiling of 900 seconds on the mean is the whole
    # window: a gap that long means one request, which says nothing either way.
    ('interval_mean_900s', 'TIMING', 900, 'seconds'),
    ('interval_cv_900s', 'TIMING', 2, 'coefficient of variation'),
    ('interval_entropy_900s', 'TIMING', 1, 'normalised entropy'),
    ('burst_10s', 'TIMING', 1, 'fraction of the minute'),

    ('static_resource_ratio', 'SESSION', 1, 'fraction'),
    ('no_referer_ratio', 'SESSION', 1, 'fraction'),
    ('no_user_agent_ratio', 'SESSION', 1, 'fraction'),
    ('agent_change_rate', 'SESSION', 1, 'changes per request'),

    ('host_diversity', 'PROTOCOL_QUALITY', 8, 'distinct hosts'),
    ('unknown_method_count', 'PROTOCOL_QUALITY', 10, 'requests'),

    ('persistence_900s', 'PERSISTENCE', 900, 'seconds'),
    ('active_windows', 'PERSISTENCE', 3, 'windows'),
)

NAMES = tuple(name for name, *_ in SPEC)
FAMILY_OF = {name: family for name, family, *_ in SPEC}
CEILING_OF = {name: ceiling for name, _, ceiling, _ in SPEC}
UNIT_OF = {name: unit for name, *_, unit in SPEC}

#: Methods a plain website normally sees. Anything else is *evidence*, because
#: what is unexpected depends on the application: an API legitimately uses PUT
#: and DELETE, so this is configurable per protected service.
DEFAULT_EXPECTED_METHODS = ('GET', 'HEAD', 'POST', 'OPTIONS')


@dataclass(frozen=True)
class WebFeatures:
    """Bounded behavioural features for one source, plus the evidence behind them."""

    values: dict
    observations: int
    observation_seconds: float
    families_present: tuple = ()
    saturated_paths: bool = False
    schema_version: int = WEB_FEATURE_SCHEMA_VERSION

    def normalised(self):
        """Every feature scaled to [0, 1] against its ceiling."""
        return {name: min(1.0, max(0.0, (self.values.get(name) or 0.0) / CEILING_OF[name]))
                for name in NAMES}

    def by_family(self):
        grouped = {family: {} for family in FAMILIES}
        for name, value in self.values.items():
            grouped[FAMILY_OF[name]][name] = value
        return grouped

    def explain(self):
        return {'web_feature_schema_version': WEB_FEATURE_SCHEMA_VERSION,
                'observations': self.observations,
                'observation_seconds': round(self.observation_seconds, 1),
                'families_present': list(self.families_present),
                'saturated_paths': self.saturated_paths,
                'values': {name: round(float(value), 4)
                           for name, value in sorted(self.values.items())}}


def _ratio(count, total):
    return (count / total) if total else 0.0


def extract(state, now, *, expected_methods=DEFAULT_EXPECTED_METHODS):
    """Turn one source's recent behaviour into features.

    Reads the state's bounded windows; allocates nothing that scales with the
    number of distinct values the source produced.
    """
    expected = frozenset(expected_methods or DEFAULT_EXPECTED_METHODS)
    last_10 = state.within(now, 10)
    last_60 = state.within(now, 60)
    last_900 = state.within(now, 900)
    total_60 = len(last_60)
    total_900 = len(last_900)

    statuses_60 = [item.status for item in last_60 if item.status]
    status_total = len(statuses_60)
    methods_60 = {item.method for item in last_60}
    unexpected = sum(1 for item in last_60 if item.method not in expected)

    intervals = interval_statistics(last_60)
    intervals_900 = interval_statistics(last_900)
    auth_failures_60 = sum(1 for item in last_60 if item.auth_outcome == 'failure')
    auth_failures_900 = sum(1 for item in last_900 if item.auth_outcome == 'failure')
    auth_total_60 = sum(1 for item in last_60 if item.auth_outcome)

    sensitive_hits = [item for item in last_900 if item.sensitive]
    sensitive_names = {name for item in sensitive_hits for name in item.sensitive}

    unique_60 = len({item.path_key for item in last_60 if item.path_key})
    unique_900 = len({item.path_key for item in last_900 if item.path_key})

    values = {
        'requests_10s': float(len(last_10)),
        'requests_60s': float(total_60),
        'requests_900s': float(total_900),
        'request_rate_per_minute': rate_per_minute(total_60, 60),

        'unique_paths_60s': float(unique_60),
        'unique_paths_900s': float(unique_900),
        'path_request_ratio': _ratio(unique_60, total_60),
        'repeated_path_ratio': _ratio(total_60 - unique_60, total_60),
        'path_entropy_mean': (sum(item.path_entropy for item in last_60) / total_60
                              if total_60 else 0.0),
        'sensitive_probe_count': float(len(sensitive_hits)),
        'sensitive_category_count': float(len(sensitive_names)),

        'failed_auth_60s': float(auth_failures_60),
        'failed_auth_900s': float(auth_failures_900),
        'auth_failure_ratio': _ratio(auth_failures_60, auth_total_60),

        'http_404_ratio': _ratio(sum(1 for s in statuses_60 if s == 404), status_total),
        'http_401_ratio': _ratio(sum(1 for s in statuses_60 if s == 401), status_total),
        'http_403_ratio': _ratio(sum(1 for s in statuses_60 if s == 403), status_total),
        'http_4xx_ratio': _ratio(sum(1 for s in statuses_60 if 400 <= s < 500), status_total),
        'http_5xx_ratio': _ratio(sum(1 for s in statuses_60 if 500 <= s < 600), status_total),
        'http_2xx_ratio': _ratio(sum(1 for s in statuses_60 if 200 <= s < 300), status_total),

        'method_diversity': float(len(methods_60)),
        'unexpected_method_ratio': _ratio(unexpected, total_60),

        'interval_mean_60s': intervals['mean'] if intervals['mean'] is not None else 0.0,
        'interval_cv_60s': intervals['cv'] if intervals['cv'] is not None else 0.0,
        'interval_mean_900s': (intervals_900['mean']
                               if intervals_900['mean'] is not None else 0.0),
        'interval_cv_900s': (intervals_900['cv']
                             if intervals_900['cv'] is not None else 0.0),
        'interval_entropy_900s': (intervals_900['entropy']
                                  if intervals_900['entropy'] is not None else 1.0),
        'interval_entropy_60s': (intervals['entropy']
                                 if intervals['entropy'] is not None else 0.0),
        'burst_10s': _ratio(len(last_10), total_60),

        'static_resource_ratio': _ratio(
            sum(1 for item in last_60 if item.extension == 'static'), total_60),
        'no_referer_ratio': _ratio(
            sum(1 for item in last_60 if not item.referer_present), total_60),
        'no_user_agent_ratio': _ratio(
            sum(1 for item in last_60 if not item.agent_digest), total_60),
        'agent_change_rate': _ratio(state.agent_changes, state.total_requests),

        'host_diversity': float(len(state.hosts)),
        'unknown_method_count': float(sum(1 for item in last_900 if item.method == 'OTHER')),

        'persistence_900s': min(900.0, state.persistence_seconds),
        'active_windows': float(sum(1 for group in (last_10, last_60, last_900) if group)),
    }

    families = tuple(family for family in FAMILIES
                     if any(values.get(name) for name, spec_family, *_ in SPEC
                            if spec_family == family))
    return WebFeatures(values=values, observations=total_900,
                       observation_seconds=min(900.0, state.persistence_seconds),
                       families_present=families,
                       saturated_paths=state.paths.saturated)
