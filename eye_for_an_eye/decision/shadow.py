"""Bounded research aggregate; absent labels never become false-positive claims."""
from collections import Counter
from .policy import ACTIONS


class ShadowReport:
    def __init__(self, max_sources=10000):
        self.max_sources = max_sources
        self.sources = {}
        self.actions, self.disagreements, self.contributions = Counter(), Counter(), Counter()
        self.histogram = [0] * 10
        self.overflow = 0

    def observe(self, record, label=None):
        data = record['observations']
        action = data['action']
        if action not in ACTIONS:
            raise ValueError('invalid decision action')
        self.actions[action] += 1
        self.disagreements[data['disagreement']] += 1
        self.histogram[min(9, int(data['risk'] * 10))] += 1
        self.contributions.update(data.get('math_contributions', {}))
        key = (record['sensor_id'], record['src_ip'])
        if key not in self.sources and len(self.sources) >= self.max_sources:
            self.overflow += 1
            return
        source = self.sources.setdefault(key, {'highest': 'OBSERVE', 'would_block': False, 'label': label})
        if ACTIONS.index(action) > ACTIONS.index(source['highest']):
            source['highest'] = action
        source['would_block'] |= data['would_enforce']

    def snapshot(self):
        blocked = [s for s in self.sources.values() if s['would_block']]
        labelled = [s for s in blocked if s['label'] in (0, 1)]
        return {'total_sources_retained': len(self.sources), 'source_limit_exceeded_events': self.overflow,
            'decisions_by_action': dict(self.actions), 'highest_action_by_source': dict(Counter(s['highest'] for s in self.sources.values())),
            'would_block_sources': len(blocked), 'agreement': dict(self.disagreements), 'risk_deciles': self.histogram,
            'top_math_contributions_sum': self.contributions.most_common(6),
            'potential_false_positive_sources': sum(s['label'] == 0 for s in labelled) if labelled else None,
            'block_precision': sum(s['label'] == 1 for s in labelled) / len(labelled) if labelled else None,
            'labelled_would_block_sources': len(labelled), 'unlabelled_would_block_sources': len(blocked) - len(labelled)}
