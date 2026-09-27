"""Shared pure event analysis for queued live runtime and paced offline replay."""
from .correlation.engine import CorrelationEngine
from .decision.engine import DecisionEngine


class EventAnalysis:
    def __init__(self, config, *, offline=False):
        self.correlator = CorrelationEngine(config.correlation)
        self.decisions = DecisionEngine(config, self.correlator, offline=offline)

    def start(self):
        self.decisions.start()

    def close(self):
        self.decisions.close()

    def process(self, event):
        yield event
        for result in self.correlator.observe(event):
            yield result.event(event)
        yield from self.decisions.observe(event)

    def poll(self):
        yield from self.decisions.poll()
