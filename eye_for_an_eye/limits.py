"""Finite token buckets; no per-client threads."""
import time


class TokenBucket:
    def __init__(self, rate, burst=None, clock=time.monotonic):
        self.rate = rate
        self.burst = max(1.0, rate) if burst is None else burst
        self.tokens = self.burst
        self.clock = clock
        self.updated = clock()

    def allow(self):
        now = self.clock()
        self.tokens = min(self.burst, self.tokens + max(0, now - self.updated) * self.rate)
        self.updated = now
        if self.tokens < 1:
            return False
        self.tokens -= 1
        return True
