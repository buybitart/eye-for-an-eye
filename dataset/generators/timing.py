"""Timing shapes shared by both label classes.

Every shape is available to benign and to malicious-automation-like scenarios, so a model
cannot learn the harness: there is no spacing that only one class ever produces.
"""
from .base import jitter


def steady(stream, count, period, spread=.06, start=0.0):
    """Regular, the way a monitoring agent or a health check is regular."""
    moment, times = start, []
    for _ in range(count):
        times.append(moment)
        moment += jitter(stream, period, spread)
    return times


def jittered(stream, count, period, spread=.45, start=0.0):
    """Ordinary irregular traffic."""
    moment, times = start, []
    for _ in range(count):
        times.append(moment)
        moment += jitter(stream, period, spread)
    return times


def human(stream, count, period, start=0.0):
    """Uneven, with occasional thinking pauses."""
    moment, times = start, []
    for index in range(count):
        times.append(moment)
        gap = jitter(stream, period, .8)
        if index and index % stream.randrange(3, 6) == 0:
            gap += stream.uniform(period, period * 4)
        moment += gap
    return times


def bursty(stream, bursts, burst_size, inside, pause, start=0.0):
    """Burst, pause, burst. Used by benign deploy probes and by reconnaissance alike."""
    moment, times = start, []
    for burst in range(bursts):
        for _ in range(burst_size):
            times.append(moment)
            moment += jitter(stream, inside, .5)
        if burst < bursts - 1:
            moment += jitter(stream, pause, .3)
    return times


def paced(stream, count, delay, spread=.35, start=0.0):
    """Deliberately slow. A quiet scanner and a slow updater share this shape."""
    return jittered(stream, count, delay, spread, start)
