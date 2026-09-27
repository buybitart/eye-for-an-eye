"""Thread-safe TTL/LRU cache with optional retained-object byte accounting."""
from collections import OrderedDict
from copy import deepcopy
from dataclasses import fields, is_dataclass
import math
import sys
import threading
import time


def _size(value, seen=None):
    seen = set() if seen is None else seen
    if id(value) in seen:
        return 0
    seen.add(id(value))
    total = sys.getsizeof(value)
    if isinstance(value, dict):
        total += sum(_size(k, seen) + _size(v, seen) for k, v in value.items())
    elif isinstance(value, (list, tuple, set, frozenset)):
        total += sum(_size(v, seen) for v in value)
    elif is_dataclass(value) and not isinstance(value, type):
        total += sum(_size(getattr(value, item.name), seen) for item in fields(value))
    return total


class TTLCache:
    def __init__(self, max_entries=10_000, ttl_seconds=600, *, clock=time.monotonic, max_bytes=None):
        if type(max_entries) is not int or max_entries < 1:
            raise ValueError("max_entries must be a positive integer")
        if not math.isfinite(ttl_seconds) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be finite and positive")
        if max_bytes is not None and (type(max_bytes) is not int or max_bytes < 1):
            raise ValueError("max_bytes must be a positive integer")
        self.max_entries, self.ttl_seconds, self.max_bytes = max_entries, ttl_seconds, max_bytes
        self.clock = clock
        self._items = OrderedDict()
        self._bytes = 0
        self._lock = threading.RLock()
        self._metrics = dict(hit=0, miss=0, eviction=0, expired=0, rejected=0)

    @property
    def metrics(self):
        with self._lock:
            return dict(self._metrics)

    @property
    def current_bytes(self):
        with self._lock:
            return self._bytes

    def _remove(self, key, reason=None):
        _, _, size = self._items.pop(key)
        self._bytes -= size
        if reason:
            self._metrics[reason] += 1

    def get(self, key, default=None):
        with self._lock:
            item = self._items.get(key)
            if item is not None and item[0] <= self.clock():
                self._remove(key, "expired")
                item = None
            if item is None:
                self._metrics["miss"] += 1
                return default
            self._items.move_to_end(key)
            self._metrics["hit"] += 1
            return deepcopy(item[1])

    def set(self, key, value, ttl_seconds=None):
        ttl = self.ttl_seconds if ttl_seconds is None else ttl_seconds
        if not math.isfinite(ttl) or ttl <= 0:
            raise ValueError("TTL must be finite and positive")
        # Copy on both boundaries: callers cannot grow an already-accounted value.
        size = _size(key) + _size(value) + 128
        with self._lock:
            if self.max_bytes is not None and size > self.max_bytes:
                self._metrics["rejected"] += 1
                return False
            if key in self._items:
                self._remove(key)
            while self._items and (len(self._items) >= self.max_entries or
                    (self.max_bytes is not None and self._bytes + size > self.max_bytes)):
                self._remove(next(iter(self._items)), "eviction")
            self._items[key] = (self.clock() + ttl, deepcopy(value), size)
            self._bytes += size
            return True

    def __len__(self):
        with self._lock:
            now = self.clock()
            for key in [k for k, v in self._items.items() if v[0] <= now]:
                self._remove(key, "expired")
            return len(self._items)

    def items(self):
        """Bounded key snapshot, one copied value at a time (for offline summaries)."""
        with self._lock:
            keys = list(self._items)
        for key in keys:
            value = self.get(key)
            if value is not None:
                yield key, value
