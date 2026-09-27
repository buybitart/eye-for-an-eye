"""Nonblocking drop-newest queues with explicit item and retained byte budgets."""
from collections import deque
import threading
import time
import queue


class BoundedQueue:
    drop_policy = 'drop-newest'

    def __init__(self, max_events, max_bytes, *, priority_enabled=False, low_watermark=.75, normal_watermark=.9):
        if type(max_events) is not int or type(max_bytes) is not int or min(max_events, max_bytes) < 1:
            raise ValueError('queue limits must be positive integers')
        self.maxsize, self.max_bytes = max_events, max_bytes
        if type(priority_enabled) is not bool or not 0 < low_watermark < normal_watermark < 1:
            raise ValueError('invalid priority admission thresholds')
        self.priority_enabled = priority_enabled
        self.watermarks = {'low': low_watermark, 'normal': normal_watermark, 'high': 1.0}
        self.shed = dict.fromkeys(self.watermarks, 0)
        if priority_enabled:
            self.drop_policy = 'priority-admission-drop-newest'
        self._items, self._bytes = deque(), 0
        self._condition = threading.Condition()
        self.dropped = 0
        self.closed = False

    def put(self, item, size, *, priority='normal'):
        if type(size) is not int or size < 0:
            raise ValueError('invalid item size')
        if priority not in self.watermarks:
            raise ValueError('invalid priority')
        with self._condition:
            if self.closed or len(self._items) >= self.maxsize or self._bytes + size > self.max_bytes:
                self.dropped += 1
                return False
            # O(1), FIFO retained. Reserve space without scanning or evicting queued evidence.
            pressure = max((len(self._items) + 1) / self.maxsize, (self._bytes + size) / self.max_bytes)
            if self.priority_enabled and pressure > self.watermarks[priority]:
                self.dropped += 1
                self.shed[priority] += 1
                return False
            self._items.append((item, size))
            self._bytes += size
            self._condition.notify()
            return True

    def get(self, timeout=0):
        deadline = time.monotonic() + timeout
        with self._condition:
            while not self._items:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self.closed:
                    raise queue.Empty
                self._condition.wait(remaining)
            item, size = self._items.popleft()
            self._bytes -= size
            return item

    def close(self):
        with self._condition:
            self.closed = True
            self._condition.notify_all()

    def discard(self):
        with self._condition:
            count = len(self._items)
            self.dropped += count
            self._items.clear()
            self._bytes = 0
            return count

    def snapshot(self):
        with self._condition:
            return {'depth': len(self._items), 'bytes': self._bytes, 'dropped': self.dropped,
                    'max_events': self.maxsize, 'max_bytes': self.max_bytes, 'drop_policy': self.drop_policy,
                    'shed': dict(self.shed)}

    def qsize(self):
        return self.snapshot()['depth']

    def empty(self):
        return self.qsize() == 0
