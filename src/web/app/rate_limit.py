"""In-memory sliding-window rate limiter (no Redis needed for the prototype).

Good enough for a single Railway instance. If the app ever scales past one
instance, swap this for a shared store.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allowed(self, key: str) -> bool:
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] > self.window_seconds:
            hits.popleft()
        if len(hits) >= self.max_requests:
            return False
        hits.append(now)
        return True

    def check(self, key: str) -> bool:
        """Check without recording. For atomic multi-limiter checks."""
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] > self.window_seconds:
            hits.popleft()
        return len(hits) < self.max_requests

    def record(self, key: str) -> None:
        """Record a hit. Call only after check() passes."""
        self._hits[key].append(time.monotonic())

    def remaining(self, key: str) -> int:
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] > self.window_seconds:
            hits.popleft()
        return max(0, self.max_requests - len(hits))
