import time
from collections import defaultdict, deque
from .errors import RateLimited

class RateLimiter:
    """Sliding-window limiter (in-process). Use Redis-backed counters when running >1 worker."""
    def __init__(self, limit, window_seconds, clock=time.monotonic):
        self.limit, self.window, self.clock, self.hits = limit, window_seconds, clock, defaultdict(deque)
    def check(self, key):
        t, q = self.clock(), self.hits[key]
        while q and q[0] <= t - self.window: q.popleft()
        if len(q) >= self.limit: raise RateLimited(max(1, int(q[0] + self.window - t) + 1))
        q.append(t)
        if len(self.hits) > 10_000:
            for k in [k for k, v in self.hits.items() if not v]: del self.hits[k]
