"""Per-client request limits for the API: a token bucket per client address.

Off unless LOCKSTEP_RATE_LIMIT_PER_MINUTE is set. Meant for installs open to anyone, such as
the public demo, so one client can't use up a single app process's capacity. It's held in
memory, per process (each replica counts on its own), and remembers a bounded number of
addresses: when that's exceeded, the least recently seen are forgotten (they start again
with a full bucket).

The address is the one the app sees. Behind a reverse proxy, that's the client's only if the
proxy sets X-Forwarded-For and the app trusts it (uvicorn's --proxy-headers).
"""

from __future__ import annotations

import math
import time
from collections import OrderedDict
from typing import Callable


class RateLimiter:
    def __init__(self, per_minute: int, burst: int, max_clients: int = 10_000,
                 clock: Callable[[], float] = time.monotonic):
        if per_minute <= 0 or burst <= 0:
            raise ValueError("per_minute and burst must be positive")
        self.rate = per_minute / 60.0  # tokens per second
        self.burst = float(burst)
        self.max_clients = max_clients
        self.clock = clock
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()  # key -> (tokens, last)

    def check(self, key: str) -> float:
        """Take one token for `key`. Returns 0 if allowed, else the seconds until one is free."""
        now = self.clock()
        tokens, last = self._buckets.pop(key, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        wait = 0.0
        if tokens >= 1:
            tokens -= 1
        else:
            wait = (1 - tokens) / self.rate
        self._buckets[key] = (tokens, now)  # most recently seen last
        while len(self._buckets) > self.max_clients:
            self._buckets.popitem(last=False)
        return wait


def retry_after(wait: float) -> int:
    return max(1, math.ceil(wait))


class FailureThrottle:
    """Failed sign-ins per key (a client address, a user on a Vault): `max_failures` in
    `window` seconds and the key is refused until the oldest of them is older than the window.
    Always on (LOCKSTEP_SIGNIN_MAX_FAILURES, 0 turns it off); in memory, per process, bounded."""

    def __init__(self, max_failures: int, window: float, max_keys: int = 10_000,
                 clock: Callable[[], float] = time.monotonic):
        self.max_failures, self.window, self.max_keys, self.clock = max_failures, window, max_keys, clock
        self._fails: OrderedDict[str, list[float]] = OrderedDict()

    def _recent(self, key: str, now: float) -> list[float]:
        times = [t for t in self._fails.get(key, ()) if now - t < self.window]
        if times:
            self._fails[key] = times
        else:
            self._fails.pop(key, None)
        return times

    def wait(self, *keys: str) -> float:
        """0 if every key may try, else the seconds until all of them may."""
        if self.max_failures <= 0:
            return 0.0
        now = self.clock()
        waits = [self.window - (now - times[0]) for k in keys
                 if len(times := self._recent(k, now)) >= self.max_failures]
        return max(waits, default=0.0)

    def failed(self, *keys: str) -> None:
        if self.max_failures <= 0:
            return
        now = self.clock()
        for k in keys:
            times = self._recent(k, now)
            times.append(now)
            self._fails.pop(k, None)
            self._fails[k] = times[-self.max_failures:]  # most recently failed last
        while len(self._fails) > self.max_keys:
            self._fails.popitem(last=False)

    def succeeded(self, key: str) -> None:
        self._fails.pop(key, None)


_throttles: dict[tuple[int, float], FailureThrottle] = {}


def signin_throttle(max_failures: int, window: float) -> FailureThrottle:
    """The process's sign-in throttle for these settings."""
    return _throttles.setdefault((max_failures, window), FailureThrottle(max_failures, window))
