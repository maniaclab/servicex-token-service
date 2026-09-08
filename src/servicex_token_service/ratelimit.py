"""Per-subject in-memory sliding-window rate limiting.

Deliberately in-process, not shared across replicas: this exists to bound
abuse of this service's own /v1/redeem endpoint, not to protect a third
party's lockout policy (see the design doc's rate-limiting rationale), so
each replica tracking its own counter — making the effective limit roughly
max_events * replica_count under a multi-replica deployment — is an
acceptable approximation rather than a correctness bug worth the complexity
of shared-state (e.g. Redis-backed) rate limiting.
"""

from __future__ import annotations

import time
from collections import deque


class RateLimiter:
    """Sliding-window limiter: at most *max_events* per *window_seconds* per key."""

    def __init__(self, max_events: int, window_seconds: float) -> None:
        self._max_events = max_events
        self._window_seconds = window_seconds
        self._events: dict[str, deque[float]] = {}

    def try_acquire(self, key: str, now: float | None = None) -> float | None:
        """Record an event for *key* if allowed.

        Returns ``None`` when the event was admitted, or the number of
        seconds until a slot frees (a Retry-After value) when the key is
        over its limit — in which case nothing is recorded, so hammering
        while blocked never pushes the retry horizon out.

        *now* is injectable for deterministic tests; production callers
        leave it unset (monotonic clock).
        """
        if now is None:
            now = time.monotonic()
        events = self._events.setdefault(key, deque())
        while events and now - events[0] >= self._window_seconds:
            events.popleft()
        if len(events) >= self._max_events:
            return self._window_seconds - (now - events[0])
        events.append(now)
        return None
