"""
Token-bucket rate limiter used by the RATE_LIMIT guardrail action.

One bucket is maintained per (policy_id, user_id) pair.
Bucket capacity and refill rate are derived from the policy rule
  "max_requests_per_minute" (default: 60).

When GUARDRAIL_REDIS_URL is set, limits are enforced with a Redis sliding-
window counter and are therefore consistent across every replica. Without
Redis, enforcement is per-process (sufficient for single-instance deployments).
"""

import logging
import os
import threading
import time
from typing import Dict, Optional

_log = logging.getLogger("rate_limiter")


class TokenBucket:
    """Thread-safe token bucket (in-process only)."""

    __slots__ = ("capacity", "refill_rate", "_tokens", "_last", "_lock")

    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate          # tokens added per second
        self._tokens = float(capacity)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, n: int = 1) -> bool:
        with self._lock:
            now = time.monotonic()
            self._tokens = min(
                self.capacity,
                self._tokens + (now - self._last) * self.refill_rate,
            )
            self._last = now
            if self._tokens >= n:
                self._tokens -= n
                return True
            return False

    @property
    def available(self) -> float:
        with self._lock:
            return self._tokens


class _RedisWindow:
    """
    Fixed-window counter backed by Redis INCR + EXPIRE.

    The window key includes the current UTC minute so it resets automatically.
    A 2-minute TTL is used so Redis doesn't accumulate stale keys indefinitely.
    When Redis is unreachable the check fails open (returns True) so a Redis
    outage never blocks legitimate traffic.
    """

    def __init__(self, redis_url: str):
        import redis as _redis  # optional; install with: pip install redis>=5.0.0
        self._client = _redis.from_url(
            redis_url,
            socket_connect_timeout=1,
            socket_timeout=1,
            decode_responses=True,
        )

    def check(self, key: str, max_per_minute: int) -> bool:
        window = int(time.time() // 60)          # current 1-minute bucket
        rkey = f"guardrail:rl:{key}:{window}"
        try:
            count = self._client.incr(rkey)
            if count == 1:
                self._client.expire(rkey, 120)  # 2-min TTL — window + grace
            return count <= max_per_minute
        except Exception as exc:
            _log.warning("Redis rate-limit check failed (failing open): %s", exc)
            return True                          # fail open — don't block traffic


class PolicyRateLimiter:
    """
    Per-(policy, user) rate limiting.

    Automatically uses Redis when GUARDRAIL_REDIS_URL is set, giving consistent
    enforcement across all replicas. Without Redis, falls back to in-process
    token buckets (suitable for single-instance deployments).

    Usage::
        limiter = PolicyRateLimiter()
        allowed = limiter.check(policy_id="…", user_id="u1", max_per_minute=60)
        if not allowed:
            # return RATE_LIMIT result
    """

    def __init__(self, redis_url: Optional[str] = None):
        url = redis_url or os.getenv("GUARDRAIL_REDIS_URL", "").strip() or None
        self._redis: Optional[_RedisWindow] = None
        if url:
            try:
                self._redis = _RedisWindow(url)
                # Log only the host portion — never log credentials.
                safe_host = url.split("@")[-1] if "@" in url else url
                _log.info(
                    "Rate limiter: Redis backend active (%s) — limits are "
                    "enforced consistently across all replicas.", safe_host
                )
            except Exception as exc:
                _log.warning(
                    "Rate limiter: Redis unavailable (%s) — falling back to "
                    "in-process token buckets. Limits will NOT be shared across "
                    "replicas until Redis is reachable.", exc
                )

        self._buckets: Dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def check(
        self,
        policy_id: str,
        user_id: Optional[str],
        max_per_minute: int = 60,
    ) -> bool:
        key = f"{policy_id}:{user_id or '__anon__'}"

        if self._redis is not None:
            return self._redis.check(key, max_per_minute)

        # In-process token bucket
        with self._lock:
            if key not in self._buckets:
                self._buckets[key] = TokenBucket(
                    capacity=max_per_minute,
                    refill_rate=max_per_minute / 60.0,
                )
        return self._buckets[key].consume()

    def purge_stale(self):
        """Remove in-process buckets for inactive users to prevent unbounded growth."""
        with self._lock:
            self._buckets.clear()


# Module-level singleton shared across all guardrail checks in this process
policy_rate_limiter = PolicyRateLimiter()
