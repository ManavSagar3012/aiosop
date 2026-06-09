"""
Rate Limiter
Token bucket implementation for safety, rate limiting, and backpressure.
"""

import asyncio
import time
from typing import Dict, Optional


class TokenBucket:
    """A standard token bucket for rate limiting."""

    def __init__(self, capacity: int, fill_rate: float):
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        if fill_rate <= 0:
            raise ValueError("fill_rate must be positive")
        self.capacity = capacity
        self.tokens = float(capacity)
        self.fill_rate = fill_rate
        self.last_fill = time.monotonic()
        self.lock = asyncio.Lock()

    async def consume(self, tokens: int = 1) -> None:
        """Wait until `tokens` can be consumed from the bucket."""
        if tokens <= 0:
            raise ValueError("tokens must be positive")
        if tokens > self.capacity:
            raise ValueError("tokens cannot exceed bucket capacity")

        while True:
            async with self.lock:
                now = time.monotonic()
                elapsed = now - self.last_fill
                self.tokens = min(float(self.capacity), self.tokens + elapsed * self.fill_rate)
                self.last_fill = now

                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return

                wait_time = (tokens - self.tokens) / self.fill_rate

            await asyncio.sleep(wait_time)


class RateLimiter:
    """
    Manages token buckets for global, per-target, and per-tool limits.
    Implements queue-based backpressure.
    """

    def __init__(
        self,
        global_rate: float = 50.0,
        global_capacity: int = 100,
        target_rate: float = 10.0,
        target_capacity: int = 20,
        tool_rate: float = 5.0,
        tool_capacity: int = 10,
        acquire_timeout_seconds: Optional[float] = None,
    ):
        self.global_bucket = TokenBucket(global_capacity, global_rate)
        self.target_buckets: Dict[str, TokenBucket] = {}
        self.tool_buckets: Dict[str, TokenBucket] = {}

        self.default_target_rate = target_rate
        self.default_target_capacity = target_capacity
        self.default_tool_rate = tool_rate
        self.default_tool_capacity = tool_capacity
        self.acquire_timeout_seconds = acquire_timeout_seconds

        # Observable metrics (Prometheus-compatible)
        self.metrics = {
            "requests_total": 0,
            "rate_limited_total": 0,
            "backpressure_events": 0,
            "timeouts_total": 0,
        }

    async def acquire(self, target: Optional[str] = None, tool: Optional[str] = None) -> None:
        """Acquire permission to execute a task."""
        self.metrics["requests_total"] += 1

        try:
            if self.acquire_timeout_seconds is None:
                await self._acquire(target=target, tool=tool)
            else:
                await asyncio.wait_for(
                    self._acquire(target=target, tool=tool),
                    timeout=self.acquire_timeout_seconds,
                )
        except asyncio.TimeoutError:
            self.metrics["timeouts_total"] += 1
            raise

    async def _acquire(self, target: Optional[str], tool: Optional[str]) -> None:
        """Apply global, per-target, and per-tool token buckets."""
        before = time.monotonic()
        await self.global_bucket.consume(1)
        self._record_wait(before)

        if target:
            bucket = self.target_buckets.setdefault(
                target,
                TokenBucket(self.default_target_capacity, self.default_target_rate),
            )
            before = time.monotonic()
            await bucket.consume(1)
            self._record_wait(before)

        if tool:
            bucket = self.tool_buckets.setdefault(
                tool,
                TokenBucket(self.default_tool_capacity, self.default_tool_rate),
            )
            before = time.monotonic()
            await bucket.consume(1)
            self._record_wait(before)

    def _record_wait(self, started_at: float) -> None:
        if time.monotonic() - started_at > 0.001:
            self.metrics["rate_limited_total"] += 1

    def record_backpressure(self, target: str, response_time: float) -> None:
        """
        Queue-based backpressure: slow down when targets respond slowly.
        """
        if response_time > 2.0 and target in self.target_buckets:
            self.metrics["backpressure_events"] += 1
            bucket = self.target_buckets[target]
            # Reduce fill rate dynamically (throttle down to 1 request/sec max)
            bucket.fill_rate = max(1.0, bucket.fill_rate * 0.8)
        elif response_time < 0.5 and target in self.target_buckets:
            bucket = self.target_buckets[target]
            # Recover fill rate gradually
            bucket.fill_rate = min(self.default_target_rate, bucket.fill_rate * 1.1)
