import asyncio
import time

import pytest

from ai_osop.safety.rate_limiter import RateLimiter, TokenBucket


@pytest.mark.asyncio
async def test_token_bucket_consume():
    bucket = TokenBucket(capacity=5, fill_rate=10.0)

    # Should consume immediately
    await bucket.consume(1)
    assert bucket.tokens <= 4.0

    # Drain the bucket
    await bucket.consume(4)
    assert bucket.tokens <= 0.0

    # Next consume should wait briefly
    start = time.monotonic()
    await bucket.consume(1)
    duration = time.monotonic() - start

    assert duration >= 0.05  # Should take ~0.1s to regenerate 1 token at 10/s


@pytest.mark.asyncio
async def test_rate_limiter_global():
    limiter = RateLimiter(global_rate=100.0, global_capacity=10)

    await limiter.acquire(target="test.com", tool="nmap")
    assert limiter.metrics["requests_total"] == 1
    assert "test.com" in limiter.target_buckets
    assert "nmap" in limiter.tool_buckets


def test_rate_limiter_backpressure():
    limiter = RateLimiter()

    # Initialize bucket by acquiring once
    asyncio.run(limiter.acquire(target="slow.com"))

    initial_fill_rate = limiter.target_buckets["slow.com"].fill_rate

    # Simulate slow response
    limiter.record_backpressure("slow.com", response_time=3.0)

    assert limiter.metrics["backpressure_events"] == 1
    new_fill_rate = limiter.target_buckets["slow.com"].fill_rate
    assert new_fill_rate < initial_fill_rate

    # Simulate fast response (recovery)
    limiter.record_backpressure("slow.com", response_time=0.1)
    recovered_fill_rate = limiter.target_buckets["slow.com"].fill_rate
    assert recovered_fill_rate > new_fill_rate


@pytest.mark.asyncio
async def test_rate_limiter_timeout_metric():
    limiter = RateLimiter(global_rate=1.0, global_capacity=1, acquire_timeout_seconds=0.01)

    await limiter.acquire()

    with pytest.raises(asyncio.TimeoutError):
        await limiter.acquire()

    assert limiter.metrics["timeouts_total"] == 1
