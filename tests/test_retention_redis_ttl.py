"""Retention-service Redis TTL audit tests (mocked Redis — no live server needed)."""

import pytest

from ai_osop.memory.retention_service import RetentionService


class _FakeRedis:
    """In-memory stand-in exposing scan_iter/ttl/expire with real semantics."""

    def __init__(self, keys_with_ttl):
        # keys_with_ttl: dict of str key -> ttl seconds (None meaning no TTL).
        self._data = {k: v for k, v in keys_with_ttl.items()}
        self.expired = {}  # key -> seconds set by expire()

    async def scan_iter(self, match="*", count=100):
        prefix = match.rstrip("*")
        for k in list(self._data.keys()):
            if k.startswith(prefix):
                yield k.encode()

    async def ttl(self, key):
        k = key.decode() if isinstance(key, bytes) else key
        v = self._data.get(k)
        return -1 if v is None else v

    async def expire(self, key, seconds):
        k = key.decode() if isinstance(key, bytes) else key
        self.expired[k] = seconds
        return True


class _StubSessionMemory:
    def __init__(self, redis):
        self._redis = redis


@pytest.mark.asyncio
async def test_audit_redis_ttl_sets_ttl_on_missing_keys():
    fake = _FakeRedis(
        {
            "task:1": None,          # no TTL -> should be set
            "task:2": 3600,          # healthy TTL -> untouched
            "session:abc": None,      # no TTL -> should be set
            "approval:x": None,       # no TTL -> should be set
        }
    )
    svc = RetentionService(graph_memory=None, session_memory=_StubSessionMemory(fake))
    results = await svc._audit_redis_ttl()

    assert results["total_keys_scanned"] == 4
    assert results["keys_without_ttl"] == 3
    assert results["ttl_set"] == 3
    assert set(fake.expired.keys()) == {"task:1", "session:abc", "approval:x"}
    assert fake.expired["task:1"] != fake.expired["session:abc"]  # different TTL classes


@pytest.mark.asyncio
async def test_audit_redis_ttl_no_redis_is_noop():
    svc = RetentionService(graph_memory=None, session_memory=_StubSessionMemory(None))
    assert await svc._audit_redis_ttl() == {"error": "redis_not_connected"}
