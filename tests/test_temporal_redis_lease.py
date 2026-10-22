"""Opt-in real-Redis qualification of the Temporal ownership fence.

Run only against an explicitly supplied isolated Redis endpoint:
OSOP_TEST_REDIS_URL=redis://127.0.0.1:16390/15 pytest ...
No agent or MCP network calls occur in these tests.
"""

import asyncio
import os
import uuid

import pytest

from ai_osop.orchestrator.temporal_worker import (
    TaskActivities, _renew_execution_owner,
)
from tests.test_temporal_activity import authorized_worker


@pytest.fixture
async def isolated_redis():
    url = os.getenv("OSOP_TEST_REDIS_URL", "")
    if not url:
        pytest.skip("OSOP_TEST_REDIS_URL required for isolated Redis qualification")
    # Refuse an unspecified host/default production Redis configuration.
    from urllib.parse import urlsplit

    parsed = urlsplit(url)
    if parsed.hostname not in {"127.0.0.1", "localhost"} or parsed.port != 16390:
        pytest.fail("Isolated Temporal Redis tests require port 16390 on localhost")
    import redis.asyncio as redis

    client = redis.from_url(url, decode_responses=True, socket_timeout=2)
    try:
        await client.ping()
        yield client
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_real_redis_owner_fence_competes_and_prevents_stale_renewal(isolated_redis):
    key = "temporal:qualification:" + uuid.uuid4().hex
    owner = "owner-" + uuid.uuid4().hex
    other = "other-" + uuid.uuid4().hex
    try:
        assert await isolated_redis.set(key, owner, nx=True, ex=30) is True
        assert await isolated_redis.set(key, other, nx=True, ex=30) is None

        class Memory:
            async def _ensure_redis(self):
                return isolated_redis

        await _renew_execution_owner(Memory(), key, owner)
        assert await isolated_redis.ttl(key) > 0
        with pytest.raises(RuntimeError, match="expired or changed"):
            await _renew_execution_owner(Memory(), key, other)
        assert await isolated_redis.get(key) == owner
    finally:
        await isolated_redis.eval(
            'if redis.call("get",KEYS[1]) == ARGV[1] then '
            'return redis.call("del",KEYS[1]) else return 0 end',
            1, key, owner,
        )


@pytest.mark.asyncio
async def test_temporal_activity_uses_real_redis_fence_and_releases_it(isolated_redis):
    task, orch, activity = authorized_worker()
    task.id = "task-" + uuid.uuid4().hex[:16]
    key = f"temporal:execute:{task.engagement_id}:{task.id}"
    memory = orch.session_memory

    async def acquire_lock(name, owner, ttl_seconds):
        return bool(await isolated_redis.set(name, owner, nx=True, ex=ttl_seconds))

    async def release_lock(name, owner):
        return bool(await isolated_redis.eval(
            'if redis.call("get",KEYS[1]) == ARGV[1] then '
            'return redis.call("del",KEYS[1]) else return 0 end',
            1, name, owner,
        ))

    async def get_redis():
        return isolated_redis

    memory.acquire_lock.side_effect = acquire_lock
    memory.release_lock.side_effect = release_lock
    # Exercise real compare-and-EXPIRE renewal path without mocked renew_lock.
    delattr(memory, "renew_lock")
    memory._ensure_redis = get_redis
    try:
        result = await asyncio.wait_for(activity.execute_task_activity(task.model_dump()), 5)
        assert result["status"] == "success"
        assert await isolated_redis.exists(key) == 0
        assert memory.release_lock.await_count == 1
    finally:
        # This key is unique to this test and must not survive an assertion.
        await isolated_redis.delete(key)
