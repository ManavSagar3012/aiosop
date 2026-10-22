"""Opt-in Redis quota reservation idempotency on an isolated loopback Redis."""

import asyncio
import hashlib
import os
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import urlparse

import pytest
import redis.asyncio as redis

from ai_osop.core.models import ScopeDefinition, SessionState
from ai_osop.memory.session_memory import SessionMemory


def _isolated_url() -> str:
    value = os.getenv("OSOP_MCP_QUOTA_TEST_REDIS_URL", "")
    if not value:
        pytest.skip("Dedicated Redis quota qualification service unavailable")
    parsed = urlparse(value)
    if (
        parsed.scheme != "redis" or parsed.hostname not in {"localhost", "127.0.0.1"}
        or parsed.port in {None, 6379, 6380} or parsed.path not in {"/13", "/14", "/15"}
    ):
        pytest.fail("Refusing non-disposable Redis quota service")
    return value


@pytest.fixture
async def quota():
    client = redis.from_url(_isolated_url(), decode_responses=True)
    engagement = "eng-quota-" + uuid.uuid4().hex[:20]
    session = SessionState(
        session_id=engagement, phase="reconnaissance",
        scope=ScopeDefinition(
            engagement_id=engagement,
            domains=["example.test"], authorization_ref="signed-test-policy",
        ),
        roe={
            "tool_call_budget_total": 1,
            "tool_call_budget_per_tool": 1,
            "tool_call_window_seconds": 3600,
        },
    )
    memory = SessionMemory.__new__(SessionMemory)
    memory.load_session_state = AsyncMock(return_value=session)
    memory.assert_signed_authorization = AsyncMock(return_value=SimpleNamespace(version=1))
    memory._ensure_redis = AsyncMock(return_value=client)
    try:
        yield memory, client, engagement
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_real_redis_same_remote_request_is_reserved_once_across_competing_workers(quota):
    memory, client, engagement = quota
    request = "req-same-provider-id-" + uuid.uuid4().hex[:8]
    attempts = await asyncio.gather(*[
        memory.consume_mcp_tool_budget(
            engagement, "provider.get_status", "agent-one", request_id=request
        ) for _ in range(12)
    ])
    assert attempts == [True] * 12
    eng_key = hashlib.sha256(engagement.encode()).hexdigest()[:24]
    assert await client.get(f"osop:tool-budget:{eng_key}:total") == "1"
    assert await client.ttl(f"osop:tool-budget:{eng_key}:total") > 0
    # A distinct consequential request cannot bypass the atomic total cap.
    assert not await memory.consume_mcp_tool_budget(
        engagement, "provider.get_status", "agent-one",
        request_id="req-second-" + uuid.uuid4().hex[:8],
    )
    assert await client.get(f"osop:tool-budget:{eng_key}:total") == "1"


@pytest.mark.asyncio
async def test_real_redis_quota_receipt_scope_does_not_debit_invalid_identity(quota):
    memory, client, engagement = quota
    with pytest.raises(ValueError, match="Invalid MCP quota request identity"):
        await memory.consume_mcp_tool_budget(
            engagement, "provider.get_status", "agent-one",
            request_id="foreign:unbounded:request",
        )
    eng_key = hashlib.sha256(engagement.encode()).hexdigest()[:24]
    assert await client.get(f"osop:tool-budget:{eng_key}:total") is None
