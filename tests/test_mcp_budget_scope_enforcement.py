"""Engagement MCP quota accounting remains bounded by signed ROE windows."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.models import ScopeDefinition, SessionState
from ai_osop.memory.session_memory import SessionMemory


def _memory(*, end=None, phase="reconnaissance", signed=True, scoped=True, roe=None):
    session = SessionState(
        session_id="eng-budget",
        phase=phase,
        scope=ScopeDefinition(
            engagement_id="eng-budget",
            domains=["example.com"] if scoped else [],
            authorization_ref="signed-roe" if signed else None,
            testing_window_end=end,
        ),
        roe=roe or {},
    )
    mem = SessionMemory.__new__(SessionMemory)
    mem.load_session_state = AsyncMock(return_value=session)
    # Simulate a separately verified PostgreSQL signed authorization; a
    # printable authorization_ref alone is not sufficient for dispatch.
    mem.assert_signed_authorization = AsyncMock(return_value=SimpleNamespace(version=1))
    redis = AsyncMock()
    redis.eval.return_value = 1
    mem._ensure_redis = AsyncMock(return_value=redis)
    return mem, redis


@pytest.mark.asyncio
async def test_active_signed_engagement_without_numeric_quota_is_allowed():
    memory, redis = _memory()
    assert await memory.consume_mcp_tool_budget("eng-budget", "scanner.scan")
    redis.eval.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("limited", [False, True])
async def test_expired_roes_deny_direct_mcp_calls_even_without_budget_limit(limited):
    memory, redis = _memory(
        end=datetime.now(timezone.utc) - timedelta(seconds=10),
        roe={"tool_call_budget_total": 10} if limited else {},
    )
    assert not await memory.consume_mcp_tool_budget("eng-budget", "scanner.scan")
    redis.eval.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "conditions",
    [
        {"phase": "halted"},
        {"phase": "completed"},
        {"signed": False},
        {"scoped": False},
    ],
)
async def test_unusable_engagement_cannot_consume_mcp_calls(conditions):
    memory, redis = _memory(**conditions)
    assert not await memory.consume_mcp_tool_budget("eng-budget", "scanner.scan")
    redis.eval.assert_not_awaited()


@pytest.mark.asyncio
async def test_missing_identity_is_denied_and_explicit_bootstrap_is_exempt():
    memory, redis = _memory()
    assert not await memory.consume_mcp_tool_budget("", "scanner.scan")
    assert await memory.consume_mcp_tool_budget("api-bootstrap", "internal.health")
    memory.load_session_state.assert_not_awaited()
    redis.eval.assert_not_awaited()


@pytest.mark.asyncio
async def test_live_bounded_engagement_reserves_atomic_redis_quota_once():
    memory, redis = _memory(
        roe={"tool_call_budget_total": 5, "tool_call_budget_per_tool": 2}
    )
    assert await memory.consume_mcp_tool_budget(
        "eng-budget", "scanner.scan", "agent-recon"
    )
    args = redis.eval.await_args.args
    assert args[1] == 2
    assert args[4:] == (5, 2, 3600)
    assert "tool-budget:" in args[2]
    assert "tool-budget:" in args[3]


@pytest.mark.asyncio
async def test_revoked_signature_never_consumes_mcp_quota():
    memory, redis = _memory(roe={"tool_call_budget_total": 5})
    memory.assert_signed_authorization.side_effect = RuntimeError("revoked")
    assert await memory.consume_mcp_tool_budget("eng-budget", "scanner.scan") is False
    redis.eval.assert_not_awaited()
