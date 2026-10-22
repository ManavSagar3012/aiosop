"""MCP dispatch/cancellation may not authorize from a stale Redis task mirror."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import ScopeDefinition, SessionState, Task
from ai_osop.mcp.tool_budget import (
    check_cancellation_authorization,
    check_tool_authorization,
)
from ai_osop.memory.session_memory import SessionMemory


def memory_with_stale_redis(*, persisted_status="cancelled", persisted_payload=None):
    memory = SessionMemory.__new__(SessionMemory)
    engagement_id = "eng-mcp-db-fence"
    task_id = "task-mcp-db-fence"
    session = SessionState(
        session_id=engagement_id,
        scope=ScopeDefinition(
            engagement_id=engagement_id,
            domains=["example.com"],
            authorization_ref="trusted-signed-policy",
        ),
        phase="reconnaissance",
    )

    def task(status, payload):
        return Task(
            id=task_id, engagement_id=engagement_id,
            type="full_recon", agent_type=AgentType.RECON,
            status=status, payload=payload,
        )

    memory.load_session_state = AsyncMock(return_value=session)
    memory.load_task = AsyncMock(return_value=task(
        "running", {"_authorization_version": 1, "approval_id": "apr-cache-only"},
    ))
    memory.load_task_authoritative = AsyncMock(return_value=task(
        persisted_status,
        persisted_payload if persisted_payload is not None else {"_authorization_version": 1},
    ))
    memory.assert_signed_authorization = AsyncMock(return_value=SimpleNamespace(version=1))
    memory.is_task_approved = AsyncMock(return_value=True)
    return memory


@pytest.mark.asyncio
async def test_active_mcp_never_uses_stale_redis_running_state():
    memory = memory_with_stale_redis(persisted_status="cancelled")
    outcome = await check_tool_authorization(
        memory.consume_mcp_tool_budget,
        "scanner", "scan_target", {"url": "https://example.com"},
        {"engagement_id": "eng-mcp-db-fence", "task_id": "task-mcp-db-fence"},
    )
    assert outcome == "scope_denied"
    memory.load_task.assert_not_awaited()
    memory.load_task_authoritative.assert_awaited_once_with("task-mcp-db-fence")


@pytest.mark.asyncio
async def test_consequential_mcp_rechecks_authoritative_approval_identity():
    memory = memory_with_stale_redis(persisted_status="running")
    outcome = await check_tool_authorization(
        memory.consume_mcp_tool_budget,
        "scanner", "scan_target", {"url": "https://example.com"},
        {"engagement_id": "eng-mcp-db-fence", "task_id": "task-mcp-db-fence"},
        requires_approval=True,
    )
    assert outcome == "approval_required"
    memory.load_task.assert_not_awaited()
    assert memory.load_task_authoritative.await_count == 2
    memory.is_task_approved.assert_not_awaited()


@pytest.mark.asyncio
async def test_remote_stop_ignores_stale_redis_approval_grant():
    memory = memory_with_stale_redis(persisted_status="cancelled")
    outcome = await check_cancellation_authorization(
        memory.consume_mcp_tool_budget,
        "scanner", "scan_target", {"url": "https://example.com"},
        "eng-mcp-db-fence", "task-mcp-db-fence", requires_approval=True,
    )
    assert outcome == "approval_required"
    memory.load_task.assert_not_awaited()
    memory.load_task_authoritative.assert_awaited_once_with("task-mcp-db-fence")
    memory.is_task_approved.assert_not_awaited()


@pytest.mark.asyncio
async def test_db_task_read_failure_never_falls_back_to_redis():
    memory = memory_with_stale_redis(persisted_status="running")
    memory.load_task_authoritative.side_effect = ConnectionError("signed PostgreSQL unavailable")
    outcome = await check_tool_authorization(
        memory.consume_mcp_tool_budget,
        "scanner", "scan_target", {"url": "https://example.com"},
        {"engagement_id": "eng-mcp-db-fence", "task_id": "task-mcp-db-fence"},
    )
    assert outcome == "scope_unavailable"
    memory.load_task.assert_not_awaited()
