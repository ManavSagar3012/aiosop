"""Real SessionMemory MCP dispatch refuses revoked or stale signed scopes."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import ScopeDefinition, SessionState, Task
from ai_osop.mcp.tool_budget import check_tool_authorization
from ai_osop.memory.session_memory import SessionMemory


class BoundMemory(SessionMemory):
    async def consume_mcp_tool_budget(self, engagement_id, tool_name, agent_id=None):
        return await self._mock_quota(engagement_id, tool_name, agent_id)


def authorized_memory(*, version=1):
    memory = BoundMemory.__new__(BoundMemory)
    memory.load_session_state = AsyncMock(
        return_value=SessionState(
            session_id="eng-signed-mcp",
            scope=ScopeDefinition(
                engagement_id="eng-signed-mcp",
                domains=["example.test"],
                authorization_ref="auth-test",
            ),
            phase="reconnaissance",
        )
    )
    memory.assert_signed_authorization = AsyncMock(
        return_value=SimpleNamespace(version=version)
    )
    memory.load_task_authoritative = AsyncMock(
        return_value=Task(
            id="task-signed-mcp",
            type="full_recon",
            agent_type=AgentType.RECON,
            engagement_id="eng-signed-mcp",
            status="running",
            payload={"domain": "example.test", "_authorization_version": 1},
        )
    )
    # Production signed gates must never consult a stale Redis-backed reader.
    memory.load_task = AsyncMock(side_effect=AssertionError("Redis task cache is not authority"))
    memory.is_task_approved = AsyncMock(return_value=False)
    memory._mock_quota = AsyncMock(return_value=True)
    return memory


@pytest.mark.asyncio
async def test_revocation_denies_target_before_quota_admission():
    memory = authorized_memory()
    memory.assert_signed_authorization.side_effect = RuntimeError("revoked")
    denied = await check_tool_authorization(
        memory.consume_mcp_tool_budget, "scanner", "scan_target",
        {"url": "https://example.test/"}, {"engagement_id": "eng-signed-mcp",
                                            "task_id": "task-signed-mcp"},
    )
    assert denied == "scope_unavailable"
    memory.load_task.assert_not_awaited()
    memory.load_task_authoritative.assert_not_awaited()
    memory._mock_quota.assert_not_awaited()


@pytest.mark.asyncio
async def test_newly_signed_version_does_not_authorize_stale_task():
    memory = authorized_memory(version=2)
    denied = await check_tool_authorization(
        memory.consume_mcp_tool_budget, "scanner", "scan_target",
        {"url": "https://example.test/"}, {"engagement_id": "eng-signed-mcp",
                                            "task_id": "task-signed-mcp"},
    )
    assert denied == "scope_denied"
    memory.load_task_authoritative.assert_awaited_once_with("task-signed-mcp")
    memory.load_task.assert_not_awaited()
    memory._mock_quota.assert_not_awaited()


@pytest.mark.asyncio
async def test_unchanged_signed_version_allows_only_scoped_passive_tool():
    memory = authorized_memory()
    permitted = await check_tool_authorization(
        memory.consume_mcp_tool_budget, "scanner", "scan_target",
        {"url": "https://example.test/"}, {"engagement_id": "eng-signed-mcp",
                                            "task_id": "task-signed-mcp"},
    )
    assert permitted is None
    denied = await check_tool_authorization(
        memory.consume_mcp_tool_budget, "scanner", "scan_target",
        {"url": "https://outside.invalid/"}, {"engagement_id": "eng-signed-mcp",
                                               "task_id": "task-signed-mcp"},
    )
    assert denied == "scope_denied"


@pytest.mark.asyncio
@pytest.mark.parametrize("tool,arguments", [
    ("scan_target", {"target": "https://example.test"}),
    ("get_status", {"target": "https://example.test"}),
    ("run_shell", {}),
    ("get_status", {"request": "GET / HTTP/1.1\r\nHost:example.test"}),
])
async def test_bootstrap_does_not_grant_any_target_or_effect(tool, arguments):
    denied = await check_tool_authorization(
        None, "mcp", tool, arguments, {"engagement_id": "api-bootstrap"},
    )
    assert denied == "scope_denied"
