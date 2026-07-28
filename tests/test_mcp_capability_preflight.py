"""Regression tests for scheduler-side MCP capability contracts."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.enums import AgentType
from ai_osop.core.models import MCPToolRequirement, Task
from ai_osop.mcp.protocol import MCPRegistry
from ai_osop.orchestrator.task_scheduler import TaskScheduler


class _Connection:
    def __init__(self, initialized: bool, tools: tuple[str, ...] = ()) -> None:
        self._initialized = initialized
        self._tools = {tool: object() for tool in tools}


def test_registry_distinguishes_missing_tools_from_lazy_connections() -> None:
    registry = MCPRegistry()
    registry._servers = {
        "ready": _Connection(True, ("execute",)),
        "cold": _Connection(False),
    }

    assert registry.check_tool_requirements(
        [("ready", "execute"), ("ready", "missing"), ("cold", "execute"), ("absent", "x")]
    ) == [
        {"server_id": "ready", "tool_name": "execute", "state": "available"},
        {"server_id": "ready", "tool_name": "missing", "state": "tool_missing"},
        {"server_id": "cold", "tool_name": "execute", "state": "unknown"},
        {"server_id": "absent", "tool_name": "x", "state": "server_missing"},
    ]


def _scheduler(registry: MCPRegistry) -> TaskScheduler:
    orch = SimpleNamespace(
        mcp_registry=registry,
        _sessions={},
        _agents={},
        session_memory=SimpleNamespace(),
    )
    return TaskScheduler(orch)


def test_scheduler_rejects_initialized_server_missing_required_tool() -> None:
    registry = MCPRegistry()
    registry._servers = {"browser-mcp": _Connection(True)}
    task = Task(
        type="capture_authenticated_surface", agent_type=AgentType.WORKFLOW, engagement_id="eng-x"
    )

    failure = _scheduler(registry)._mcp_capability_failure(task)

    assert failure == {
        "error": "MCP tool contract unavailable: browser-mcp/execute (tool_missing)",
        "error_type": "MCPToolContractUnavailable",
    }
    assert TaskScheduler._is_non_retryable(failure)


def test_scheduler_allows_lazy_mcp_reconnect_and_explicit_contracts() -> None:
    registry = MCPRegistry()
    registry._servers = {
        "browser-mcp": _Connection(False),
        "oast-mcp": _Connection(True, ("oast_register",)),
    }
    task = Task(
        type="capture_authenticated_surface",
        agent_type=AgentType.WORKFLOW,
        engagement_id="eng-x",
        mcp_requirements=[MCPToolRequirement(server_id="oast-mcp", tool_name="oast_register")],
    )

    assert _scheduler(registry)._mcp_capability_failure(task) is None


@pytest.mark.asyncio
async def test_non_retryable_failure_is_terminalized_on_first_attempt() -> None:
    scheduler = _scheduler(MCPRegistry())
    task = Task(
        type="capture_authenticated_surface", agent_type=AgentType.WORKFLOW, engagement_id="eng-x"
    )
    scheduler._orch.graph_memory = SimpleNamespace(upsert_task=AsyncMock())
    scheduler._orch.session_memory.store_task = AsyncMock()
    scheduler._orch.coordination_bus = SimpleNamespace(publish=AsyncMock())
    scheduler._orch.dlq = SimpleNamespace(enqueue=AsyncMock())
    scheduler._orch._tasks = {}
    scheduler._orch._audit_log = AsyncMock()

    await scheduler._on_task_failure(
        task,
        {
            "error": "MCP tool contract unavailable: browser-mcp/execute (tool_missing)",
            "error_type": "MCPToolContractUnavailable",
        },
    )

    assert task.status == "failed"
    scheduler._orch.dlq.enqueue.assert_awaited_once()
