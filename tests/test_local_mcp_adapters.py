from unittest.mock import AsyncMock

import pytest

from ai_osop.adapters.attack_graph_mcp import AttackGraphMCPAdapter
from ai_osop.adapters.reporting_mcp import ReportingMCPAdapter
from ai_osop.adapters.session_memory_mcp import SessionMemoryMCPAdapter
from ai_osop.core.exceptions import MCPException
from ai_osop.core.models import AuditEvent, ScopeDefinition, SessionState
from ai_osop.reporting.exporters import ReportExporter


@pytest.mark.asyncio
async def test_attack_graph_mcp_get_stats() -> None:
    graph_memory = AsyncMock()
    graph_memory.get_graph_stats.return_value = {"assets": 1}

    adapter = AttackGraphMCPAdapter(graph_memory)

    assert await adapter.get_stats("eng-1") == {"assets": 1}


@pytest.mark.asyncio
async def test_session_memory_mcp_query_audit_log() -> None:
    session_memory = AsyncMock()
    event = AuditEvent(
        event_type="task_completed",
        severity="info",
        actor_type="agent",
        actor_id="agent-1",
        action={},
        result={},
        context={},
        engagement_id="eng-1",
    )
    session_memory.query_audit_log.return_value = [event]

    adapter = SessionMemoryMCPAdapter(session_memory)

    result = await adapter.query_audit_log("eng-1")

    assert result[0]["event_type"] == "task_completed"


@pytest.mark.asyncio
async def test_session_memory_mcp_store_session() -> None:
    session_memory = AsyncMock()
    session = SessionState(
        session_id="eng-1",
        scope=ScopeDefinition(engagement_id="eng-1"),
        roe={},
    )

    adapter = SessionMemoryMCPAdapter(session_memory)

    assert await adapter.store_session(session) == {"status": "success", "session_id": "eng-1"}
    session_memory.store_session_state.assert_awaited_once()
    session_memory.persist_session_state.assert_awaited_once()


@pytest.mark.asyncio
async def test_reporting_mcp_template_allowlist(tmp_path) -> None:
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "executive.md.j2").write_text("Executive {{ engagement_id }}")
    exporter = ReportExporter(str(template_dir))
    adapter = ReportingMCPAdapter(exporter)

    rendered = await adapter.render_markdown("executive.md.j2", {"engagement_id": "eng-1"})

    assert rendered["content"] == "Executive eng-1"
    with pytest.raises(MCPException):
        await adapter.render_markdown("../secret", {})
