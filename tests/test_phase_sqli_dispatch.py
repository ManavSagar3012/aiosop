"""AIOSOP-GOLDEN-001: sqli_http_scan phase dispatch tests (2026-08-30).

Verifies the VULNERABILITY_DISCOVERY phase-entry path in PhaseMonitor schedules
a sqli_http_scan task for login-form endpoints and skips non-form endpoints, and
that a graph-query failure does not break phase entry.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.config import AgentType, EngagementPhase
from ai_osop.core.models import ScopeDefinition, SessionState
from ai_osop.orchestrator.orchestrator import Orchestrator
from ai_osop.orchestrator.phase_monitor import PhaseMonitor


def _make_orch(endpoint_records=None) -> "tuple[Orchestrator, PhaseMonitor, SessionState]":
    """A real Orchestrator + PhaseMonitor with mocked graph/session memory."""
    session_memory = AsyncMock()
    graph_memory = AsyncMock()
    mcp_registry = MagicMock()
    mcp_registry._servers = {}
    llm_client = AsyncMock()

    orch = Orchestrator(session_memory, graph_memory, mcp_registry, llm_client)
    orch.rate_limiter = AsyncMock()
    orch.task_scheduler.schedule_task = AsyncMock()  # capture, don't persist

    # session_store is consulted for diff-auth; empty => skipped.
    orch.session_store = MagicMock()
    orch.session_store.list_sessions = AsyncMock(return_value=[])

    # _on_phase_enter queries assets, endpoints, and (new) login endpoints via
    # graph_memory.run_read_query. Default: no records.
    graph_memory.run_read_query = AsyncMock(
        return_value=endpoint_records if endpoint_records is not None else []
    )

    monitor = PhaseMonitor(orch)

    scope = ScopeDefinition(
        engagement_id="dispatch-test",
        domains=["target.example"],
        authorization_ref="/x",
    )
    session = SessionState(
        session_id="dispatch-eng",
        scope=scope,
        roe={},
        phase=EngagementPhase.VULNERABILITY_DISCOVERY.value,
        agents={},
        checkpoint_id=None,
        audit_log_position="0",
        authorization_confirmed=True,
    )
    return orch, monitor, session


def _scheduled_types(orch: Orchestrator) -> list:
    return [c.args[0].type for c in orch.task_scheduler.schedule_task.await_args_list]


def _scheduled_sqli(orch: Orchestrator) -> list:
    return [
        c.args[0]
        for c in orch.task_scheduler.schedule_task.await_args_list
        if c.args[0].type == "sqli_http_scan"
    ]


@pytest.mark.asyncio
async def test_schedules_sqli_scan_for_login_endpoint():
    """A /login endpoint schedules a sqli_http_scan with the right payload."""
    orch, monitor, session = _make_orch(endpoint_records=[{"url": "https://target.example/login"}])
    await monitor._on_phase_enter(session, EngagementPhase.VULNERABILITY_DISCOVERY)

    sqli_tasks = _scheduled_sqli(orch)
    assert len(sqli_tasks) == 1, f"scheduled: {_scheduled_types(orch)}"
    t = sqli_tasks[0]
    assert t.type == "sqli_http_scan"
    assert t.agent_type == AgentType.VULN_ANALYSIS
    assert t.payload["url"] == "https://target.example/login"
    assert t.payload["engagement_id"] == session.session_id


@pytest.mark.asyncio
async def test_skips_non_login_endpoints():
    """Endpoints without a login/auth-like path are NOT scanned."""
    orch, monitor, session = _make_orch(
        endpoint_records=[
            {"url": "https://target.example/api/users"},
            {"url": "https://target.example/health"},
        ]
    )
    await monitor._on_phase_enter(session, EngagementPhase.VULNERABILITY_DISCOVERY)
    assert _scheduled_sqli(orch) == []


@pytest.mark.asyncio
async def test_graph_query_failure_does_not_raise():
    """A failing login-endpoint graph query must not break phase entry."""
    orch, monitor, session = _make_orch()

    async def _boom(*a, **k):
        raise RuntimeError("graph down")

    orch.graph_memory.run_read_query = AsyncMock(side_effect=_boom)
    # Must not raise.
    await monitor._on_phase_enter(session, EngagementPhase.VULNERABILITY_DISCOVERY)


@pytest.mark.asyncio
async def test_dedupes_repeated_login_endpoints():
    """The same login URL is only scheduled once."""
    orch, monitor, session = _make_orch(
        endpoint_records=[
            {"url": "https://target.example/login"},
            {"url": "https://target.example/login"},
        ]
    )
    await monitor._on_phase_enter(session, EngagementPhase.VULNERABILITY_DISCOVERY)
    assert len(_scheduled_sqli(orch)) == 1


# ---------------------------------------------------------------------------
# BURP-COMMUNITY-001 (2026-08-31): edition-aware scan scheduling on phase entry
# ---------------------------------------------------------------------------


def _make_orch_with_edition(edition: str, scanner_available: bool):
    """Orchestrator whose mcp_registry answers get_version like a real Burp."""
    from ai_osop.mcp.protocol import MCPExecuteResponse

    orch, monitor, session = _make_orch(endpoint_records=[{"url": "https://target.example/login"}])

    async def _execute_tool(server_id, tool, params, **_):
        assert server_id == "burp-mcp"
        if tool == "get_version":
            return MCPExecuteResponse(
                request_id="r",
                status="success",
                result={
                    "edition": edition,
                    "version": "2026.4",
                    "scanner_available": scanner_available,
                    "collaborator_available": scanner_available,
                    "organizer_available": scanner_available,
                    "websocket_available": True,
                    "live_traffic": True,
                },
            )
        return MCPExecuteResponse(request_id="r", status="success", result={})

    orch.mcp_registry = MagicMock()
    orch.mcp_registry.execute_tool = AsyncMock(side_effect=_execute_tool)
    return orch, monitor, session


def _scheduled_by_type(orch, task_type: str) -> list:
    return [
        c.args[0]
        for c in orch.task_scheduler.schedule_task.await_args_list
        if c.args[0].type == task_type
    ]


@pytest.mark.asyncio
async def test_community_schedules_no_duplicate_web_audit():
    """Community with a live Burp: burp_scan runs web_audit INLINE (its routed
    active-scan engine), so phase entry must NOT schedule a standalone
    web_audit for the same asset — that would duplicate every probe."""
    orch, monitor, session = _make_orch_with_edition("COMMUNITY_EDITION", False)
    await monitor._on_phase_enter(session, EngagementPhase.VULNERABILITY_DISCOVERY)

    burp_tasks = _scheduled_by_type(orch, "burp_scan")
    assert len(burp_tasks) == 1
    assert _scheduled_by_type(orch, "web_audit") == []
    # Budget covers the inline engines: nuclei_mcp_timeout + web_audit + slack.
    from ai_osop.core.config import settings

    assert burp_tasks[0].timeout_seconds >= settings.nuclei_mcp_timeout + 600


@pytest.mark.asyncio
async def test_pro_schedules_burp_scan_plus_standalone_web_audit():
    """Pro: Burp's own scanner covers the audit, so the standalone web_audit
    differential sweep is still scheduled as its complement (pre-change
    behavior preserved)."""
    orch, monitor, session = _make_orch_with_edition("PROFESSIONAL_EDITION", True)
    await monitor._on_phase_enter(session, EngagementPhase.VULNERABILITY_DISCOVERY)

    assert len(_scheduled_by_type(orch, "burp_scan")) == 1
    assert len(_scheduled_by_type(orch, "web_audit")) == 1


@pytest.mark.asyncio
async def test_burp_down_still_schedules_full_web_audit_sweep():
    """burp-mcp unreachable: burp_scan degrades to internal_routed (with its
    minimal inline audit), so the standalone full max_urls=25 web_audit sweep
    IS scheduled to restore complete differential coverage."""
    orch, monitor, session = _make_orch(endpoint_records=[])

    # Force the capability probe to see a dead registry.
    async def _dead(*a, **k):
        raise ConnectionError("burp-mcp down")

    orch.mcp_registry = MagicMock()
    orch.mcp_registry.execute_tool = AsyncMock(side_effect=_dead)
    await monitor._on_phase_enter(session, EngagementPhase.VULNERABILITY_DISCOVERY)

    assert len(_scheduled_by_type(orch, "burp_scan")) == 1
    audits = _scheduled_by_type(orch, "web_audit")
    assert len(audits) == 1
    assert audits[0].payload["max_urls"] == 25
