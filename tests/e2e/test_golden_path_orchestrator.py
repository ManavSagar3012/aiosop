"""AIOSOP orchestrator-driven golden path E2E (2026-08-30).

One level deeper than tests/e2e/test_golden_path_finding.py: a real Orchestrator
carries a sqli_http_scan task through its scheduler + a real VulnAnalysisAgent,
producing a VALIDATED finding from the deliberately-vulnerable target.

This is the product claim, end-to-end, through the actual pipeline plumbing:
  create engagement -> schedule task via orchestrator -> real agent executes
  -> finding minted + persisted to the findings ledger.
"""

import asyncio
import socket
import sys
import threading
import time
from unittest.mock import AsyncMock, MagicMock

import pytest
import requests

sys.path.insert(0, ".")
sys.path.insert(0, "src")

from golden_path_target import run_golden_path_server

from ai_osop.agents.base import AgentContext
from ai_osop.agents.vuln_agent import VulnAnalysisAgent
from ai_osop.core.config import AgentType, EngagementPhase
from ai_osop.core.findings_ledger import get_findings_ledger
from ai_osop.core.models import ScopeDefinition, Task
from ai_osop.orchestrator.orchestrator import Orchestrator


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def target_url():
    """Start the golden-path target on a dynamic port in a thread."""
    port = _free_port()
    server = run_golden_path_server(port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://localhost:{port}"
    # Wait for it to accept.
    for _ in range(20):
        try:
            if requests.get(f"{base}/health", timeout=2).status_code == 200:
                break
        except requests.RequestException:
            time.sleep(0.2)
    yield base
    server.shutdown()
    thread.join(timeout=5)


async def _make_orchestrator_with_agent() -> "tuple[Orchestrator, str]":
    """A real Orchestrator with a real VulnAnalysisAgent registered."""
    session_memory = AsyncMock()
    graph_memory = AsyncMock()
    graph_memory.run_read_query = AsyncMock(return_value=[])
    mcp_registry = MagicMock()
    mcp_registry._servers = {}
    llm_client = AsyncMock()

    orch = Orchestrator(session_memory, graph_memory, mcp_registry, llm_client)
    orch.rate_limiter = AsyncMock()

    ctx = AgentContext(
        agent_id="vuln-orch-golden",
        agent_type=AgentType.VULN_ANALYSIS,
        session_id="orch-golden-eng",
        session_memory=session_memory,
        graph_memory=graph_memory,
        vector_memory=AsyncMock(),
        llm_client=llm_client,
        mcp_registry=mcp_registry,
        rate_limiter=AsyncMock(),
        threat_intel_adapter=None,
        audit_callback=None,
        coordination_bus=None,
    )
    ctx.mcp_registry._servers = {}
    ctx.session_memory.get_session_state = AsyncMock(return_value=None)
    ctx.session_memory.load_session_state = AsyncMock(return_value=None)
    agent = VulnAnalysisAgent(ctx)
    await agent._setup_resources()
    # Mark idle so the scheduler's _find_available_agent will claim it.
    agent.ctx.status = "idle"
    orch.state.register_agent(agent)
    orch._agents[agent.ctx.agent_id] = agent
    return orch, "vuln-orch-golden"


@pytest.mark.asyncio
async def test_orchestrator_drives_golden_path_to_validated_finding(target_url: str):
    """The orchestrator's task path delivers a VALIDATED finding from the target."""
    # Clear the ledger for a clean funnel.
    ledger = get_findings_ledger()
    ledger.clear()

    orch, _agent_id = await _make_orchestrator_with_agent()

    # Create + authorize the engagement.
    scope = ScopeDefinition(
        engagement_id="orch-golden-eng",
        domains=[target_url.replace("http://", "").split(":")[0]],
        authorization_ref="/x/roe",
    )
    session = await orch.create_engagement(scope, {})
    session.authorization_confirmed = True

    # Schedule the sqli_http_scan through the real orchestrator.
    task = Task(
        type="sqli_http_scan",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"url": f"{target_url}/login", "engagement_id": session.session_id},
        engagement_id=session.session_id,
        scope_check=False,
    )
    scheduled = await orch.task_scheduler.schedule_task(task)
    # Dispatch deterministically through the scheduler's agent-execution path
    # (the same `_execute_via_agent` the background `_assign_task` uses).
    agent = orch._agents["vuln-orch-golden"]
    await orch.task_scheduler._execute_via_agent(agent, scheduled)

    # The real agent executed it -> task terminal + result persisted.
    result = scheduled.result or {}
    assert scheduled.status in ("completed", "success"), f"task status: {scheduled.status}"
    assert result.get("injectable") is True, f"not injectable: {result}"
    assert result.get("findings_count") == 1, f"findings_count: {result}"

    finding = result["findings"][0]
    assert finding["vuln_type"] == "sqli"
    assert finding.get("validated") is True, "finding not validated"

    # Ledger recorded the proposal.
    funnel = ledger.funnel_for(session.session_id)
    assert funnel["by_status"].get("PROPOSED", 0) >= 1, f"ledger: {funnel}"

    # The dispatch path also works: entering VULNERABILITY_DISCOVERY with a
    # /login endpoint schedules a sqli_http_scan task.
    orch.graph_memory.run_read_query = AsyncMock(
        return_value=[{"url": f"{target_url}/login"}]
    )
    await orch.phase_monitor._on_phase_enter(session, EngagementPhase.VULNERABILITY_DISCOVERY)
    scheduled_types = [
        t.type
        for t in orch.state.get_all_tasks().values()
        if t.engagement_id == session.session_id
    ]
    assert "sqli_http_scan" in scheduled_types, f"scheduled: {scheduled_types}"
