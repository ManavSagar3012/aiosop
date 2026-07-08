import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.config import AgentType, VulnClass
from ai_osop.core.models import ScopeDefinition, SessionState, Task
from ai_osop.orchestrator.orchestrator import EngagementPhase, Orchestrator
from ai_osop.orchestrator.phase_monitor import PhaseMonitor
from ai_osop.orchestrator.task_scheduler import TaskScheduler


@pytest.fixture
def mock_orchestrator():
    session_memory = AsyncMock()
    graph_memory = AsyncMock()
    mcp_registry = AsyncMock()
    llm_client = AsyncMock()

    orch = Orchestrator(session_memory, graph_memory, mcp_registry, llm_client)
    orch.rate_limiter = AsyncMock()
    graph_memory.run_read_query = AsyncMock(return_value=[])

    # Mock coordination_bus publish
    orch.coordination_bus = AsyncMock()

    return orch


@pytest.fixture
def dummy_scope():
    return ScopeDefinition(
        engagement_id="test-eng", domains=["example.com"], approval_required_for=["rce"]
    )


@pytest.mark.asyncio
async def test_phase_monitor_schedules_tech_specific_scanners(mock_orchestrator, dummy_scope):
    """Verify PhaseMonitor schedules target-technology-specific scanners."""
    session = SessionState(
        session_id="test-session",
        scope=dummy_scope,
        roe={},
        phase=EngagementPhase.RECONNAISSANCE.value,
        agents={},
        checkpoint_id=None,
        audit_log_position="0",
    )

    # 1. Test target-specific technology (Django)
    # Match the query in phase_monitor.py: e.url, e.query_keys, e.method, e.technologies
    mock_orchestrator.graph_memory.run_read_query.side_effect = lambda query, params: (
        # Return Django endpoint record for the param query (SQLi/XSS/injection targets)
        [
            {
                "url": "http://example.com/search?q=1",
                "query_keys": ["q"],
                "method": "GET",
                "technologies": ["django"],
            }
        ]
        if "size(coalesce(e.query_keys" in query
        else []  # Return empty for the other queries (assets, endpoints with status_code)
    )

    scheduled_tasks = []

    async def capture_schedule(task):
        scheduled_tasks.append(task)
        return task

    mock_orchestrator.task_scheduler.schedule_task = capture_schedule

    phase_monitor = PhaseMonitor(mock_orchestrator)
    await phase_monitor._on_phase_enter(session, EngagementPhase.VULNERABILITY_DISCOVERY)

    # We expect:
    # - sqli_scan (from baseline injection targets)
    # - xss_scan (from baseline injection targets)
    # - ssti_scan (from Django techrecommendation: ssti)
    # - csrf_scan (from Django tech recommendation: csrf)
    # - pollution_scan (from Django tech recommendation: deserialization -> pollution_scanner)
    task_types = [t.type for t in scheduled_tasks]
    assert "sqli_scan" in task_types
    assert "xss_scan" in task_types
    assert "ssti_scan" in task_types
    assert "csrf_scan" in task_types
    assert "pollution_scan" in task_types

    # Should not schedule SSRF or JWT for Django since they are not recommended
    assert "ssrf_scan" not in task_types
    assert "jwt_scan" not in task_types


@pytest.mark.asyncio
async def test_phase_monitor_fallback_scanners(mock_orchestrator, dummy_scope):
    """Verify PhaseMonitor falls back to minimal high-value subset (CSRF, JWT) if no tech is identified."""
    session = SessionState(
        session_id="test-session",
        scope=dummy_scope,
        roe={},
        phase=EngagementPhase.RECONNAISSANCE.value,
        agents={},
        checkpoint_id=None,
        audit_log_position="0",
    )

    # 2. Test empty technologies (falls back to CSRF, JWT)
    mock_orchestrator.graph_memory.run_read_query.side_effect = lambda query, params: (
        [
            {
                "url": "http://example.com/search?q=1",
                "query_keys": ["q"],
                "method": "GET",
                "technologies": [],
            }
        ]
        if "size(coalesce(e.query_keys" in query
        else []
    )

    scheduled_tasks = []

    async def capture_schedule(task):
        scheduled_tasks.append(task)
        return task

    mock_orchestrator.task_scheduler.schedule_task = capture_schedule

    phase_monitor = PhaseMonitor(mock_orchestrator)
    await phase_monitor._on_phase_enter(session, EngagementPhase.VULNERABILITY_DISCOVERY)

    task_types = [t.type for t in scheduled_tasks]
    assert "sqli_scan" in task_types
    assert "xss_scan" in task_types
    # Fallback subset
    assert "csrf_scan" in task_types
    assert "jwt_scan" in task_types
    # Minimal fallback -> SSTI and SSRF should not be scheduled
    assert "ssti_scan" not in task_types
    assert "ssrf_scan" not in task_types


@pytest.mark.asyncio
async def test_task_scheduler_chains_next_steps(mock_orchestrator):
    """Verify TaskScheduler._on_task_success schedules next steps with priority 9."""
    task = Task(
        id="task-123",
        type="xss_scan",
        priority=8,
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"url": "http://example.com/inject"},
        engagement_id="test-session",
    )

    scheduled_tasks = []

    async def capture_schedule(t):
        scheduled_tasks.append(t)
        return t

    scheduler = TaskScheduler(mock_orchestrator)
    scheduler.schedule_task = capture_schedule

    # Successful vulnerability result
    result = {"status": "vulnerable", "evidence": "XSS confirmed"}

    await scheduler._on_task_success(task, result)

    # xss next steps recommendation: csrf, jwt_abuse, authentication_weakness
    # Which map to: csrf_scan, jwt_scan, saml_scan
    # All of these should be scheduled with priority 9 targeting the same URL
    assert len(scheduled_tasks) == 3
    for follow_up in scheduled_tasks:
        assert follow_up.priority == 9
        assert follow_up.payload["url"] == "http://example.com/inject"
        assert follow_up.engagement_id == "test-session"

    scheduled_types = {t.type for t in scheduled_tasks}
    assert "csrf_scan" in scheduled_types
    assert "jwt_scan" in scheduled_types
    assert "saml_scan" in scheduled_types


@pytest.mark.asyncio
async def test_task_scheduler_does_not_chain_if_not_vulnerable(mock_orchestrator):
    """Verify TaskScheduler does not schedule follow-up tasks if result is not vulnerable."""
    task = Task(
        id="task-123",
        type="xss_scan",
        priority=8,
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"url": "http://example.com/inject"},
        engagement_id="test-session",
    )

    scheduled_tasks = []

    async def capture_schedule(t):
        scheduled_tasks.append(t)
        return t

    scheduler = TaskScheduler(mock_orchestrator)
    scheduler.schedule_task = capture_schedule

    # Success/clean scan result
    result = {"status": "success", "message": "no vulnerabilities found"}

    await scheduler._on_task_success(task, result)

    # No follow-up tasks should be scheduled
    assert len(scheduled_tasks) == 0
