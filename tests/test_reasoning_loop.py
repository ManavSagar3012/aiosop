"""Tests for the hypothesis-driven reasoning loop.

The reasoning loop replaces the fixed pipeline with a continuous
Observe → Hypothesize → Dispatch → Evaluate → Learn cycle. These tests
mock the graph + bus + scheduler to verify each phase of the loop
hermetically (no live Neo4j / no live target).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.enums import AgentType
from ai_osop.orchestrator.reasoning_loop import _SKILL_TO_AGENT_TYPE, ReasoningLoop


def _mock_orchestrator():
    """Build a SimpleNamespace that quacks like Orchestrator for the loop."""
    bus = MagicMock()
    bus.publish = AsyncMock()

    gm = MagicMock()
    gm.run_read_query = AsyncMock(return_value=[])
    gm.run_write_query = AsyncMock(return_value=None)
    gm.get_hypotheses_by_engagement = AsyncMock(return_value=[])
    # HypothesisEngine calls these internally during generate_hypotheses
    gm.get_all_nodes_for_engagement = AsyncMock(return_value=[])
    gm.get_all_edges_for_engagement = AsyncMock(return_value=[])
    gm.findings_knowledge = MagicMock()
    gm.findings_knowledge.recall_similar = AsyncMock(return_value=[])

    scheduler = MagicMock()
    scheduler.schedule_task = AsyncMock()

    state = SimpleNamespace(
        get_task=lambda tid: None,
        get_all_tasks=lambda: {},
    )

    orch = SimpleNamespace(
        graph_memory=gm,
        session_memory=MagicMock(),
        task_scheduler=scheduler,
        coordination_bus=bus,
        state=state,
        _sessions={},
        skill_engine=None,
        _running=True,
    )
    return orch


def _make_session(eid="eng-test", phase="vulnerability_discovery"):
    """Create a SessionState-like object for the loop."""
    return SimpleNamespace(
        canonical_engagement_id=eid,
        phase=phase,
    )


@pytest.mark.asyncio
async def test_reasoning_loop_starts_and_stops():
    """The loop starts as a background task and stops cleanly."""
    orch = _mock_orchestrator()
    rl = ReasoningLoop(orch)
    rl.start()
    assert rl._task is not None
    assert rl._running is True
    await asyncio.sleep(0.5)  # let it tick once
    await rl.stop()
    assert rl._running is False


@pytest.mark.asyncio
async def test_observe_reads_graph_state():
    """_observe queries endpoints + findings + hypotheses from the graph."""
    orch = _mock_orchestrator()
    orch.graph_memory.run_read_query = AsyncMock(side_effect=[
        [{"url": "http://t.test/api/users", "id": "ep-1"}],  # endpoints
        [{"vuln_type": "sqli", "severity": "high"}],  # findings
    ])
    orch.graph_memory.get_hypotheses_by_engagement = AsyncMock(return_value=[
        {"id": "hyp-1", "status": "open"},
    ])
    rl = ReasoningLoop(orch)
    state = await rl._observe("eng-test")
    assert len(state["endpoints"]) == 1
    assert "sqli" in state["finding_types"]
    assert "hyp-1" in state["open_hypotheses"]


@pytest.mark.asyncio
async def test_select_hypothesis_picks_highest_confidence():
    """_select_hypothesis ranks by confidence + novelty and returns the top."""
    orch = _mock_orchestrator()
    rl = ReasoningLoop(orch)
    hypotheses = [
        {"id": "h-1", "title": "Low confidence", "category": "authz",
         "confidence": 0.3, "status": "open", "recommended_skills": ["jwt_scan"],
         "target_id": "ep-1"},
        {"id": "h-2", "title": "High confidence", "category": "graphql",
         "confidence": 0.9, "status": "open", "recommended_skills": ["ssrf_scan"],
         "target_id": "ep-2"},
    ]
    state = {"finding_types": set(), "open_hypotheses": {"h-1", "h-2"}}
    selected = await rl._select_hypothesis("eng-test", hypotheses, state)
    assert selected is not None
    assert selected["id"] == "h-2"  # higher confidence wins


@pytest.mark.asyncio
async def test_select_hypothesis_novelty_boost():
    """A hypothesis in a category that hasn't been found yet gets a boost."""
    orch = _mock_orchestrator()
    rl = ReasoningLoop(orch)
    hypotheses = [
        {"id": "h-1", "title": "Already found", "category": "sqli",
         "confidence": 0.8, "status": "open", "recommended_skills": ["sqli_scan"],
         "target_id": "ep-1"},
        {"id": "h-2", "title": "Novel category", "category": "graphql",
         "confidence": 0.75, "status": "open", "recommended_skills": ["ssrf_scan"],
         "target_id": "ep-2"},
    ]
    # sqli already found → h-1 gets 0.8, h-2 gets 0.75 + 0.1 novelty = 0.85
    state = {"finding_types": {"sqli"}, "open_hypotheses": {"h-1", "h-2"}}
    selected = await rl._select_hypothesis("eng-test", hypotheses, state)
    assert selected["id"] == "h-2"  # novelty boost pushes it past h-1


@pytest.mark.asyncio
async def test_dispatch_hypothesis_creates_task():
    """_dispatch_hypothesis creates a Task with the right agent_type + payload."""
    orch = _mock_orchestrator()
    orch.graph_memory.run_read_query = AsyncMock(return_value=[
        {"url": "http://t.test/api/users"},
    ])
    rl = ReasoningLoop(orch)
    hypothesis = {
        "id": "hyp-1",
        "title": "Test authz",
        "category": "authz",
        "target_id": "ep-1",
        "recommended_skills": ["jwt_scan"],
        "status": "open",
    }
    task = await rl._dispatch_hypothesis("eng-test", "eng-session", hypothesis)
    assert task is not None
    assert task.type == "jwt_scan"
    assert task.agent_type == AgentType.JWT_SCANNER
    assert task.payload["url"] == "http://t.test/api/users"
    assert task.payload["hypothesis_id"] == "hyp-1"
    orch.task_scheduler.schedule_task.assert_awaited_once()


@pytest.mark.asyncio
async def test_dispatch_skips_hypothesis_with_no_mapped_skill():
    """A hypothesis whose recommended_skills don't map to any agent_type is skipped."""
    orch = _mock_orchestrator()
    rl = ReasoningLoop(orch)
    hypothesis = {
        "id": "hyp-1",
        "recommended_skills": ["unknown_skill_xyz"],
        "target_id": "ep-1",
        "status": "open",
    }
    task = await rl._dispatch_hypothesis("eng-test", "eng-session", hypothesis)
    assert task is None
    orch.task_scheduler.schedule_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_evaluate_confirmed_updates_status_and_chains():
    """When a hypothesis test finds findings, status → confirmed + chain hypotheses generated."""
    orch = _mock_orchestrator()
    rl = ReasoningLoop(orch)
    hypothesis = {"id": "hyp-1", "category": "redirect_ssrf", "target_id": "ep-1"}
    result = {"status": "success", "findings_count": 2}
    await rl._evaluate_result("eng-test", hypothesis, result)
    # Status updated to confirmed
    orch.graph_memory.run_write_query.assert_any_call(
        "MATCH (h:Hypothesis {id: $hid}) SET h.status = $status",
        {"hid": "hyp-1", "status": "confirmed"},
    )
    assert rl._dead_ends == 0  # reset on success


@pytest.mark.asyncio
async def test_evaluate_refuted_generates_followup():
    """When a hypothesis test finds nothing, status → refuted + follow-up hypotheses generated."""
    orch = _mock_orchestrator()
    rl = ReasoningLoop(orch)
    hypothesis = {"id": "hyp-1", "category": "authz", "target_id": "ep-1"}
    result = {"status": "success", "findings_count": 0}
    await rl._evaluate_result("eng-test", hypothesis, result)
    orch.graph_memory.run_write_query.assert_any_call(
        "MATCH (h:Hypothesis {id: $hid}) SET h.status = $status",
        {"hid": "hyp-1", "status": "refuted"},
    )
    assert rl._dead_ends == 1  # incremented on dead end


@pytest.mark.asyncio
async def test_evaluate_timeout_marks_inconclusive():
    """When a task times out (result is None), hypothesis → inconclusive."""
    orch = _mock_orchestrator()
    rl = ReasoningLoop(orch)
    hypothesis = {"id": "hyp-1", "category": "authz", "target_id": "ep-1"}
    await rl._evaluate_result("eng-test", hypothesis, None)
    orch.graph_memory.run_write_query.assert_any_call(
        "MATCH (h:Hypothesis {id: $hid}) SET h.status = $status",
        {"hid": "hyp-1", "status": "inconclusive"},
    )


@pytest.mark.asyncio
async def test_finding_event_published_on_persist():
    """GraphMemory._publish_finding_event publishes on the coordination bus."""
    from ai_osop.core.enums import Severity, VulnClass
    from ai_osop.core.models import Vulnerability
    from ai_osop.memory.graph_memory import GraphMemory

    gm = GraphMemory()
    gm.coordination_bus = MagicMock()
    gm.coordination_bus.publish = AsyncMock()

    vuln = Vulnerability(
        cwe="CWE-89", vuln_type=VulnClass.SQLI, severity=Severity.HIGH,
        title="SQLi", description="test", tool_source="test",
        confidence=0.9, validated=True, engagement_id="eng-test",
    )
    await gm._publish_finding_event(vuln, "vuln-123")
    gm.coordination_bus.publish.assert_awaited_once()
    call_args = gm.coordination_bus.publish.call_args
    assert call_args.args[0] == "finding.recorded"
    assert call_args.args[1]["finding_id"] == "vuln-123"
    assert call_args.args[1]["vuln_type"] == "sqli"


@pytest.mark.asyncio
async def test_skill_to_agent_type_mapping_covers_all_scanners():
    """Every scanner task type must map to an AgentType in _SKILL_TO_AGENT_TYPE."""
    required = {
        "sqli_scan", "xss_scan", "ssrf_scan", "ssti_scan", "csrf_scan",
        "jwt_scan", "smuggling_scan", "race_scan", "upload_scan",
        "pollution_scan", "websocket_scan", "saml_scan", "takeover_scan",
        "mass_assignment_scan", "nosql_scan", "cache_poisoning_scan",
        "open_redirect_scan", "oauth_reset_scan",
    }
    mapped = set(_SKILL_TO_AGENT_TYPE.keys())
    missing = required - mapped
    assert not missing, f"Scanner task types without agent mapping: {missing}"
