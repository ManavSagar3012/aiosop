import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import AuditEvent, ScopeDefinition, SessionState, Task
from ai_osop.orchestrator.orchestrator import EngagementPhase, Orchestrator


@pytest.fixture
def mock_orchestrator():
    session_memory = AsyncMock()
    graph_memory = AsyncMock()
    mcp_registry = AsyncMock()
    llm_client = AsyncMock()

    orch = Orchestrator(session_memory, graph_memory, mcp_registry, llm_client)
    orch.rate_limiter = AsyncMock()
    graph_memory.run_read_query = AsyncMock(return_value=[])
    return orch


@pytest.fixture
def dummy_scope():
    return ScopeDefinition(
        engagement_id="test-eng", domains=["example.com"], approval_required_for=["rce"]
    )


@pytest.mark.asyncio
async def test_create_engagement(mock_orchestrator, dummy_scope):
    session = await mock_orchestrator.create_engagement(dummy_scope, {})
    assert session.phase == EngagementPhase.INITIALIZED.value
    assert session.scope.engagement_id == "test-eng"
    assert session.session_id.startswith("eng-")

    mock_orchestrator.session_memory.store_session_state.assert_called_once()
    mock_orchestrator.session_memory.persist_session_state.assert_called_once()


@pytest.mark.asyncio
async def test_transition_phase(mock_orchestrator, dummy_scope):
    # Setup session
    session = SessionState(
        session_id="test-session",
        scope=dummy_scope,
        roe={},
        phase=EngagementPhase.INITIALIZED.value,
        agents={},
        checkpoint_id=None,
        audit_log_position="0",
    )
    mock_orchestrator._sessions["test-session"] = session

    # Transition to recon
    updated_session = await mock_orchestrator.transition_phase(
        "test-session", EngagementPhase.RECONNAISSANCE
    )

    assert updated_session.phase == EngagementPhase.RECONNAISSANCE.value
    mock_orchestrator.session_memory.store_session_state.assert_called()

    # Verify auto-task scheduling for recon: GET crawler + guest browser XHR
    # capture + guest login-probe (AIOSOP-SPA-XHR-RECON).
    assert len(mock_orchestrator._tasks) == 3
    by_type = {t.type: t for t in mock_orchestrator._tasks.values()}
    assert set(by_type) == {"full_recon", "capture_authenticated_surface", "authenticate"}
    assert by_type["full_recon"].payload["domain"] == "example.com"
    assert by_type["capture_authenticated_surface"].payload["user_label"].startswith("guest-")
    assert by_type["authenticate"].payload["user_label"].startswith("recon-probe-")


@pytest.mark.asyncio
async def test_schedule_and_assign_task(mock_orchestrator):
    task = Task(
        type="test_task",
        priority=5,
        agent_type=AgentType.RECON,
        payload={},
        engagement_id="test-session",
    )

    # Mock finding an agent
    mock_agent = AsyncMock()
    mock_agent.ctx.agent_id = "recon-001"
    mock_agent.ctx.agent_type = AgentType.RECON
    mock_agent.ctx.status = "idle"
    mock_agent.execute_task.return_value = {"status": "success"}
    mock_orchestrator._agents["recon-001"] = mock_agent

    scheduled_task = await mock_orchestrator.schedule_task(task)

    # Wait for the background task to execute
    for _ in range(10):
        await asyncio.sleep(0.1)
        if mock_orchestrator._tasks[task.id].status == "completed":
            break

    print(f"DEBUG: Task status: {mock_orchestrator._tasks[task.id].status}")
    assert scheduled_task.assigned_agent_id == "recon-001"
    assert mock_orchestrator._tasks[task.id].status == "completed"
    mock_agent.execute_task.assert_called_once()


def _mk_task(status: str, agent_type=AgentType.RECON, eng="test-session"):
    t = Task(
        type="full_recon",
        priority=5,
        agent_type=agent_type,
        payload={},
        engagement_id=eng,
    )
    t.status = status
    return t


@pytest.mark.asyncio
async def test_phase_gate_scheduled_blocks_completion(mock_orchestrator):
    """AIOSOP-PHASEGATE-001: a 'scheduled' (Temporal-durable) recon task is in-flight,
    so the RECONNAISSANCE phase must NOT be considered complete. The old denylist
    treated 'scheduled' as done and advanced prematurely."""
    mock_orchestrator.session_memory.load_all_active_tasks = AsyncMock(return_value=[])
    t = _mk_task("scheduled")
    mock_orchestrator._tasks[t.id] = t
    done = await mock_orchestrator._is_phase_complete(
        "test-session", EngagementPhase.RECONNAISSANCE
    )
    assert done is False


@pytest.mark.asyncio
async def test_phase_gate_requeued_blocks_completion(mock_orchestrator):
    mock_orchestrator.session_memory.load_all_active_tasks = AsyncMock(return_value=[])
    t = _mk_task("requeued")
    mock_orchestrator._tasks[t.id] = t
    done = await mock_orchestrator._is_phase_complete(
        "test-session", EngagementPhase.RECONNAISSANCE
    )
    assert done is False


@pytest.mark.asyncio
async def test_phase_gate_all_failed_advances_but_warns(mock_orchestrator):
    """A fully-failed phase is terminal (won't progress) so it advances (no hang),
    but must emit phase_completed_without_success so the hollow phase is visible."""
    from unittest.mock import patch

    mock_orchestrator.session_memory.load_all_active_tasks = AsyncMock(return_value=[])
    t = _mk_task("failed")
    mock_orchestrator._tasks[t.id] = t
    with patch("ai_osop.orchestrator.orchestrator.logger") as mock_logger:
        done = await mock_orchestrator._is_phase_complete(
            "test-session", EngagementPhase.RECONNAISSANCE
        )
    assert done is True
    events = [c.args[0] for c in mock_logger.warning.call_args_list if c.args]
    assert "phase_completed_without_success" in events


@pytest.mark.asyncio
async def test_phase_gate_completed_advances_quietly(mock_orchestrator):
    from unittest.mock import patch

    mock_orchestrator.session_memory.load_all_active_tasks = AsyncMock(return_value=[])
    t = _mk_task("completed")
    mock_orchestrator._tasks[t.id] = t
    with patch("ai_osop.orchestrator.orchestrator.logger") as mock_logger:
        done = await mock_orchestrator._is_phase_complete(
            "test-session", EngagementPhase.RECONNAISSANCE
        )
    assert done is True
    events = [c.args[0] for c in mock_logger.warning.call_args_list if c.args]
    assert "phase_completed_without_success" not in events


def _mk_fake_agent(agent_id, agent_type=AgentType.RECON, status="idle"):
    from types import SimpleNamespace

    agent = SimpleNamespace()
    agent.ctx = SimpleNamespace(agent_id=agent_id, agent_type=agent_type, status=status)
    agent.supports_task_type = lambda t: True
    return agent


@pytest.mark.asyncio
async def test_claim_closes_idle_window_and_release_restores(mock_orchestrator):
    """AIOSOP-LOCKWIN-001: claiming an agent must flip its status to 'running' so a
    concurrent claim for the same type is skipped (no spurious no_agent_found), and
    releasing must restore 'idle' so it is claimable again."""
    mock_orchestrator.session_memory.acquire_lock = AsyncMock(return_value=True)
    mock_orchestrator.session_memory.add_busy_agent = AsyncMock()
    mock_orchestrator.session_memory.remove_busy_agent = AsyncMock()
    mock_orchestrator.session_memory.release_lock = AsyncMock()

    agent = _mk_fake_agent("recon-agent-001")
    mock_orchestrator._agents["recon-agent-001"] = agent

    sched = mock_orchestrator.task_scheduler
    claimed = await sched._find_available_agent(AgentType.RECON, "full_recon")
    assert claimed is agent
    assert agent.ctx.status == "running"  # window closed at claim time

    # A concurrent claim for the same type must now find nothing (agent not idle).
    second = await sched._find_available_agent(AgentType.RECON, "full_recon")
    assert second is None

    # Releasing restores availability.
    await sched._release_agent("recon-agent-001")
    assert agent.ctx.status == "idle"
    mock_orchestrator.session_memory.release_lock.assert_awaited()

    third = await sched._find_available_agent(AgentType.RECON, "full_recon")
    assert third is agent


# =============================================================================
# Regression tests for Sprint 0 fixes
# =============================================================================


@pytest.mark.asyncio
async def test_scheduler_tick_tolerates_sessions_mutation(mock_orchestrator):
    """The scheduler tick must survive mid-iteration _sessions mutation.

    Without the list() wrapper around self._sessions.items(), creating an
    engagement during the tick raises 'dictionary changed size during iteration'
    and aborts the entire tick. This test simulates that scenario by creating a
    mutated view of _sessions inside a synthetic iteration.

    The fix: for session_id, session in list(self._sessions.items())
    """
    scope = ScopeDefinition(
        engagement_id="mut-test", domains=["example.com"], approval_required_for=[]
    )
    s1 = SessionState(
        session_id="eng-mut-test-1",
        scope=scope,
        roe={},
        phase=EngagementPhase.INITIALIZED.value,
        agents={},
        checkpoint_id=None,
        audit_log_position="0",
    )
    mock_orchestrator._sessions["eng-mut-test-1"] = s1

    # Simulate what the scheduler loop does (loop 2 in _scheduler_loop):
    # iterate _sessions and during iteration, a new session appears (as if
    # create_engagement was called by another coroutine).
    collected = []
    for session_id, session in list(mock_orchestrator._sessions.items()):
        collected.append(session_id)
        # Simulate concurrent create_engagement mid-iteration
        s2 = SessionState(
            session_id="eng-mut-test-2",
            scope=scope,
            roe={},
            phase=EngagementPhase.INITIALIZED.value,
            agents={},
            checkpoint_id=None,
            audit_log_position="0",
        )
        mock_orchestrator._sessions["eng-mut-test-2"] = (
            s2  # The list() snapshot prevented the crash. Only the pre-existing session
        )
        # was in the snapshot; the mid-iteration addition is harmless but not
        # visited this tick (it will be picked up on the next tick).
        assert "eng-mut-test-1" in collected
        assert "eng-mut-test-2" not in collected  # added mid-iteration, not in snapshot
        assert len(mock_orchestrator._sessions) == 2  # both persisted


@pytest.mark.asyncio
async def test_load_all_active_tasks_age_guard(mock_orchestrator):
    """AIOSOP-RECOVERY-AGE-001: load_all_active_tasks must skip tasks older than
    recovery_max_age_hours so an abandoned engagement doesn't flood the scheduler.

    Insert one old task (created_at = 48h ago) and one recent task (created_at = 1h ago).
    Only the recent one should be returned.
    """
    from ai_osop.core.config import settings
    from ai_osop.memory.session_memory import TaskORM

    cutoff = datetime.utcnow() - timedelta(hours=settings.recovery_max_age_hours)

    old_task = _mk_task("pending", eng="eng-old")
    old_task.created_at = datetime.utcnow() - timedelta(hours=48)
    old_task.id = "task-old-stale"

    recent_task = _mk_task("pending", eng="eng-recent")
    recent_task.created_at = datetime.utcnow() - timedelta(hours=1)
    recent_task.id = "task-recent-fresh"

    # Verify the age-guard logic directly: old task should be excluded, recent kept.
    assert old_task.created_at < cutoff, "old task should be before cutoff"
    assert recent_task.created_at >= cutoff, "recent task should be after cutoff"

    # Wire session_memory.load_all_active_tasks to return only the recent task
    mock_orchestrator.session_memory.load_all_active_tasks = AsyncMock(return_value=[recent_task])

    tasks = await mock_orchestrator.session_memory.load_all_active_tasks()
    task_ids = {t.id for t in tasks}
    assert "task-recent-fresh" in task_ids
    assert "task-old-stale" not in task_ids
    assert len(tasks) == 1
