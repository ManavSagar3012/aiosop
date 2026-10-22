"""Safety checks inspect live execution and never generate target traffic."""

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import ScopeDefinition, SessionState, Task
from ai_osop.tasks.safety_monitor import SafetyMonitor


def _fixture(
    *,
    approval_required=False,
    testing_window_end=None,
    status="running",
    seconds_running=5,
):
    now = datetime.utcnow()
    session = SessionState(
        session_id="eng-monitor",
        phase="reconnaissance",
        scope=ScopeDefinition(
            engagement_id="eng-monitor",
            domains=["example.com"],
            authorization_ref="test-authorization",
            testing_window_end=testing_window_end,
        ),
    )
    task = Task(
        id="task-monitor",
        type="recon",
        agent_type=AgentType.RECON,
        engagement_id=session.session_id,
        status=status,
        approval_required=approval_required,
        started_at=now - timedelta(seconds=seconds_running),
        timeout_seconds=20,
        payload={"target": "https://example.com"},
    )
    memory = SimpleNamespace(is_task_approved=AsyncMock(return_value=True))
    orchestrator = SimpleNamespace(
        _sessions={session.session_id: session},
        _tasks={task.id: task},
        session_memory=memory,
        _audit_log=AsyncMock(),
        halt_engagement=AsyncMock(),
    )
    return session, task, orchestrator


@pytest.mark.asyncio
async def test_monitor_halts_expired_active_engagement_once() -> None:
    session, task, orch = _fixture(testing_window_end=datetime.utcnow() - timedelta(minutes=1))
    monitor = SafetyMonitor(orch)

    result = await monitor.check_once()
    assert result == [
        {"engagement_id": session.session_id, "task_id": task.id, "code": "testing_window_closed"}
    ]
    orch.halt_engagement.assert_awaited_once()
    audit = orch._audit_log.await_args.args[0]
    assert audit.event_type == "operational_safety_alert"
    assert "example.com" not in str(audit.model_dump())
    assert await monitor.check_once() == []


@pytest.mark.asyncio
async def test_audit_write_failure_cannot_bypass_expired_window_halt() -> None:
    _, _, orch = _fixture(testing_window_end=datetime.now(timezone.utc) - timedelta(minutes=1))
    orch._audit_log.side_effect = RuntimeError("audit store disconnected")

    with pytest.raises(RuntimeError, match="audit store disconnected"):
        await SafetyMonitor(orch).check_once(now=datetime.now(timezone.utc))
    orch.halt_engagement.assert_awaited_once()


@pytest.mark.asyncio
async def test_monitor_halts_running_task_without_persisted_approval() -> None:
    _, task, orch = _fixture(approval_required=True)
    orch.session_memory.is_task_approved.return_value = False
    task.payload["approval_id"] = "apr-test"

    events = await SafetyMonitor(orch).check_once()
    assert events[0]["code"] == "missing_operator_approval"
    orch.session_memory.is_task_approved.assert_awaited_once_with(
        task.id, task.engagement_id, "apr-test"
    )
    orch.halt_engagement.assert_awaited_once()


@pytest.mark.asyncio
async def test_unavailable_approval_store_fails_closed() -> None:
    _, task, orch = _fixture(approval_required=True)
    task.payload["approval_id"] = "apr-test"
    orch.session_memory.is_task_approved.side_effect = OSError("store down")

    assert (await SafetyMonitor(orch).check_once())[0]["code"] == "missing_operator_approval"
    orch.halt_engagement.assert_awaited_once()


@pytest.mark.asyncio
async def test_monitor_accepts_persisted_approval_and_in_window_task() -> None:
    _, task, orch = _fixture(approval_required=True)
    task.payload["approval_id"] = "apr-test"

    assert await SafetyMonitor(orch).check_once() == []
    orch.halt_engagement.assert_not_awaited()
    orch._audit_log.assert_not_awaited()


@pytest.mark.asyncio
async def test_overdue_task_is_logged_without_duplicate_or_automatic_retry() -> None:
    _, _, orch = _fixture(seconds_running=50)
    monitor = SafetyMonitor(orch)
    assert (await monitor.check_once())[0]["code"] == "task_overdue"
    assert await monitor.check_once() == []
    orch._audit_log.assert_awaited_once()
    orch.halt_engagement.assert_not_awaited()


@pytest.mark.asyncio
async def test_start_and_shutdown_are_idempotent() -> None:
    _, _, orch = _fixture(status="completed")
    monitor = SafetyMonitor(orch, check_interval=30)
    await monitor.start()
    runner = monitor._runner
    await monitor.start()
    assert runner is monitor._runner
    await asyncio.wait_for(monitor.shutdown(), timeout=1)
    assert monitor._runner is None
