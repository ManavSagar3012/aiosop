"""Temporal activities must prove scope and approval before calling an agent."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import ScopeDefinition, SessionState, Task
from ai_osop.orchestrator.temporal_worker import TaskActivities
from ai_osop.orchestrator import temporal_worker


def authorized_worker(
    *, approved=False, authorization_ref="signed-roe", target="https://example.com/api"
):
    task = Task(
        id="task-temporal",
        type="test_task",
        agent_type=AgentType.RECON,
        engagement_id="eng-123",
        approval_required=approved,
        status="scheduled",
        payload={"target": target, "approval_id": "apr-one"} if approved else {"target": target},
    )
    session = SessionState(
        session_id="eng-123",
        scope=ScopeDefinition(
            engagement_id="eng-123",
            domains=["example.com"],
            authorization_ref=authorization_ref,
        ),
        phase="reconnaissance",
    )
    memory = SimpleNamespace(
        load_task=AsyncMock(return_value=task),
        load_session_state=AsyncMock(return_value=session),
        is_task_approved=AsyncMock(return_value=True),
        acquire_lock=AsyncMock(return_value=True),
        renew_lock=AsyncMock(return_value=True),
        release_lock=AsyncMock(return_value=True),
    )
    orch = SimpleNamespace(
        session_memory=memory,
        _sessions={"eng-123": session},
        supervision_store=SimpleNamespace(
            start_attempt=AsyncMock(return_value={"id": "run-temporal", "revision": 0, "created": True}),
            update_attempt=AsyncMock(return_value={"id": "run-temporal", "revision": 1}),
            list_attempts=AsyncMock(return_value=[]),
            claim_execution_lease=AsyncMock(return_value={
                "acquired": True, "lease_id": "lease-temporal",
            }),
            renew_execution_lease=AsyncMock(return_value={
                "lease_id": "lease-temporal", "state": "running",
            }),
            check_execution_lease=AsyncMock(return_value=True),
            mark_execution_dispatched=AsyncMock(return_value=True),
            release_execution_lease=AsyncMock(return_value=True),
        ),
        _execute_task_durable=AsyncMock(return_value={"status": "success", "data": "test"}),
        _on_task_success=AsyncMock(),
        _on_task_failure=AsyncMock(),
        _quarantine_unknown_execution=AsyncMock(),
    )
    return task, orch, TaskActivities(orch)


@pytest.mark.asyncio
async def test_execute_task_activity_calls_real_orchestrator() -> None:
    task, orch, activity = authorized_worker()
    result = await activity.execute_task_activity(task.model_dump())
    assert result["status"] == "success"
    orch._execute_task_durable.assert_awaited_once()
    assert isinstance(orch._execute_task_durable.call_args.args[0], Task)
    orch._on_task_success.assert_awaited_once()
    orch._on_task_failure.assert_not_awaited()
    orch.supervision_store.start_attempt.assert_awaited_once_with(
        task.engagement_id, task.id, 1, status="running", external_id=f"ai-osop-{task.id}",
    )
    orch.supervision_store.update_attempt.assert_awaited_once_with(
        "run-temporal", 0, "succeeded", receipt={"outcome": "success"},
    )


@pytest.mark.asyncio
async def test_temporal_real_supervision_uses_atomic_terminal_handoff_without_legacy_callbacks():
    task, orch, activity = authorized_worker()
    orch._supervision_active = True
    orch.terminal_store = SimpleNamespace(
        commit_terminal=AsyncMock(return_value={"created": True, "status": "pending"})
    )
    result = await activity.execute_task_activity(task.model_dump())
    assert result["status"] == "success"
    assert orch._execute_task_durable.await_args.kwargs == {"persist_terminal": False}
    orch.terminal_store.commit_terminal.assert_awaited_once_with(
        task.engagement_id, task.id, "run-temporal", 0, "succeeded",
        owner_id=orch.terminal_store.commit_terminal.await_args.kwargs["owner_id"],
        lease_id="lease-temporal", receipt_code="temporal_agent_completed",
        continuation={"status": "success", "data": "test"},
    )
    orch.supervision_store.update_attempt.assert_not_awaited()
    orch._on_task_success.assert_not_awaited()
    orch._on_task_failure.assert_not_awaited()


@pytest.mark.asyncio
async def test_temporal_unknown_outcome_does_not_create_downstream_success_callback():
    task, orch, activity = authorized_worker()
    orch._supervision_active = True
    orch.terminal_store = SimpleNamespace(
        commit_terminal=AsyncMock(return_value={
            "created": True, "status": "dispatch_unknown", "callback": None,
        })
    )
    orch._execute_task_durable.return_value = {"status": "execution_unknown"}
    result = await activity.execute_task_activity(task.model_dump())
    assert result["status"] == "execution_unknown"
    assert orch.terminal_store.commit_terminal.await_args.args[4] == "unknown"
    orch._on_task_success.assert_not_awaited()
    orch._on_task_failure.assert_not_awaited()


@pytest.mark.asyncio
async def test_temporal_activity_propagates_worker_failure() -> None:
    task, orch, activity = authorized_worker()
    orch._execute_task_durable.side_effect = RuntimeError("worker failed")
    with pytest.raises(RuntimeError, match="worker failed"):
        await activity.execute_task_activity(task.model_dump())


@pytest.mark.asyncio
async def test_temporal_rejects_unapproved_or_forged_flag() -> None:
    task, orch, activity = authorized_worker(approved=True)
    task.payload["operator_approved"] = True
    orch.session_memory.is_task_approved.return_value = False
    with pytest.raises(RuntimeError, match="No current persisted approval"):
        await activity.execute_task_activity(task.model_dump())
    orch._execute_task_durable.assert_not_awaited()


@pytest.mark.asyncio
async def test_temporal_rejects_out_of_scope_target() -> None:
    task, orch, activity = authorized_worker(target="https://not-authorized.example.net/")
    with pytest.raises(Exception, match="not in scope"):
        await activity.execute_task_activity(task.model_dump())
    orch._execute_task_durable.assert_not_awaited()


@pytest.mark.asyncio
async def test_temporal_rejects_missing_authorization() -> None:
    task, orch, activity = authorized_worker(authorization_ref=None)
    with pytest.raises(RuntimeError, match="Explicit authorization"):
        await activity.execute_task_activity(task.model_dump())
    orch._execute_task_durable.assert_not_awaited()


@pytest.mark.asyncio
async def test_temporal_rejects_unpersisted_task() -> None:
    task, orch, activity = authorized_worker()
    orch.session_memory.load_task.return_value = None
    with pytest.raises(RuntimeError, match="no matching persisted"):
        await activity.execute_task_activity(task.model_dump())
    orch._execute_task_durable.assert_not_awaited()


@pytest.mark.asyncio
async def test_temporal_failure_records_normal_failure_lifecycle() -> None:
    task, orch, activity = authorized_worker()
    orch._execute_task_durable.return_value = {"status": "failed", "error": "mock failure"}
    result = await activity.execute_task_activity(task.model_dump())
    assert result["status"] == "failed"
    orch._on_task_failure.assert_awaited_once()
    orch._on_task_success.assert_not_awaited()


@pytest.mark.asyncio
async def test_temporal_refuses_execution_when_attempt_persistence_fails() -> None:
    task, orch, activity = authorized_worker()
    orch.supervision_store.start_attempt.side_effect = ConnectionError("postgres offline")
    with pytest.raises(ConnectionError, match="postgres offline"):
        await activity.execute_task_activity(task.model_dump())
    orch._execute_task_durable.assert_not_awaited()


@pytest.mark.asyncio
async def test_temporal_attempt_cas_conflict_never_completes_task() -> None:
    task, orch, activity = authorized_worker()
    orch.supervision_store.update_attempt.return_value = None
    with pytest.raises(RuntimeError, match="changed during execution"):
        await activity.execute_task_activity(task.model_dump())
    orch._on_task_success.assert_not_awaited()
    orch._on_task_failure.assert_not_awaited()


@pytest.mark.asyncio
async def test_temporal_transport_error_records_unknown_outcome() -> None:
    task, orch, activity = authorized_worker()
    orch._execute_task_durable.side_effect = TimeoutError("upstream lost")
    with pytest.raises(TimeoutError, match="upstream lost"):
        await activity.execute_task_activity(task.model_dump())
    orch.supervision_store.update_attempt.assert_awaited_once_with(
        "run-temporal", 0, "unknown", receipt={"outcome": "worker_interrupted"},
    )
    orch._quarantine_unknown_execution.assert_awaited_once_with(task)


@pytest.mark.asyncio
async def test_unknown_remote_result_does_not_complete_task() -> None:
    task, orch, activity = authorized_worker()
    orch._execute_task_durable.return_value = {"status": "unknown"}
    result = await activity.execute_task_activity(task.model_dump())
    assert result["status"] == "execution_unknown"
    orch.supervision_store.update_attempt.assert_awaited_once_with(
        "run-temporal", 0, "unknown", receipt={"outcome": "unknown"},
    )
    orch._quarantine_unknown_execution.assert_awaited_once_with(task)
    orch._on_task_failure.assert_not_awaited()
    orch._on_task_success.assert_not_awaited()


@pytest.mark.asyncio
async def test_temporal_duplicate_attempt_never_replays_remote_execution() -> None:
    task, orch, activity = authorized_worker()
    orch.supervision_store.start_attempt.return_value = {
        "id": "run-existing", "revision": 0, "created": False,
    }
    result = await activity.execute_task_activity(task.model_dump())
    assert result["status"] == "execution_unknown"
    orch._execute_task_durable.assert_not_awaited()
    orch.supervision_store.update_attempt.assert_not_awaited()
    orch._on_task_success.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["authenticated", "workflow_recorded", "completed"])
async def test_temporal_valid_agent_success_markers_complete(status: str) -> None:
    task, orch, activity = authorized_worker()
    orch._execute_task_durable.return_value = {"status": status}
    result = await activity.execute_task_activity(task.model_dump())
    assert result["status"] == status
    orch.supervision_store.update_attempt.assert_awaited_once_with(
        "run-temporal", 0, "succeeded", receipt={"outcome": status},
    )
    orch._on_task_success.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["error", "timeout", "cancelled"])
async def test_temporal_ambiguous_agent_errors_quarantine(status: str) -> None:
    task, orch, activity = authorized_worker()
    orch._execute_task_durable.return_value = {"status": status}
    result = await activity.execute_task_activity(task.model_dump())
    assert result["status"] == "execution_unknown"
    orch._quarantine_unknown_execution.assert_awaited_once()
    orch._on_task_failure.assert_not_awaited()
    orch._on_task_success.assert_not_awaited()


@pytest.mark.asyncio
async def test_temporal_dispatch_refused_when_ownership_lock_held() -> None:
    task, orch, activity = authorized_worker()
    orch.session_memory.acquire_lock.return_value = False
    with pytest.raises(RuntimeError, match="ownership unavailable"):
        await activity.execute_task_activity(task.model_dump())
    orch.supervision_store.start_attempt.assert_not_awaited()
    orch._execute_task_durable.assert_not_awaited()


@pytest.mark.asyncio
async def test_temporal_refuses_execution_when_lease_renewal_denied() -> None:
    task, orch, activity = authorized_worker()
    orch.session_memory.renew_lock.return_value = False
    with pytest.raises(RuntimeError, match="lease expired or changed"):
        await activity.execute_task_activity(task.model_dump())
    orch._execute_task_durable.assert_not_awaited()
    orch.supervision_store.update_attempt.assert_awaited_once()
    orch._quarantine_unknown_execution.assert_awaited_once()
    orch.session_memory.release_lock.assert_awaited_once()


@pytest.mark.asyncio
async def test_temporal_lease_lost_during_agent_execution_quarantines(monkeypatch) -> None:
    task, orch, activity = authorized_worker()
    monkeypatch.setattr(temporal_worker, "_HEARTBEAT_INTERVAL_SECONDS", 0.01)
    started = asyncio.Event()

    async def long_remote_execution(_task):
        started.set()
        await asyncio.Event().wait()

    orch._execute_task_durable.side_effect = long_remote_execution
    lease_checks = 0

    async def renew_then_fail(*_args, **_kwargs):
        nonlocal lease_checks
        lease_checks += 1
        return lease_checks == 1

    orch.session_memory.renew_lock.side_effect = renew_then_fail
    with pytest.raises(RuntimeError, match="checkpoint ownership"):
        await asyncio.wait_for(activity.execute_task_activity(task.model_dump()), 1)
    assert started.is_set()
    assert lease_checks >= 2
    orch.supervision_store.update_attempt.assert_awaited_once_with(
        "run-temporal", 0, "unknown", receipt={"outcome": "worker_interrupted"},
    )
    orch._quarantine_unknown_execution.assert_awaited_once()
    orch._on_task_success.assert_not_awaited()
    orch.session_memory.release_lock.assert_awaited_once()


@pytest.mark.asyncio
async def test_temporal_operator_pending_cancel_blocks_before_dispatch() -> None:
    task, orch, activity = authorized_worker()
    orch.supervision_store.list_controls = AsyncMock(return_value=[{
        "action": "cancel", "status": "pending",
    }])
    with pytest.raises(RuntimeError, match="checkpoint unavailable"):
        await activity.execute_task_activity(task.model_dump())
    orch._execute_task_durable.assert_not_awaited()
    orch._quarantine_unknown_execution.assert_awaited_once()


@pytest.mark.asyncio
async def test_temporal_releases_lease_after_failure_and_no_retry_duplicate() -> None:
    task, orch, activity = authorized_worker()
    orch._execute_task_durable.side_effect = RuntimeError("connection failed after send")
    with pytest.raises(RuntimeError):
        await activity.execute_task_activity(task.model_dump())
    orch.session_memory.release_lock.assert_awaited_once()
    orch.supervision_store.start_attempt.return_value = {
        "id": "run-temporal", "revision": 1, "created": False,
    }
    result = await activity.execute_task_activity(task.model_dump())
    assert result["status"] == "execution_unknown"
    assert orch._execute_task_durable.await_count == 1


@pytest.mark.asyncio
async def test_temporal_blocks_retry_while_prior_remote_attempt_unknown() -> None:
    task, orch, activity = authorized_worker()
    task.retry_count = 1
    orch.supervision_store.list_attempts.return_value = [{
        "attempt": 1, "status": "unknown", "id": "run-previous",
    }]
    result = await activity.execute_task_activity(task.model_dump())
    assert result["status"] == "execution_unknown"
    assert result["reason"] == "unresolved_previous_attempt"
    orch.supervision_store.start_attempt.assert_not_awaited()
    orch._execute_task_durable.assert_not_awaited()


@pytest.mark.asyncio
async def test_temporal_allows_retry_only_after_definite_prior_failure() -> None:
    task, orch, activity = authorized_worker()
    task.retry_count = 1
    orch.supervision_store.list_attempts.return_value = [{
        "attempt": 1, "status": "failed", "id": "run-previous",
    }]
    result = await activity.execute_task_activity(task.model_dump())
    assert result["status"] == "success"
    orch.supervision_store.start_attempt.assert_awaited_once_with(
        task.engagement_id, task.id, 2, status="running", external_id=f"ai-osop-{task.id}",
    )


@pytest.mark.asyncio
async def test_temporal_unauthorized_queued_task_is_denied_before_remote_execution() -> None:
    task, orch, activity = authorized_worker()
    task.status = "awaiting_approval"
    with pytest.raises(RuntimeError, match="checkpoint unavailable"):
        await activity.execute_task_activity(task.model_dump())
    orch._execute_task_durable.assert_not_awaited()


@pytest.mark.asyncio
async def test_temporal_rechecks_revoked_approval_before_dispatch() -> None:
    task, orch, activity = authorized_worker(approved=True)
    orch.session_memory.is_task_approved.side_effect = [True, False]
    with pytest.raises(RuntimeError, match="checkpoint unavailable"):
        await activity.execute_task_activity(task.model_dump())
    orch._execute_task_durable.assert_not_awaited()


@pytest.mark.asyncio
async def test_temporal_requires_authoritative_postgres_lease_before_attempt() -> None:
    task, orch, activity = authorized_worker()
    orch.supervision_store.claim_execution_lease.return_value = {"acquired": False}
    with pytest.raises(RuntimeError, match="PostgreSQL execution lease denied"):
        await activity.execute_task_activity(task.model_dump())
    orch.supervision_store.start_attempt.assert_not_awaited()
    orch._execute_task_durable.assert_not_awaited()
    orch.session_memory.release_lock.assert_awaited_once()


@pytest.mark.asyncio
async def test_temporal_fails_closed_when_postgres_lease_check_lost() -> None:
    task, orch, activity = authorized_worker()
    orch.supervision_store.check_execution_lease.return_value = False
    with pytest.raises(RuntimeError, match="PostgreSQL execution ownership lost"):
        await activity.execute_task_activity(task.model_dump())
    orch.supervision_store.start_attempt.assert_not_awaited()
    orch._execute_task_durable.assert_not_awaited()
    orch.supervision_store.release_execution_lease.assert_awaited_once()


@pytest.mark.asyncio
async def test_temporal_durable_lease_revocation_while_agent_runs(monkeypatch) -> None:
    task, orch, activity = authorized_worker()
    monkeypatch.setattr(temporal_worker, "_HEARTBEAT_INTERVAL_SECONDS", 0.01)
    began = asyncio.Event()

    async def agent_execution(_task):
        began.set()
        await asyncio.Event().wait()

    orch._execute_task_durable.side_effect = agent_execution
    checks = 0

    async def still_owned(*_args):
        nonlocal checks
        checks += 1
        return checks <= 2

    orch.supervision_store.check_execution_lease.side_effect = still_owned
    with pytest.raises(RuntimeError, match="checkpoint ownership"):
        await asyncio.wait_for(activity.execute_task_activity(task.model_dump()), 1)
    assert began.is_set() and checks >= 3
    orch._on_task_success.assert_not_awaited()
    orch._quarantine_unknown_execution.assert_awaited_once()
    orch.supervision_store.release_execution_lease.assert_awaited_once()


@pytest.mark.asyncio
async def test_temporal_requires_durable_dispatched_transition_before_agent() -> None:
    task, orch, activity = authorized_worker()
    orch.supervision_store.mark_execution_dispatched.return_value = False
    with pytest.raises(RuntimeError, match="dispatch lease transition denied"):
        await activity.execute_task_activity(task.model_dump())
    orch._execute_task_durable.assert_not_awaited()
    orch.supervision_store.update_attempt.assert_awaited_once()
    orch._quarantine_unknown_execution.assert_awaited_once()


@pytest.mark.asyncio
async def test_temporal_activity_emits_checkpoints_when_sdk_context_exists(monkeypatch) -> None:
    task, orch, activity = authorized_worker()
    sdk = SimpleNamespace(info=MagicMock(return_value=SimpleNamespace()), heartbeat=MagicMock())
    monkeypatch.setattr(temporal_worker, "temporal_activity", sdk)
    result = await activity.execute_task_activity(task.model_dump())
    assert result["status"] == "success"
    stages = [call.args[0]["stage"] for call in sdk.heartbeat.call_args_list]
    assert stages == ["authorized", "result_received"]
    assert all(call.args[0]["task_id"] == task.id for call in sdk.heartbeat.call_args_list)


@pytest.mark.asyncio
@pytest.mark.parametrize("monitor_exit", ["clean", "cancelled", "exception"])
async def test_temporal_early_monitor_exit_quarantines_without_waiting_for_remote(
    monkeypatch, monitor_exit: str,
) -> None:
    """A monitor that exits without monitor_error cannot strand Temporal forever."""
    task, orch, activity = authorized_worker()
    started = asyncio.Event()
    remote_cancelled = asyncio.Event()
    allow_remote_finish = asyncio.Event()
    remote_handle = None
    most_recent_handle = None

    async def stubborn_remote(_task):
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            remote_cancelled.set()
            # Simulate an external agent ignoring the local cancellation.
            await allow_remote_finish.wait()
            return {"status": "success"}

    orch._execute_task_durable.side_effect = stubborn_remote
    original_create_task = asyncio.create_task

    async def exited_monitor():
        await started.wait()
        if monitor_exit == "cancelled":
            raise asyncio.CancelledError()
        if monitor_exit == "exception":
            raise RuntimeError("unexpected monitor failure")

    def replace_monitor(coro):
        nonlocal remote_handle, most_recent_handle
        name = getattr(getattr(coro, "cr_code", None), "co_name", "")
        if name == "heartbeat_and_check":
            remote_handle = most_recent_handle
            coro.close()
            return original_create_task(exited_monitor())
        handle = original_create_task(coro)
        most_recent_handle = handle
        return handle

    monkeypatch.setattr(temporal_worker.asyncio, "create_task", replace_monitor)
    try:
        with pytest.raises(RuntimeError, match="monitor terminated before verified completion"):
            await asyncio.wait_for(activity.execute_task_activity(task.model_dump()), 1)
        assert started.is_set() and remote_cancelled.is_set()
        assert remote_handle is not None and not remote_handle.done()
        orch.supervision_store.update_attempt.assert_awaited_once_with(
            "run-temporal", 0, "unknown", receipt={"outcome": "worker_interrupted"},
        )
        orch._quarantine_unknown_execution.assert_awaited_once_with(task)
        orch._on_task_success.assert_not_awaited()
        orch._on_task_failure.assert_not_awaited()
        orch.supervision_store.release_execution_lease.assert_awaited_once()
    finally:
        allow_remote_finish.set()
        if remote_handle is not None:
            await asyncio.wait_for(remote_handle, 1)


@pytest.mark.asyncio
async def test_temporal_monitor_loss_does_not_hang_on_stalled_attempt_writer(
    monkeypatch,
) -> None:
    task, orch, activity = authorized_worker()
    monkeypatch.setattr(temporal_worker, "_HEARTBEAT_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(temporal_worker, "_CONTROL_CHECK_SECONDS", 0.05)
    orch.session_memory.renew_lock.side_effect = [True, False]

    async def running_agent(_task):
        await asyncio.Event().wait()

    async def stalled_writer(*_args, **_kwargs):
        await asyncio.Event().wait()

    orch._execute_task_durable.side_effect = running_agent
    orch.supervision_store.update_attempt.side_effect = stalled_writer
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(activity.execute_task_activity(task.model_dump()), 1)
    orch._quarantine_unknown_execution.assert_awaited_once_with(task)
    orch._on_task_success.assert_not_awaited()
    orch._on_task_failure.assert_not_awaited()


@pytest.mark.asyncio
async def test_temporal_durable_status_persisted_then_replay_skips_duplicate_completion() -> None:
    """The durable executor commits task status before the lifecycle callback."""
    task, orch, activity = authorized_worker()
    orch.session_memory.store_task = AsyncMock()

    async def persisted_success(persisted_task):
        persisted_task.status = "completed"
        persisted_task.result = {"status": "success", "data": "saved"}
        await orch.session_memory.store_task(persisted_task)
        return persisted_task.result

    orch._execute_task_durable.side_effect = persisted_success
    first = await activity.execute_task_activity(task.model_dump())
    assert first == {"status": "success", "data": "saved"}
    assert task.status == "completed"
    orch.session_memory.store_task.assert_awaited_once_with(task)
    orch._on_task_success.assert_awaited_once_with(task, first)

    # Simulate a new activity worker reloading the committed terminal record.
    orch.session_memory.load_task.return_value = Task(**task.model_dump())
    second = await activity.execute_task_activity(task.model_dump())
    assert second == {
        "status": "completed", "task_id": task.id, "already_finalized": True,
    }
    orch._execute_task_durable.assert_awaited_once()
    orch._on_task_success.assert_awaited_once()
    orch._on_task_failure.assert_not_awaited()
    orch.supervision_store.start_attempt.assert_awaited_once()


@pytest.mark.asyncio
async def test_temporal_lost_dispatch_ack_fails_closed_on_crash_replay() -> None:
    """A crashed worker cannot retry a dispatched-or-unknown durable attempt."""
    task, orch, activity = authorized_worker()
    orch.supervision_store.mark_execution_dispatched.side_effect = ConnectionError(
        "dispatch transaction acknowledged remotely but local reply lost"
    )

    with pytest.raises(ConnectionError, match="local reply lost"):
        await activity.execute_task_activity(task.model_dump())
    orch._execute_task_durable.assert_not_awaited()
    orch.supervision_store.update_attempt.assert_awaited_once_with(
        "run-temporal", 0, "unknown", receipt={"outcome": "worker_interrupted"},
    )
    orch._quarantine_unknown_execution.assert_awaited_once_with(task)
    orch.supervision_store.release_execution_lease.assert_awaited_once()

    # Simulate a fresh worker after a crash. The real PostgreSQL lease guards
    # reject any prior unresolved attempt, even if the first worker released
    # its short-lived local Redis fence.
    orch.supervision_store.claim_execution_lease.return_value = {
        "acquired": False, "reason": "attempt_exists_unreconciled",
    }
    with pytest.raises(RuntimeError, match="PostgreSQL execution lease denied"):
        await TaskActivities(orch).execute_task_activity(task.model_dump())
    assert orch._execute_task_durable.await_count == 0
    assert orch.supervision_store.start_attempt.await_count == 1
