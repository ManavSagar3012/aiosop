"""Opt-in, non-intrusive qualification against an isolated Temporal dev server.

Only run with OSOP_TEMPORAL_LIVE_TEST=1 and temporalio installed in the
invoking Python process. Temporal's local test environment runs a disposable
SQLite-backed service on a free localhost port; there are no target scans or
connections to the project's databases.
"""

import asyncio
import os
import uuid

import pytest

from ai_osop.orchestrator import temporal_worker
from tests.test_temporal_activity import authorized_worker


pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        os.getenv("OSOP_TEMPORAL_LIVE_TEST") != "1",
        reason="Set OSOP_TEMPORAL_LIVE_TEST=1 for disposable Temporal service qualification",
    ),
]


async def test_disposable_temporal_service_success_heartbeat_and_replay(monkeypatch):
    """Check actual Temporal client, workflow, worker, activity and heartbeat."""
    from temporalio.common import WorkflowIDReusePolicy
    from temporalio.exceptions import WorkflowAlreadyStartedError
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Worker

    assert temporal_worker.temporal_available()
    monkeypatch.setattr(temporal_worker, "_HEARTBEAT_INTERVAL_SECONDS", 0.05)
    heartbeats = []
    original_heartbeat = temporal_worker._heartbeat_checkpoint

    def tracked_heartbeat(stage: str, task_id: str) -> None:
        heartbeats.append((stage, task_id))
        original_heartbeat(stage, task_id)

    monkeypatch.setattr(temporal_worker, "_heartbeat_checkpoint", tracked_heartbeat)
    # start_local() provisions and tears down its own SQLite-backed Temporal
    # process; no docker, existing ports, or project databases are involved.
    async with await WorkflowEnvironment.start_local(ip="127.0.0.1", port=None) as env:
        task, orch, activities = authorized_worker()
        task.id = "task-temporal-live-" + uuid.uuid4().hex[:12]
        queue = "osop-qual-" + uuid.uuid4().hex[:12]

        async def synthetic_activity(_task):
            await asyncio.sleep(0.18)
            return {"status": "success", "source": "synthetic"}

        orch._execute_task_durable.side_effect = synthetic_activity
        async with Worker(
            env.client,
            task_queue=queue,
            workflows=[temporal_worker.TaskWorkflow],
            activities=[activities.execute_task_activity],
            workflow_runner=temporal_worker._sandboxed_workflow_runner(),
        ):
            result = await asyncio.wait_for(
                env.client.execute_workflow(
                    temporal_worker.TaskWorkflow.run,
                    task.model_dump(mode="json"),
                    id="ai-osop-" + task.id,
                    task_queue=queue,
                ),
                timeout=20,
            )
        assert result == {"status": "success", "source": "synthetic"}
        assert ("authorized", task.id) in heartbeats
        assert ("running", task.id) in heartbeats
        assert ("result_received", task.id) in heartbeats
        orch._execute_task_durable.assert_awaited_once()
        orch.supervision_store.start_attempt.assert_awaited_once()
        orch.supervision_store.mark_execution_dispatched.assert_awaited_once()
        orch._on_task_success.assert_awaited_once()

        # After completion, a second start with the same workflow ID must be
        # rejected by the real Temporal service (not just our process cache).
        with pytest.raises(WorkflowAlreadyStartedError):
            await env.client.start_workflow(
                temporal_worker.TaskWorkflow.run,
                task.model_dump(mode="json"),
                id="ai-osop-" + task.id,
                task_queue=queue,
                id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
            )
        scheduler = temporal_worker.TemporalTaskScheduler(client=env.client)
        assert await scheduler.start_task_workflow(task.model_dump(mode="json")) == (
            "ai-osop-" + task.id
        )
        orch._execute_task_durable.assert_awaited_once()

        # Simulate replay after a crashed worker already committed the attempt.
        # A new Temporal workflow must not reissue an intrusive command.
        duplicate_task, duplicate_orch, duplicate_activities = authorized_worker()
        duplicate_task.id = "task-temporal-replay-" + uuid.uuid4().hex[:12]
        duplicate_orch.supervision_store.start_attempt.return_value = {
            "id": "run-prior", "revision": 0, "created": False,
        }
        async with Worker(
            env.client,
            task_queue=queue,
            workflows=[temporal_worker.TaskWorkflow],
            activities=[duplicate_activities.execute_task_activity],
            workflow_runner=temporal_worker._sandboxed_workflow_runner(),
        ):
            replay_result = await asyncio.wait_for(
                env.client.execute_workflow(
                    temporal_worker.TaskWorkflow.run,
                    duplicate_task.model_dump(mode="json"),
                    id="ai-osop-" + duplicate_task.id,
                    task_queue=queue,
                ),
                timeout=20,
            )
        assert replay_result["status"] == "execution_unknown"
        duplicate_orch._execute_task_durable.assert_not_awaited()
        duplicate_orch._on_task_success.assert_not_awaited()


async def test_disposable_temporal_service_cancellation_is_not_remote_stop():
    """A Temporal CANCELED status is not evidence an external scanner stopped."""
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Worker

    assert temporal_worker.temporal_available()
    async with await WorkflowEnvironment.start_local(ip="127.0.0.1", port=None) as env:
        task, orch, activities = authorized_worker()
        task.id = "task-temporal-cancel-" + uuid.uuid4().hex[:12]
        queue = "osop-qual-" + uuid.uuid4().hex[:12]
        started = asyncio.Event()
        quarantined = asyncio.Event()
        release_synthetic = asyncio.Event()
        synthetic_finished = asyncio.Event()

        async def synthetic_activity(_task):
            started.set()
            try:
                await release_synthetic.wait()
            finally:
                synthetic_finished.set()

        async def mark_quarantine(_task):
            quarantined.set()

        orch._execute_task_durable.side_effect = synthetic_activity
        orch._quarantine_unknown_execution.side_effect = mark_quarantine
        try:
            async with Worker(
                env.client,
                task_queue=queue,
                workflows=[temporal_worker.TaskWorkflow],
                activities=[activities.execute_task_activity],
                workflow_runner=temporal_worker._sandboxed_workflow_runner(),
            ):
                handle = await env.client.start_workflow(
                    temporal_worker.TaskWorkflow.run,
                    task.model_dump(mode="json"),
                    id="ai-osop-" + task.id,
                    task_queue=queue,
                )
                await asyncio.wait_for(started.wait(), timeout=20)
                receipt = await temporal_worker.TemporalTaskScheduler(
                    client=env.client
                ).cancel_task_workflow(task.id)
                assert receipt["accepted"] is True
                # The scheduler's workflow-only status must never claim that
                # a separate MCP/external scanner has terminated.
                assert "remote_stopped" not in receipt
                assert receipt["status"] in {
                    "cancellation_requested", "confirmed_stopped",
                }
                try:
                    await asyncio.wait_for(handle.result(), timeout=20)
                except Exception:
                    pass  # Expected: cancelled Temporal workflow
                else:
                    raise AssertionError("Cancelled Temporal workflow unexpectedly succeeded")
                await asyncio.wait_for(quarantined.wait(), timeout=5)
                orch._on_task_success.assert_not_awaited()
                orch._on_task_failure.assert_not_awaited()
        finally:
            # Temporal workflow termination does not itself prove that the
            # externally executing coroutine has stopped. Release the purely
            # synthetic test task so no background mock survives pytest.
            release_synthetic.set()
            await asyncio.wait_for(synthetic_finished.wait(), timeout=3)
