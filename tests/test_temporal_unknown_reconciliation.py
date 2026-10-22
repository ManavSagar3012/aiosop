"""Provider observation for uncertain Temporal starts cannot replay side effects."""

import asyncio
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
import uuid

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.exceptions import WorkflowException
from ai_osop.core.models import Task
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.orchestrator.orchestrator import Orchestrator
from ai_osop.orchestrator.temporal_worker import TemporalTaskScheduler


def _description(status="RUNNING", **overrides):
    data = {
        "id": "ai-osop-task-one",
        "namespace": "default",
        "task_queue": "safe-queue",
        "workflow_type": "TaskWorkflow",
        "run_id": "provider-run-123",
        "status": SimpleNamespace(name=status),
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def _provider(status="RUNNING", **overrides):
    handle = SimpleNamespace(describe=AsyncMock(return_value=_description(status, **overrides)))
    client = SimpleNamespace(
        get_workflow_handle=MagicMock(return_value=handle),
        start_workflow=AsyncMock(),
    )
    return (
        TemporalTaskScheduler(client=client, namespace="default", task_queue="safe-queue"),
        client,
        handle,
    )


def _scheduler(task_status="dispatch_unknown"):
    memory = SessionMemory()
    task = Task(
        id="task-one",
        engagement_id="eng-one",
        type="summarize_context",
        agent_type=AgentType.CONTEXT_MANAGER,
        status=task_status,
        payload={"_authorization_version": 3},
    )
    memory.load_task_authoritative = AsyncMock(return_value=task)
    memory.load_task = AsyncMock(
        side_effect=AssertionError("Redis must not authorize reconciliation")
    )
    memory.assert_signed_authorization = AsyncMock(return_value=object())
    memory.claim_temporal_dispatch = AsyncMock(side_effect=AssertionError("No dispatch claim"))
    memory.settle_temporal_dispatch = AsyncMock(side_effect=AssertionError("No settlement"))
    memory.store_task = AsyncMock(side_effect=AssertionError("No task mutation"))
    orch = Orchestrator(memory, AsyncMock(), AsyncMock(), AsyncMock())
    orch.temporal_enabled = True
    orch.temporal_scheduler, client, handle = _provider()
    orch._validate_temporal_task_scope = MagicMock()
    return orch.task_scheduler, memory, task, client, handle


@pytest.mark.parametrize(
    "status, expected",
    [
        ("RUNNING", "running"),
        ("WORKFLOW_EXECUTION_STATUS_COMPLETED", "completed"),
        ("FAILED", "failed"),
        ("CANCELED", "canceled"),
        ("TERMINATED", "terminated"),
        ("TIMED_OUT", "timed_out"),
        ("CONTINUED_AS_NEW", "continued_as_new"),
    ],
)
@pytest.mark.asyncio
async def test_provider_observation_proves_only_temporal_state(status, expected):
    provider, client, handle = _provider(status)
    receipt = await provider.observe_task_workflow("task-one")
    assert receipt == {
        "workflow_id": "ai-osop-task-one",
        "observation": "found",
        "provider_status": expected,
        "verified": True,
        "safe_to_retry": False,
        "external_effect_status": "unknown",
        "run_id": "provider-run-123",
    }
    client.get_workflow_handle.assert_called_once_with("ai-osop-task-one")
    handle.describe.assert_awaited_once()
    client.start_workflow.assert_not_awaited()


@pytest.mark.parametrize(
    "bad",
    [
        {"id": "ai-osop-task-other"},
        {"namespace": "other"},
        {"task_queue": "other"},
        {"workflow_type": "OtherWorkflow"},
        {"run_id": ""},
        {"status": None},
        {"status": SimpleNamespace(name="UNRECOGNIZED")},
    ],
)
@pytest.mark.asyncio
async def test_mismatched_provider_identity_or_status_is_unverified(bad):
    provider, client, _ = _provider(**bad)
    receipt = await provider.observe_task_workflow("task-one")
    assert receipt["observation"] == "unknown"
    assert receipt["provider_status"] == "unknown"
    assert receipt["verified"] is False
    assert receipt["safe_to_retry"] is False
    client.start_workflow.assert_not_awaited()


@pytest.mark.asyncio
async def test_not_found_does_not_authorize_a_replay():
    from temporalio.service import RPCError, RPCStatusCode

    provider, client, handle = _provider()
    handle.describe.side_effect = RPCError("history expired", RPCStatusCode.NOT_FOUND, b"")
    receipt = await provider.observe_task_workflow("task-one")
    assert receipt["observation"] == "not_found"
    assert receipt["verified"] is False
    assert receipt["safe_to_retry"] is False
    client.start_workflow.assert_not_awaited()


@pytest.mark.parametrize(
    "failure", [TimeoutError("describe timeout"), ConnectionError("network unavailable")]
)
@pytest.mark.asyncio
async def test_provider_failure_cannot_fabricate_a_workflow_receipt(failure):
    provider, client, handle = _provider()
    handle.describe.side_effect = failure
    receipt = await provider.observe_task_workflow("task-one")
    assert receipt["observation"] == "unknown"
    assert receipt["verified"] is False
    client.start_workflow.assert_not_awaited()


@pytest.mark.asyncio
async def test_cancelled_observation_propagates_without_reissuing():
    provider, client, handle = _provider()
    handle.describe.side_effect = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await provider.observe_task_workflow("task-one")
    client.start_workflow.assert_not_awaited()


@pytest.mark.asyncio
async def test_signed_postgres_task_observation_never_mutates_or_claims():
    scheduler, memory, task, client, handle = _scheduler()
    handle.describe.return_value = _description("COMPLETED")
    result = await scheduler.reconcile_temporal_dispatch("task-one", "eng-one")
    assert result["task_status"] == "dispatch_unknown"
    assert result["provider_status"] == "completed"
    assert result["durable_status_changed"] is False
    assert result["external_effect_status"] == "unknown"
    assert result["safe_to_retry"] is False
    assert task.status == "dispatch_unknown"
    memory.load_task_authoritative.assert_awaited_once_with("task-one")
    memory.assert_signed_authorization.assert_awaited_once_with(
        "eng-one",
        expected_version=3,
    )
    memory.claim_temporal_dispatch.assert_not_awaited()
    memory.settle_temporal_dispatch.assert_not_awaited()
    memory.store_task.assert_not_awaited()
    client.start_workflow.assert_not_awaited()
    await scheduler._dispatch_temporal_task(task)
    client.start_workflow.assert_not_awaited()


@pytest.mark.asyncio
async def test_dispatching_claim_is_observed_without_reclaiming():
    scheduler, memory, task, _, _ = _scheduler("dispatching")
    receipt = await scheduler.reconcile_temporal_dispatch(task.id, task.engagement_id)
    assert receipt["task_status"] == "dispatching"
    assert receipt["observation"] == "found"
    assert task.status == "dispatching"
    memory.claim_temporal_dispatch.assert_not_awaited()


@pytest.mark.asyncio
async def test_foreign_engagement_does_not_query_provider():
    scheduler, memory, task, client, _ = _scheduler()
    with pytest.raises(PermissionError, match="unavailable"):
        await scheduler.reconcile_temporal_dispatch(task.id, "eng-foreign")
    memory.assert_signed_authorization.assert_not_awaited()
    client.get_workflow_handle.assert_not_called()


@pytest.mark.asyncio
async def test_absent_or_unsigned_task_does_not_query_provider():
    scheduler, memory, task, client, _ = _scheduler()
    task.payload.clear()
    with pytest.raises(PermissionError, match="authorization"):
        await scheduler.reconcile_temporal_dispatch(task.id, task.engagement_id)
    client.get_workflow_handle.assert_not_called()
    task.payload["_authorization_version"] = 3
    memory.assert_signed_authorization.side_effect = PermissionError("revoked")
    with pytest.raises(PermissionError):
        await scheduler.reconcile_temporal_dispatch(task.id, task.engagement_id)
    client.get_workflow_handle.assert_not_called()


@pytest.mark.asyncio
async def test_other_state_skips_provider_even_with_valid_signer():
    scheduler, memory, task, client, _ = _scheduler("scheduled")
    receipt = await scheduler.reconcile_temporal_dispatch(task.id, task.engagement_id)
    assert receipt["observation"] == "not_applicable"
    assert receipt["durable_status_changed"] is False
    memory.assert_signed_authorization.assert_not_awaited()
    client.get_workflow_handle.assert_not_called()


@pytest.mark.asyncio
async def test_store_outage_returns_error_without_provider_lookup():
    scheduler, memory, task, client, _ = _scheduler()
    memory.load_task_authoritative.side_effect = OSError("Postgres unavailable")
    with pytest.raises(WorkflowException, match="store unavailable"):
        await scheduler.reconcile_temporal_dispatch(task.id, task.engagement_id)
    client.get_workflow_handle.assert_not_called()


@pytest.mark.skipif(
    os.getenv("OSOP_TEMPORAL_LIVE_TEST") != "1",
    reason="Requires opt-in disposable localhost Temporal service",
)
@pytest.mark.asyncio
async def test_real_temporal_describe_receipt_is_read_only():
    """An isolated service proves metadata parity without any target activity."""
    from temporalio import activity
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Worker

    from ai_osop.orchestrator.temporal_worker import TaskWorkflow, _sandboxed_workflow_runner

    task_id = "task-reconcile-" + uuid.uuid4().hex[:12]
    queue = "reconcile-test-" + uuid.uuid4().hex[:12]
    release = asyncio.Event()
    calls = []

    @activity.defn(name="execute_task_activity")
    async def synthetic_activity(_data: dict) -> dict:
        calls.append("synthetic")
        await release.wait()
        return {"status": "synthetic_completed"}

    async with await WorkflowEnvironment.start_local(ip="127.0.0.1", port=None) as env:
        provider = TemporalTaskScheduler(
            client=env.client,
            namespace="default",
            task_queue=queue,
        )
        async with Worker(
            env.client,
            task_queue=queue,
            workflows=[TaskWorkflow],
            activities=[synthetic_activity],
            workflow_runner=_sandboxed_workflow_runner(),
        ):
            workflow_id = await provider.start_task_workflow(
                {"id": task_id, "timeout_seconds": 10},
            )
            try:
                for _ in range(30):
                    receipt = await provider.observe_task_workflow(task_id)
                    if receipt["observation"] == "found":
                        break
                    await asyncio.sleep(0.05)
                assert receipt["observation"] == "found"
                assert receipt["provider_status"] == "running"
                assert receipt["workflow_id"] == workflow_id
                assert receipt["external_effect_status"] == "unknown"
                assert receipt["safe_to_retry"] is False
            finally:
                release.set()
            result = await asyncio.wait_for(
                env.client.get_workflow_handle(workflow_id).result(),
                timeout=10,
            )
            assert result["status"] == "synthetic_completed"
            finished = await provider.observe_task_workflow(task_id)
            assert finished["provider_status"] == "completed"
            assert finished["external_effect_status"] == "unknown"
            assert finished["safe_to_retry"] is False
        assert calls == ["synthetic"]
