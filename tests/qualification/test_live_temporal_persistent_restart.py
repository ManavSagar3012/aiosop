"""Opt-in real Temporal server restart qualification on isolated loopback.

Run phase=create against a disposable Temporal development server started
with a persistent SQLite db-filename. STOP ONLY that owned container, start
a NEW container with the SAME test-only volume, then run phase=recovered.
No existing Temporal instance, application DB, agents, LLM or targets touched.
"""

import asyncio
import os
from types import SimpleNamespace

import pytest

from tests.qualification.test_live_temporal_admission_recovery import _local_worker
from ai_osop.orchestrator.temporal_worker import TemporalTaskScheduler


def _config():
    address = os.environ.get("OSOP_TEMPORAL_PERSIST_QUAL_ADDRESS", "")
    phase = os.environ.get("OSOP_TEMPORAL_PERSIST_QUAL_PHASE", "")
    workflow_id = os.environ.get("OSOP_TEMPORAL_PERSIST_QUAL_WORKFLOW_ID", "")
    if not all((address, phase, workflow_id)):
        pytest.skip("Isolated persisted Temporal restart qualification not configured")
    if (
        address != "127.0.0.1:50486"
        or phase not in {"create", "recovered"}
        or not workflow_id.startswith("ai-osop-task-temporal-persist-qual-")
        or len(workflow_id) > 64
    ):
        pytest.fail("Refusing unrelated Temporal host or non-disposable workflow identity")
    return address, phase, workflow_id


@pytest.mark.asyncio
async def test_temporal_server_restart_preserves_completed_history_and_rejects_replay():
    address, phase, workflow_id = _config()
    from temporalio.client import Client, WorkflowExecutionStatus
    from temporalio.common import WorkflowIDReusePolicy
    from temporalio.exceptions import WorkflowAlreadyStartedError
    from ai_osop.orchestrator.temporal_worker import TaskWorkflow

    client = await asyncio.wait_for(Client.connect(address), timeout=8)
    queue = "temporal-persist-qual-no-external-traffic"
    candidate = {"id": workflow_id.removeprefix("ai-osop-"), "timeout_seconds": 10}
    # The actual scheduler deterministically prefixes all Task IDs.
    scheduler = TemporalTaskScheduler(client=client, task_queue=queue)
    if phase == "create":
        invocations = []
        async with _local_worker(client, queue, counter=invocations):
            received_id = await scheduler.start_task_workflow(candidate)
            assert received_id == workflow_id
            result = await asyncio.wait_for(
                client.get_workflow_handle(workflow_id).result(), timeout=20,
            )
            assert result == {"status": "synthetic_complete", "remote_targets": 0}
        assert invocations == ["invoked"]
    else:
        # A new process after the server container has been recreated.
        handle = client.get_workflow_handle(workflow_id)
        assert await asyncio.wait_for(handle.result(), timeout=12) == {
            "status": "synthetic_complete", "remote_targets": 0,
        }
        description = await handle.describe()
        assert description.status == WorkflowExecutionStatus.COMPLETED
        with pytest.raises(WorkflowAlreadyStartedError):
            await client.start_workflow(
                TaskWorkflow.run, candidate, id=workflow_id, task_queue=queue,
                id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
            )
