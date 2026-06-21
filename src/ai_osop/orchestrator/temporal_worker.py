"""
Temporal Worker
Durable task execution using Temporal.io workflows.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict, Optional

try:
    from temporalio import workflow
    from temporalio.client import Client
    from temporalio.worker import Worker
except ModuleNotFoundError:  # pragma: no cover - exercised through availability checks
    workflow = None
    Client = None
    Worker = None

from ai_osop.core.config import settings


class TemporalUnavailableError(RuntimeError):
    """Raised when Temporal is enabled but the SDK is unavailable."""


def temporal_available() -> bool:
    """Return whether the Temporal Python SDK can be used."""
    return workflow is not None and Client is not None and Worker is not None


# Activities
if workflow is not None:

    @workflow.defn
    class TaskWorkflow:
        @workflow.run
        async def run(self, task_data: dict) -> dict:
            result = await workflow.execute_activity(
                "execute_task_activity",
                task_data,
                start_to_close_timeout=timedelta(
                    seconds=int(task_data.get("timeout_seconds", 600))
                ),
            )
            return result

    @workflow.activity.defn
    async def execute_task_activity(task_data: dict) -> dict:
        return {"status": "queued", "task_id": task_data.get("id"), "durable": True}

else:

    class TaskWorkflow:  # type: ignore[no-redef]
        """Placeholder used when temporalio is not installed."""

    async def execute_task_activity(task_data: dict) -> dict:
        raise TemporalUnavailableError("temporalio is not installed")


class TemporalTaskScheduler:
    """Small adapter around Temporal workflow startup."""

    def __init__(
        self,
        client: Optional[Any] = None,
        *,
        address: Optional[str] = None,
        namespace: Optional[str] = None,
        task_queue: Optional[str] = None,
    ):
        self.client = client
        self.address = address or settings.temporal_address
        self.namespace = namespace or settings.temporal_namespace
        self.task_queue = task_queue or settings.temporal_task_queue

    async def connect(self) -> None:
        """Connect to Temporal if no client was injected."""
        if self.client is not None:
            return
        if Client is None:
            raise TemporalUnavailableError("temporalio is not installed")

        self.client = await Client.connect(self.address, namespace=self.namespace)

    async def start_task_workflow(self, task_data: Dict[str, Any]) -> str:
        """Start a durable task workflow and return the workflow id."""
        await self.connect()
        workflow_id = f"ai-osop-{task_data['id']}"
        workflow_entrypoint = getattr(TaskWorkflow, "run", "TaskWorkflow")
        await self.client.start_workflow(
            workflow_entrypoint,
            task_data,
            id=workflow_id,
            task_queue=self.task_queue,
        )
        return workflow_id


class TaskActivities:
    """Class wrapper for Temporal activities using orchestrator context."""

    def __init__(self, orchestrator: Any):
        self.orchestrator = orchestrator

    async def execute_task_activity(self, task_data: dict) -> dict:
        try:
            from ai_osop.core.models import Task

            task = Task(**task_data)
            result = await self.orchestrator._execute_task_durable(task)
            return result
        except Exception as e:
            return {"status": "failed", "error": str(e)}


if workflow is not None:
    # Decorate TaskActivities.execute_task_activity as a Temporal activity
    TaskActivities.execute_task_activity = workflow.activity.defn(name="execute_task_activity")(
        TaskActivities.execute_task_activity
    )


async def run_worker(activities: Optional[list[Any]] = None) -> None:
    """Run a Temporal worker for AI-OSOP task workflows."""
    if Worker is None:
        raise TemporalUnavailableError("temporalio is not installed")

    scheduler = TemporalTaskScheduler()
    await scheduler.connect()
    worker = Worker(
        scheduler.client,
        task_queue=scheduler.task_queue,
        workflows=[TaskWorkflow],
        activities=activities or [execute_task_activity],
    )
    await worker.run()
