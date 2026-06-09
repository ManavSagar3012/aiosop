import asyncio

import pytest

from ai_osop.orchestrator.coordination_bus import AgentCoordinationBus


@pytest.mark.asyncio
async def test_coordination_bus_publish_subscribe() -> None:
    bus = AgentCoordinationBus()

    async def receive_once() -> str:
        async for event in bus.subscribe("task.completed"):
            return event.payload["task_id"]
        return ""

    task = asyncio.create_task(receive_once())
    await asyncio.sleep(0)

    await bus.publish("task.completed", {"task_id": "task-1"}, "test")

    assert await asyncio.wait_for(task, timeout=1.0) == "task-1"


def test_coordination_bus_counts_subscribers() -> None:
    bus = AgentCoordinationBus()

    assert bus.subscriber_count("missing") == 0
