import pytest
import asyncio
from datetime import datetime, timedelta
from ai_osop.core.config import AgentState
from ai_osop.core.models import Task

@pytest.mark.asyncio
async def test_agent_recovery_scenarios(orchestrator, session_memory):
    # 1. Create agent status
    await session_memory.store_hot("agent:recon-agent-001", {"status": "running"})
    
    # 2. Create a task and assign to recon-agent-001
    task = Task(type="full_recon", agent_type="recon", engagement_id="eng-123")
    task.status = "running"
    task.assigned_agent_id = "recon-agent-001"
    task.lease_expires = datetime.utcnow() + timedelta(seconds=90)
    await session_memory.store_task(task)

    # 3. Simulate agent heartbeat (old last_seen)
    heartbeat_data = {
        "agent_id": "recon-agent-001",
        "agent_type": "recon",
        "status": "running",
        "task_id": task.id,
        "engagement_id": "eng-123",
        "version": "8.0",
        "last_seen": (datetime.utcnow() - timedelta(seconds=65)).isoformat()
    }
    await session_memory.update_agent_heartbeat("recon-agent-001", heartbeat_data)

    # 4. Run Reaper
    await orchestrator.agent_reaper._reap()

    # 5. Verify task recovered
    recovered_task = await session_memory.retrieve_hot(f"task:{task.id}")
    assert recovered_task["status"] == "pending"
    assert recovered_task.get("assigned_agent_id") is None
    assert recovered_task.get("retry_count") == 1

    # Verify Agent status
    agent_status = await session_memory.retrieve_hot("agent:recon-agent-001")
    assert agent_status["status"] == AgentState.OFFLINE.value

print("All tests passed.")
