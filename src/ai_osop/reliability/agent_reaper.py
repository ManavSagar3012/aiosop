import asyncio
import logging
from datetime import datetime
from typing import Any

from ai_osop.core.config import AgentState
from ai_osop.core.metrics import (
    AGENT_RECOVERIES_TOTAL,
    AGENT_TIMEOUTS_TOTAL,
    TASK_REQUEUES_TOTAL,
)
from ai_osop.core.models import AuditEvent

logger = logging.getLogger("ai_osop.reliability.agent_reaper")


class AgentReaper:
    def __init__(self, orchestrator: Any):
        self.orch = orchestrator
        self.interval = 15
        self.heartbeat_timeout = 60

    async def run(self) -> None:
        while True:
            try:
                await self._reap()
            except Exception as e:
                logger.error(f"reaper_error: {e}")
            await asyncio.sleep(self.interval)

    async def _reap(self) -> None:
        agents = await self.orch.session_memory.get_all_agents()
        logger.debug(f"Found {len(agents)} agents: {list(agents.keys())}")
        for agent_id, agent_info in agents.items():
            heartbeat = await self.orch.session_memory.get_agent_heartbeat(agent_id)
            logger.debug(f"Agent {agent_id} heartbeat: {heartbeat}")
            if not heartbeat:
                continue

            last_seen = datetime.fromisoformat(heartbeat["last_seen"])
            now = datetime.utcnow()
            age = (now - last_seen).total_seconds()
            logger.debug(f"Agent {agent_id} last_seen: {last_seen}, now: {now}, age: {age}")
            if age > self.heartbeat_timeout:
                logger.debug(f"Reaper triggered for agent: {agent_id}")
                logger.warning(f"agent_dead: {agent_id}")
                AGENT_TIMEOUTS_TOTAL.inc()
                await self._recover_agent(agent_id)
                AGENT_RECOVERIES_TOTAL.inc()

    async def _recover_agent(self, agent_id: str) -> None:
        lock_key = f"agent-recovery:{agent_id}"
        if await self.orch.session_memory.acquire_lock(lock_key, ttl=30):
            try:
                tasks = await self.orch.session_memory.find_tasks_by_agent(agent_id)
                from ai_osop.core.models import Task

                logger.debug(f"Reaper found {len(tasks)} tasks for agent")
                for task_dict in tasks:
                    logger.debug(
                        f"Examining task {task_dict.get('id')}, status={task_dict.get('status')}"
                    )
                    if task_dict.get("status") == "running":
                        logger.debug(f"Recovering task {task_dict.get('id')}")
                        task_dict["status"] = "pending"
                        task_dict["assigned_agent_id"] = None
                        task_dict["lease_expires"] = None
                        task_dict["retry_count"] = task_dict.get("retry_count", 0) + 1

                        task = Task(**task_dict)
                        await self.orch.graph_memory.upsert_task(task)
                        await self.orch.session_memory.store_task(task)
                        await self.orch.task_scheduler.schedule_task(task)
                        TASK_REQUEUES_TOTAL.inc()
                        await self.orch.session_memory.write_audit_event(
                            AuditEvent(
                                event_type="task_recovered",
                                severity="INFO",
                                actor_type="system",
                                actor_id="reaper",
                                action={"task_id": task.id},
                                result={"status": "requeued"},
                                context={},
                                engagement_id=task.engagement_id,
                            )
                        )
                    else:
                        logger.debug(
                            f"Task {task_dict.get('id')} not recovered (status={task_dict.get('status')})"
                        )

                await self.orch.session_memory.update_agent_status(
                    agent_id, AgentState.OFFLINE.value
                )
            finally:
                await self.orch.session_memory.release_lock(lock_key, lock_value="locked")
