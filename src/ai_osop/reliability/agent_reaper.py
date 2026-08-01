import asyncio
import logging
from datetime import datetime
from typing import Any, Optional

from ai_osop.core.config import settings
from ai_osop.core.enums import AgentState
from ai_osop.core.metrics import AGENT_RECOVERIES_TOTAL, AGENT_TIMEOUTS_TOTAL, TASK_REQUEUES_TOTAL
from ai_osop.core.models import AuditEvent
from ai_osop.orchestrator.state_machine import EngagementStateMachine

logger = logging.getLogger("ai_osop.reliability.agent_reaper")


class AgentReaper:
    def __init__(self, orchestrator: Any, state_machine: Optional[EngagementStateMachine] = None):
        self.orch = orchestrator
        self.state_machine = state_machine or getattr(
            orchestrator, "engagement_state_machine", None
        )
        # AIOSOP-REAPER-001 (2026-07-20): both knobs are config-driven so a
        # deployment with a slow external target can widen them without a code
        # change. Defaults preserve the prior behaviour (15s poll, 60s timeout).
        self.interval = int(settings.agent_reaper_interval_seconds)
        self.heartbeat_timeout = int(settings.agent_reaper_heartbeat_timeout_seconds)

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
                        # DUAL-REAPER RACE FIX (2026-08-01, GAP-6): task recovery must
                        # serialize through ONE per-task lock so the AgentReaper path
                        # and the RecoveryService reaper cannot both touch the same
                        # running task. The recovery lock is long enough to cover the
                        # task post-write window (where Neo4j would previously blip and
                        # the scan completion task slipped to another worker). The
                        # *task-scoped* lock (not a global one) is what actually blocks
                        # concurrent recovery of the same task between both reapers.
                        task_lock_key = f"task-recovery:{task.id}"
                        got_task_lock = await self.orch.session_memory.acquire_lock(
                            task_lock_key, ttl=120
                        )
                        if not got_task_lock:
                            logger.warning(
                                f"task_recovery_skipped_locked task={task.id} agent={agent_id}"
                            )
                            continue
                        try:
                            await self.orch.graph_memory.upsert_task(task)
                            await self.orch.session_memory.store_task(task)
                            await self.orch.task_scheduler.schedule_task(task)
                            TASK_REQUEUES_TOTAL.inc()
                            # AIOSOP-REAPER-INMEM-SYNC: keep the orchestrator's in-memory
                            # task view consistent with this requeue.
                            tasks_map = getattr(self.orch, "_tasks", None)
                            if isinstance(tasks_map, dict):
                                tasks_map[task.id] = task
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
                        finally:
                            await self.orch.session_memory.release_lock(
                                task_lock_key, lock_value="locked"
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
