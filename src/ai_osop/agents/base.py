"""
Base Agent Architecture
Abstract base class for all AI-OSOP agents with lifecycle management,
memory integration, and structured reasoning.
"""

import asyncio
import json
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from ai_osop.core.config import AgentType, settings
from ai_osop.core.exceptions import AgentException, AgentTaskFailed
from ai_osop.core.models import AuditEvent, SessionState, Task
from ai_osop.core.observability import record_task
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.memory.vector_memory import VectorMemory


class AgentContext:
    """Runtime context provided to agents."""

    def __init__(
        self,
        agent_id: str,
        agent_type: AgentType,
        session_id: str,
        session_memory: SessionMemory,
        graph_memory: GraphMemory,
        vector_memory: VectorMemory,
        llm_client: Any,  # LiteLLMClient
        mcp_registry: Any,
        rate_limiter: Any,
        threat_intel_adapter: Any,
        audit_callback: Callable[[AuditEvent], None],
        coordination_bus: Any,
    ):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.session_id = session_id
        self.session_memory = session_memory
        self.graph_memory = graph_memory
        self.vector_memory = vector_memory
        self.llm_client = llm_client
        self.mcp_registry = mcp_registry
        self.rate_limiter = rate_limiter
        self.threat_intel_adapter = threat_intel_adapter
        self.audit_callback = audit_callback
        self.coordination_bus = coordination_bus

        self.working_memory: Dict[str, Any] = {}
        self.task_history: List[str] = []
        self.current_task: Optional[Task] = None
        self.status = "idle"
        self.last_heartbeat = datetime.utcnow()


class BaseAgent(ABC):
    """
    Abstract base for all AI-OSOP agents.

    Lifecycle:
    1. initialize() → Setup working memory, load prior context
    2. execute_task(task) → Process assigned task
    3. heartbeat() → Report status, handle health checks
    4. shutdown() → Persist state, cleanup resources
    """

    def __init__(self, context: AgentContext):
        self.ctx = context
        self._running = False
        self._task_queue: asyncio.Queue = asyncio.Queue()
        self._max_concurrent_tasks = 3
        self._active_tasks: Dict[str, asyncio.Task] = {}

    @property
    @abstractmethod
    def agent_type(self) -> AgentType:
        """Return the agent's type."""
        pass

    async def initialize(self) -> None:
        """Initialize agent state from persistent memory."""
        self.ctx.status = "initializing"

        # Load prior working memory if exists
        prior_state = await self.ctx.session_memory.get_agent_state(self.ctx.agent_id)
        if prior_state:
            self.ctx.working_memory = prior_state.get("working_memory", {})
            self.ctx.task_history = prior_state.get("task_history", [])

        # Initialize agent-specific resources
        await self._setup_resources()

        self.ctx.status = "idle"
        self._running = True

        # Start task worker and heartbeat loop
        asyncio.create_task(self._task_worker())
        asyncio.create_task(self._heartbeat_loop())

    async def _task_worker(self) -> None:
        """Background worker to process tasks from the queue."""
        while self._running:
            try:
                task = await self._task_queue.get()
                await self.execute_task(task)
                self._task_queue.task_done()
            except Exception as e:
                print(f"Worker error in agent {self.ctx.agent_id}: {e}")
                await asyncio.sleep(5)

    @abstractmethod
    async def _setup_resources(self) -> None:
        """Agent-specific resource initialization."""
        pass

    async def execute_task(self, task: Task) -> Dict[str, Any]:
        """
        Execute a task with full lifecycle management.

        1. Validate task
        2. Load context
        3. Execute (agent-specific)
        4. Validate output
        5. Store results
        6. Audit logging
        """
        self.ctx.current_task = task
        self.ctx.status = "running"

        target = task.payload.get("target") or task.payload.get("url") or task.payload.get("domain")
        tool = self.ctx.agent_type.value

        # Rate Limiting
        await self.ctx.rate_limiter.acquire(target=target, tool=tool)

        task.started_at = datetime.utcnow()
        start_time = time.monotonic()

        try:
            # Pre-execution validation
            await self._validate_task(task)

            # Execute agent-specific logic
            result = await self._execute(task)

            end_time = time.monotonic()
            if target:
                self.ctx.rate_limiter.record_backpressure(target, end_time - start_time)

            # Post-execution validation
            validated_result = await self._validate_output(result)

            # Store results
            task.result = validated_result
            task.status = "completed"
            task.completed_at = datetime.utcnow()

            # Update working memory
            self.ctx.task_history.append(task.id)
            await self._update_working_memory(task, validated_result)

            # Audit log
            await self._log_task_completion(task, validated_result)
            record_task(
                task.status,
                self.ctx.agent_type.value,
                (
                    (task.completed_at - task.started_at).total_seconds()
                    if task.completed_at and task.started_at
                    else 0.0
                ),
            )

            return validated_result

        except Exception as e:
            task.status = "failed"
            task.retry_count += 1
            task.completed_at = datetime.utcnow()

            await self._log_task_failure(task, e)

            if task.retry_count < task.max_retries:
                # Schedule retry with exponential backoff
                delay = 5 * (2**task.retry_count)
                asyncio.create_task(self._schedule_retry(task, delay))
            else:
                raise AgentTaskFailed(
                    f"Task {task.id} failed after {task.max_retries} retries: {e}"
                )

            return {"status": "failed", "error": str(e)}

        finally:
            self.ctx.current_task = None
            self.ctx.status = "idle"
            self.ctx.last_heartbeat = datetime.utcnow()

    @abstractmethod
    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Agent-specific task execution logic."""
        pass

    async def _validate_task(self, task: Task) -> None:
        """Validate task before execution."""
        # Check scope if required
        if task.scope_check:
            # Scope validation logic here
            pass

        # Check dependencies
        for dep_id in task.dependencies:
            # Verify dependency completed
            pass

    async def _validate_output(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Validate agent output against schema."""
        # Schema validation
        # Hallucination detection
        # Confidence threshold checks
        return result

    async def _update_working_memory(self, task: Task, result: Dict[str, Any]) -> None:
        """Update agent working memory with task results."""
        self.ctx.working_memory[task.id] = {
            "type": task.type,
            "status": task.status,
            "result_summary": self._summarize_result(result),
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Persist to hot memory
        await self.ctx.session_memory.store_agent_state(
            self.ctx.agent_id,
            {
                "working_memory": self.ctx.working_memory,
                "task_history": self.ctx.task_history,
                "status": self.ctx.status,
            },
        )

    def _summarize_result(self, result: Dict[str, Any]) -> str:
        """Create human-readable summary of result for memory."""
        return json.dumps(result, default=str)[:500]

    async def _log_task_completion(self, task: Task, result: Dict[str, Any]) -> None:
        """Write audit log for task completion."""
        target = task.payload.get("target") or task.payload.get("domain") or task.payload.get("url") or "unknown"
        event = AuditEvent(
            event_type="task_completed",
            severity="info",
            actor_type="agent",
            actor_id=self.ctx.agent_id,
            action={
                "task_id": task.id,
                "task_type": task.type,
                "target": target,
            },
            result={
                "status": task.status,
                "execution_time": (
                    (task.completed_at - task.started_at).total_seconds()
                    if task.completed_at and task.started_at
                    else 0
                ),
                "reasoning": result.get("reasoning", ""),
            },
            context={"session_id": self.ctx.session_id, "agent_type": self.ctx.agent_type.value},
            engagement_id=task.engagement_id,
        )
        await self.ctx.audit_callback(event)

    async def _log_task_failure(self, task: Task, error: Exception) -> None:
        """Write audit log for task failure."""
        event = AuditEvent(
            event_type="task_failed",
            severity="warning",
            actor_type="agent",
            actor_id=self.ctx.agent_id,
            action={"task_id": task.id, "task_type": task.type, "retry_count": task.retry_count},
            result={"error": str(error), "error_type": type(error).__name__},
            context={"session_id": self.ctx.session_id, "agent_type": self.ctx.agent_type.value},
            engagement_id=task.engagement_id,
        )
        await self.ctx.audit_callback(event)

    async def _schedule_retry(self, task: Task, delay: int) -> None:
        """Schedule task retry with delay."""
        await asyncio.sleep(delay)
        await self._task_queue.put(task)

    async def _heartbeat_loop(self) -> None:
        """Periodic heartbeat for health monitoring."""
        while self._running:
            self.ctx.last_heartbeat = datetime.utcnow()
            await self.ctx.session_memory.store_agent_state(
                self.ctx.agent_id,
                {
                    "status": self.ctx.status,
                    "last_heartbeat": self.ctx.last_heartbeat.isoformat(),
                    "current_task": self.ctx.current_task.id if self.ctx.current_task else None,
                    "task_queue_depth": self._task_queue.qsize(),
                },
                ttl=60,
            )
            await asyncio.sleep(30)

    async def shutdown(self) -> None:
        """Graceful shutdown with state preservation."""
        self._running = False
        self.ctx.status = "shutting_down"

        # Cancel active tasks
        for task in self._active_tasks.values():
            task.cancel()

        # Persist final state
        await self.ctx.session_memory.store_agent_state(
            self.ctx.agent_id,
            {
                "working_memory": self.ctx.working_memory,
                "task_history": self.ctx.task_history,
                "status": "shutdown",
                "shutdown_at": datetime.utcnow().isoformat(),
            },
            ttl=86400,
        )

        await self._cleanup_resources()

    @abstractmethod
    async def _cleanup_resources(self) -> None:
        """Agent-specific resource cleanup."""
        pass

    async def get_status(self) -> Dict[str, Any]:
        """Get current agent status."""
        return {
            "agent_id": self.ctx.agent_id,
            "agent_type": self.ctx.agent_type.value,
            "status": self.ctx.status,
            "current_task": self.ctx.current_task.id if self.ctx.current_task else None,
            "task_queue_depth": self._task_queue.qsize(),
            "last_heartbeat": self.ctx.last_heartbeat.isoformat(),
            "working_memory_keys": list(self.ctx.working_memory.keys()),
        }

    def _load_skill(self, skill_name: str) -> str:
        """Load skill instructions from the local skills directory."""
        import os

        skill_path = os.path.join(os.path.dirname(__file__), "skills", f"{skill_name}.md")
        if not os.path.exists(skill_path):
            return ""
        with open(skill_path, "r", encoding="utf-8") as f:
            return f.read()

    def _get_relevant_skills(self, task: Task) -> List[str]:
        """Dynamically resolve relevant skills for a task."""
        import os
        from ai_osop.core.config import TASK_SKILL_MAP

        # 1. Check static configuration map
        skills = TASK_SKILL_MAP.get(task.type, [])
        if skills:
            return skills

        # 2. Dynamic discovery: Check for exact match or substring match
        skill_dir = os.path.join(os.path.dirname(__file__), "skills")
        matched_skills = []
        
        # Normalize task type for matching (e.g., 'burp_scan' -> 'burp-scan')
        normalized_type = task.type.lower().replace("_", "-")
        search_terms = [normalized_type] + normalized_type.split("-")
        
        try:
            for f in os.listdir(skill_dir):
                if not f.endswith(".md"):
                    continue
                
                skill_name = f[:-3]
                
                # Exact match
                if skill_name == task.type or skill_name == normalized_type:
                    return [skill_name]
                    
                # Keyword matching
                for term in search_terms:
                    if len(term) > 3 and term in skill_name:
                        matched_skills.append(skill_name)
                        break
        except Exception as e:
            print(f"WARN: Error during dynamic skill discovery: {e}")

        # Return up to 3 dynamically matched skills to avoid overwhelming the context window
        return matched_skills[:3]
