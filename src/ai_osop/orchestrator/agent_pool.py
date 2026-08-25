"""Per-Engagement Agent Pool (T3.4)

Provides per-engagement agent isolation with resource quotas and
bus topic namespacing. Prevents one engagement from starving others
and ensures bus events are correctly routed.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("ai_osop.orchestrator.agent_pool")


@dataclass
class EngagementQuota:
    """Resource quota for an engagement."""

    engagement_id: str
    max_concurrent_agents: int = 5
    max_tasks_per_second: float = 10
    max_llm_tokens: int = 100000
    max_wall_clock_minutes: int = 60
    priority: int = 5  # 1-10, higher = more resources

    # Runtime tracking
    active_agents: int = 0
    tasks_completed: int = 0
    tokens_used: int = 0
    wall_clock_seconds: float = 0.0

    @property
    def is_agent_limit_reached(self) -> bool:
        return self.active_agents >= self.max_concurrent_agents

    @property
    def is_token_limit_reached(self) -> bool:
        return self.tokens_used >= self.max_llm_tokens

    @property
    def is_time_limit_reached(self) -> bool:
        return self.wall_clock_seconds >= self.max_wall_clock_minutes * 60

    @property
    def can_schedule_more(self) -> bool:
        return (
            not self.is_agent_limit_reached
            and not self.is_token_limit_reached
            and not self.is_time_limit_reached
        )


@dataclass
class AgentPool:
    """Pool of agents dedicated to a single engagement."""

    engagement_id: str
    quota: EngagementQuota
    agents: Dict[str, Any] = field(default_factory=dict)
    task_queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def claim_agent(self, agent_id: str) -> bool:
        """Claim an agent for this engagement. Returns False if quota exceeded."""
        async with self._lock:
            if self.quota.is_agent_limit_reached:
                return False
            self.quota.active_agents += 1
            self.agents[agent_id] = {"status": "claimed", "engagement_id": self.engagement_id}
            return True

    async def release_agent(self, agent_id: str) -> None:
        """Release a claimed agent."""
        async with self._lock:
            self.agents.pop(agent_id, None)
            self.quota.active_agents = max(0, self.quota.active_agents - 1)

    def record_tokens(self, count: int) -> None:
        """Record token usage."""
        self.quota.tokens_used += count

    def record_task_completion(self) -> None:
        """Record a completed task."""
        self.quota.tasks_completed += 1


class AgentPoolManager:
    """Manages per-engagement agent pools.

    Ensures each engagement has its own isolated pool with quotas,
    and provides a global view of resource allocation.
    """

    def __init__(self, global_max_agents: int = 50) -> None:
        self.global_max_agents = global_max_agents
        self._pools: Dict[str, AgentPool] = {}
        self._global_active: int = 0

    def create_pool(
        self,
        engagement_id: str,
        max_concurrent_agents: int = 5,
        max_tasks_per_second: float = 10,
        max_llm_tokens: int = 100000,
        max_wall_clock_minutes: int = 60,
        priority: int = 5,
    ) -> AgentPool:
        """Create a new agent pool for an engagement."""
        if engagement_id in self._pools:
            return self._pools[engagement_id]

        quota = EngagementQuota(
            engagement_id=engagement_id,
            max_concurrent_agents=max_concurrent_agents,
            max_tasks_per_second=max_tasks_per_second,
            max_llm_tokens=max_llm_tokens,
            max_wall_clock_minutes=max_wall_clock_minutes,
            priority=priority,
        )
        pool = AgentPool(engagement_id=engagement_id, quota=quota)
        self._pools[engagement_id] = pool
        logger.info(
            "agent_pool_created engagement_id=%s max_agents=%d priority=%d",
            engagement_id,
            max_concurrent_agents,
            priority,
        )
        return pool

    def get_pool(self, engagement_id: str) -> Optional[AgentPool]:
        """Get the agent pool for an engagement."""
        return self._pools.get(engagement_id)

    def remove_pool(self, engagement_id: str) -> None:
        """Remove an engagement's agent pool."""
        pool = self._pools.pop(engagement_id, None)
        if pool:
            self._global_active -= pool.quota.active_agents
            logger.info("agent_pool_removed engagement_id=%s", engagement_id)

    def can_allocate(self, engagement_id: str) -> bool:
        """Check if we can allocate more agents globally."""
        if self._global_active >= self.global_max_agents:
            return False
        pool = self._pools.get(engagement_id)
        if pool and not pool.quota.can_schedule_more:
            return False
        return True

    def get_global_status(self) -> Dict[str, Any]:
        """Get global pool status."""
        pools = list(self._pools.values())
        total_agents = sum(p.quota.active_agents for p in pools)
        total_tokens = sum(p.quota.tokens_used for p in pools)
        total_tasks = sum(p.quota.tasks_completed for p in pools)

        return {
            "engagement_count": len(pools),
            "total_active_agents": total_agents,
            "global_max": self.global_max_agents,
            "utilization": total_agents / self.global_max_agents if self.global_max_agents else 0,
            "total_tokens_used": total_tokens,
            "total_tasks_completed": total_tasks,
            "pools": {
                p.engagement_id: {
                    "active_agents": p.quota.active_agents,
                    "tokens_used": p.quota.tokens_used,
                    "tasks_completed": p.quota.tasks_completed,
                    "can_schedule_more": p.quota.can_schedule_more,
                }
                for p in pools
            },
        }

    def get_priority_order(self) -> List[str]:
        """Get engagement IDs ordered by priority (highest first)."""
        pools = list(self._pools.values())
        pools.sort(key=lambda p: p.quota.priority, reverse=True)
        return [p.engagement_id for p in pools]

    def record_tokens(self, engagement_id: str, count: int) -> None:
        """Record token usage for an engagement."""
        pool = self._pools.get(engagement_id)
        if pool:
            pool.record_tokens(count)

    def record_task(self, engagement_id: str) -> None:
        """Record a task completion for an engagement."""
        pool = self._pools.get(engagement_id)
        if pool:
            pool.record_task_completion()
