"""
Cost Tracker — Per-Engagement Resource Usage

Tracks LLM API costs, MCP tool calls, and compute time per engagement.
Enables budget enforcement and cost optimization insights.

Phase 6: Enterprise Hardening
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List

import structlog

logger = structlog.get_logger("ai_osop.cost_tracker")


# Approximate costs per 1K tokens (USD) — updated as needed
MODEL_COSTS_PER_1K_TOKENS: Dict[str, Dict[str, float]] = {
    "gpt-4o": {"input": 0.0025, "output": 0.01},
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "ollama/*": {"input": 0.0, "output": 0.0},  # Local models are free
}


@dataclass
class LLMCallRecord:
    """Record of a single LLM API call."""

    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    duration_ms: float
    agent_id: str
    task_id: str
    timestamp: float = field(default_factory=time.monotonic)


@dataclass
class MCPCallRecord:
    """Record of a single MCP tool call."""

    server: str
    tool: str
    duration_ms: float
    success: bool
    agent_id: str
    task_id: str
    timestamp: float = field(default_factory=time.monotonic)


@dataclass
class EngagementCosts:
    """Aggregated costs for a single engagement."""

    engagement_id: str
    llm_calls: List[LLMCallRecord] = field(default_factory=list)
    mcp_calls: List[MCPCallRecord] = field(default_factory=list)
    total_llm_cost_usd: float = 0.0
    total_llm_input_tokens: int = 0
    total_llm_output_tokens: int = 0
    total_mcp_calls: int = 0
    total_mcp_success: int = 0
    total_mcp_failure: int = 0
    total_task_time_seconds: float = 0.0
    created_at: datetime = field(default_factory=datetime.utcnow)


class CostTracker:
    """Tracks costs per-engagement with budget enforcement."""

    def __init__(self, budget_limit_usd: float = 50.0):
        self.budget_limit_usd = budget_limit_usd
        self._engagements: Dict[str, EngagementCosts] = defaultdict(
            lambda: EngagementCosts(engagement_id="")
        )

    def record_llm_call(
        self,
        engagement_id: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        duration_ms: float,
        agent_id: str,
        task_id: str,
    ) -> Dict[str, Any]:
        """Record an LLM API call and its cost."""
        costs = self._engagements[engagement_id]
        costs.engagement_id = engagement_id

        # Calculate cost — check exact match, then prefix match for patterns like ollama/*
        rate = MODEL_COSTS_PER_1K_TOKENS.get(model)
        if rate is None:
            # Try prefix match (e.g. ollama/llama3 matches ollama/*)
            for pattern, r in MODEL_COSTS_PER_1K_TOKENS.items():
                if pattern.endswith("/*") and model.startswith(pattern[:-2]):
                    rate = r
                    break
            if rate is None:
                rate = MODEL_COSTS_PER_1K_TOKENS["gpt-4o"]  # fallback
        cost = (input_tokens * rate["input"] + output_tokens * rate["output"]) / 1000

        record = LLMCallRecord(
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost,
            duration_ms=duration_ms,
            agent_id=agent_id,
            task_id=task_id,
        )
        costs.llm_calls.append(record)
        costs.total_llm_cost_usd += cost
        costs.total_llm_input_tokens += input_tokens
        costs.total_llm_output_tokens += output_tokens

        # Budget check
        budget_status = self._check_budget(engagement_id)

        logger.info(
            "llm_call_recorded",
            engagement_id=engagement_id,
            model=model,
            cost_usd=round(cost, 6),
            total_cost_usd=round(costs.total_llm_cost_usd, 4),
            budget_remaining_usd=budget_status["remaining_usd"],
        )

        return {
            "cost_usd": cost,
            "total_cost_usd": costs.total_llm_cost_usd,
            "budget_status": budget_status,
        }

    def record_mcp_call(
        self,
        engagement_id: str,
        server: str,
        tool: str,
        duration_ms: float,
        success: bool,
        agent_id: str,
        task_id: str,
    ) -> None:
        """Record an MCP tool call."""
        costs = self._engagements[engagement_id]
        costs.engagement_id = engagement_id

        record = MCPCallRecord(
            server=server,
            tool=tool,
            duration_ms=duration_ms,
            success=success,
            agent_id=agent_id,
            task_id=task_id,
        )
        costs.mcp_calls.append(record)
        costs.total_mcp_calls += 1
        if success:
            costs.total_mcp_success += 1
        else:
            costs.total_mcp_failure += 1

    def record_task_time(
        self, engagement_id: str, agent_id: str, duration_seconds: float
    ) -> None:
        """Record compute time for a task."""
        costs = self._engagements[engagement_id]
        costs.total_task_time_seconds += duration_seconds

    def _check_budget(self, engagement_id: str) -> Dict[str, Any]:
        """Check budget status for an engagement."""
        costs = self._engagements[engagement_id]
        remaining = self.budget_limit_usd - costs.total_llm_cost_usd
        return {
            "budget_limit_usd": self.budget_limit_usd,
            "spent_usd": round(costs.total_llm_cost_usd, 4),
            "remaining_usd": round(max(0, remaining), 4),
            "percent_used": round(
                (costs.total_llm_cost_usd / self.budget_limit_usd) * 100, 1
            ),
            "exceeded": costs.total_llm_cost_usd > self.budget_limit_usd,
        }

    def get_engagement_costs(self, engagement_id: str) -> Dict[str, Any]:
        """Get full cost breakdown for an engagement."""
        costs = self._engagements[engagement_id]

        # Per-agent breakdown
        agent_costs: Dict[str, float] = defaultdict(float)
        agent_tokens: Dict[str, int] = defaultdict(int)
        for call in costs.llm_calls:
            agent_costs[call.agent_id] += call.cost_usd
            agent_tokens[call.agent_id] += call.input_tokens + call.output_tokens

        # Per-model breakdown
        model_costs: Dict[str, float] = defaultdict(float)
        for call in costs.llm_calls:
            model_costs[call.model] += call.cost_usd

        return {
            "engagement_id": engagement_id,
            "budget": self._check_budget(engagement_id),
            "llm": {
                "total_cost_usd": round(costs.total_llm_cost_usd, 4),
                "total_input_tokens": costs.total_llm_input_tokens,
                "total_output_tokens": costs.total_llm_output_tokens,
                "total_calls": len(costs.llm_calls),
                "by_model": dict(model_costs),
                "by_agent": dict(agent_costs),
            },
            "mcp": {
                "total_calls": costs.total_mcp_calls,
                "success": costs.total_mcp_success,
                "failure": costs.total_mcp_failure,
                "success_rate": round(
                    costs.total_mcp_success / max(costs.total_mcp_calls, 1) * 100, 1
                ),
            },
            "compute": {
                "total_task_time_seconds": round(costs.total_task_time_seconds, 1),
            },
        }

    def get_all_engagement_costs(self) -> Dict[str, Any]:
        """Get cost summary for all active engagements."""
        return {
            eid: self.get_engagement_costs(eid)
            for eid in self._engagements
            if self._engagements[eid].total_llm_cost_usd > 0
        }
