"""
Per-Agent Rate Limiter — Resource Protection

Enforces rate limits per agent to prevent any single agent from
consuming disproportionate resources. Uses a sliding window counter
backed by an in-memory store (Redis-backed for distributed deployments).

Phase 6: Enterprise Hardening
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import structlog

logger = structlog.get_logger("ai_osop.rate_limiter")


@dataclass
class RateLimitConfig:
    """Rate limit configuration for a specific agent type."""

    max_requests: int = 100  # Max requests per window
    window_seconds: int = 60  # Sliding window size
    burst_max: int = 20  # Max burst before throttling
    penalty_seconds: int = 30  # Penalty cooldown after exceeded


# Default rate limits per agent type
DEFAULT_LIMITS: Dict[str, RateLimitConfig] = {
    "recon": RateLimitConfig(max_requests=200, burst_max=50),
    "vuln_analysis": RateLimitConfig(max_requests=100, burst_max=30),
    "exploit_validation": RateLimitConfig(max_requests=50, burst_max=10),
    "attack_chain": RateLimitConfig(max_requests=80, burst_max=20),
    "payload_mutation": RateLimitConfig(max_requests=150, burst_max=40),
    "self_pentest": RateLimitConfig(max_requests=30, burst_max=5),
    "default": RateLimitConfig(max_requests=100, burst_max=20),
}


@dataclass
class AgentRateState:
    """Tracking state for a single agent's rate limiting."""

    timestamps: list = field(default_factory=list)
    violations: int = 0
    last_violation: float = 0.0
    penalty_until: float = 0.0


class PerAgentRateLimiter:
    """Sliding window rate limiter with per-agent tracking."""

    def __init__(self, limits: Optional[Dict[str, RateLimitConfig]] = None):
        self.limits = limits or DEFAULT_LIMITS
        self._state: Dict[str, AgentRateState] = defaultdict(AgentRateState)

    def _get_config(self, agent_type: str) -> RateLimitConfig:
        """Get rate limit config for an agent type."""
        return self.limits.get(agent_type, self.limits["default"])

    def _cleanup_window(self, state: AgentRateState, window_seconds: int) -> None:
        """Remove timestamps outside the sliding window."""
        cutoff = time.monotonic() - window_seconds
        state.timestamps = [t for t in state.timestamps if t > cutoff]

    def check_rate_limit(
        self, agent_id: str, agent_type: str
    ) -> Dict[str, Any]:
        """Check if an agent is within its rate limit.

        Returns:
            - allowed: bool
            - current_count: int
            - limit: int
            - retry_after: float (seconds to wait, 0 if allowed)
        """
        config = self._get_config(agent_type)
        state = self._state[agent_id]

        # Check penalty cooldown
        now = time.monotonic()
        if state.penalty_until > now:
            retry_after = state.penalty_until - now
            logger.warning(
                "rate_limit_penalty",
                agent_id=agent_id,
                retry_after=round(retry_after, 1),
            )
            return {
                "allowed": False,
                "current_count": len(state.timestamps),
                "limit": config.max_requests,
                "retry_after": round(retry_after, 1),
                "reason": "penalty_cooldown",
            }

        # Cleanup old timestamps
        self._cleanup_window(state, config.window_seconds)

        # Check burst limit
        if len(state.timestamps) >= config.burst_max:
            state.violations += 1
            state.last_violation = now
            state.penalty_until = now + config.penalty_seconds

            logger.warning(
                "rate_limit_exceeded",
                agent_id=agent_id,
                agent_type=agent_type,
                current=len(state.timestamps),
                burst_limit=config.burst_max,
                violations=state.violations,
            )
            return {
                "allowed": False,
                "current_count": len(state.timestamps),
                "limit": config.max_requests,
                "retry_after": config.penalty_seconds,
                "reason": "burst_exceeded",
            }

        # Check sliding window limit
        if len(state.timestamps) >= config.max_requests:
            # Find when the oldest request in window expires
            oldest = min(state.timestamps) if state.timestamps else now
            retry_after = oldest + config.window_seconds - now

            logger.warning(
                "rate_limit_window_exceeded",
                agent_id=agent_id,
                current=len(state.timestamps),
                window_limit=config.max_requests,
            )
            return {
                "allowed": False,
                "current_count": len(state.timestamps),
                "limit": config.max_requests,
                "retry_after": round(max(0, retry_after), 1),
                "reason": "window_exceeded",
            }

        # Allowed — record the request
        state.timestamps.append(now)
        return {
            "allowed": True,
            "current_count": len(state.timestamps),
            "limit": config.max_requests,
            "retry_after": 0,
        }

    def record_completion(self, agent_id: str, duration_seconds: float) -> None:
        """Record a completed request for backpressure calculation."""
        # This is called after a task completes to adjust timing
        pass

    def get_agent_stats(self, agent_id: str) -> Dict[str, Any]:
        """Return rate limit stats for an agent."""
        state = self._state[agent_id]
        return {
            "agent_id": agent_id,
            "requests_in_window": len(state.timestamps),
            "violations": state.violations,
            "in_penalty": state.penalty_until > time.monotonic(),
        }

    def reset_agent(self, agent_id: str) -> None:
        """Reset rate limit state for an agent."""
        self._state[agent_id] = AgentRateState()
