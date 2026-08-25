"""Agent Stagnation Detector (T2.1)

Detects when an agent is going in circles — repeating similar observations,
not making progress, or burning tokens without confidence gains. Triggers
strategy shifts or escalates to the strategic planner.
"""

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ai_osop.orchestrator.stagnation")


@dataclass
class AgentObservation:
    """A single observation from an agent's execution loop."""

    timestamp: float
    tool_name: str
    result_hash: str  # hash of the result to detect duplicates
    confidence: float = 0.0
    iteration: int = 0


@dataclass
class StagnationReport:
    """Report of detected stagnation."""

    agent_id: str
    task_id: str
    stagnation_type: str  # "repetition", "no_progress", "token_burn", "confidence_plateau"
    severity: str  # "low", "medium", "high"
    details: str
    recommendation: str
    observation_count: int = 0
    duplicate_count: int = 0
    elapsed_seconds: float = 0.0
    confidence_delta: float = 0.0


class StagnationDetector:
    """Monitors agent execution for stagnation patterns.

    Tracks a sliding window of observations and detects:
    1. Repetition: Same tool + same result hash N times
    2. No progress: Confidence not increasing over M iterations
    3. Token burn: Too many iterations without objective completion
    4. Confidence plateau: Confidence stuck at the same value
    """

    def __init__(
        self,
        repetition_window: int = 10,
        repetition_threshold: int = 3,
        no_progress_iterations: int = 8,
        token_burn_threshold: int = 12,
        confidence_plateau_threshold: float = 0.05,
    ):
        self.repetition_window = repetition_window
        self.repetition_threshold = repetition_threshold
        self.no_progress_iterations = no_progress_iterations
        self.token_burn_threshold = token_burn_threshold
        self.confidence_plateau_threshold = confidence_plateau_threshold

        # Per-agent observation history
        self._history: Dict[str, deque] = {}
        # Per-agent start time
        self._start_times: Dict[str, float] = {}

    def record_observation(
        self,
        agent_id: str,
        task_id: str,
        tool_name: str,
        result: Any,
        confidence: float,
        iteration: int,
    ) -> None:
        """Record an observation from an agent."""
        if agent_id not in self._history:
            self._history[agent_id] = deque(maxlen=self.repetition_window)
            self._start_times[agent_id] = time.monotonic()

        result_hash = str(hash(str(result)[:500]))
        obs = AgentObservation(
            timestamp=time.monotonic(),
            tool_name=tool_name,
            result_hash=result_hash,
            confidence=confidence,
            iteration=iteration,
        )
        self._history[agent_id].append(obs)

    def check_stagnation(
        self,
        agent_id: str,
        task_id: str,
        current_iteration: int,
        current_confidence: float,
    ) -> Optional[StagnationReport]:
        """Check if the agent is stagnating.

        Returns a StagnationReport if stagnation is detected, None otherwise.
        """
        history = self._history.get(agent_id)
        if not history or len(history) < 3:
            return None

        observations = list(history)
        elapsed = time.monotonic() - self._start_times.get(agent_id, time.monotonic())

        # 1. Repetition detection
        report = self._check_repetition(agent_id, task_id, observations, elapsed)
        if report:
            return report

        # 2. No progress detection
        report = self._check_no_progress(agent_id, task_id, observations, elapsed)
        if report:
            return report

        # 3. Token burn detection
        if current_iteration >= self.token_burn_threshold:
            return StagnationReport(
                agent_id=agent_id,
                task_id=task_id,
                stagnation_type="token_burn",
                severity="high",
                details=f"Agent has run {current_iteration} iterations without completing objective",
                recommendation="Consider completing with partial results or escalating to strategic planner",
                observation_count=len(observations),
                elapsed_seconds=elapsed,
            )

        # 4. Confidence plateau detection
        if len(observations) >= 4:
            confidences = [o.confidence for o in observations[-4:]]
            delta = max(confidences) - min(confidences)
            if delta < self.confidence_plateau_threshold and current_iteration >= 5:
                return StagnationReport(
                    agent_id=agent_id,
                    task_id=task_id,
                    stagnation_type="confidence_plateau",
                    severity="medium",
                    details=f"Confidence stuck at ~{current_confidence:.2f} for 4+ iterations (delta={delta:.4f})",
                    recommendation="Try a different tool or approach; current strategy is not yielding new information",
                    observation_count=len(observations),
                    confidence_delta=delta,
                    elapsed_seconds=elapsed,
                )

        return None

    def _check_repetition(
        self,
        agent_id: str,
        task_id: str,
        observations: List[AgentObservation],
        elapsed: float,
    ) -> Optional[StagnationReport]:
        """Detect tool + result repetition."""
        if len(observations) < self.repetition_threshold:
            return None

        # Check last N observations for same tool+hash
        recent = observations[-self.repetition_threshold :]
        tool_hashes = [(o.tool_name, o.result_hash) for o in recent]

        # All same?
        if len(set(tool_hashes)) == 1:
            tool, _ = tool_hashes[0]
            return StagnationReport(
                agent_id=agent_id,
                task_id=task_id,
                stagnation_type="repetition",
                severity="high",
                details=f"Same tool+result repeated {self.repetition_threshold} times: {tool}",
                recommendation="Agent is stuck in a loop. Shift strategy or complete with current findings.",
                observation_count=len(observations),
                duplicate_count=self.repetition_threshold,
                elapsed_seconds=elapsed,
            )

        # Most common tool in recent window
        from collections import Counter

        tool_counts = Counter(o.tool_name for o in recent)
        most_common_tool, most_common_count = tool_counts.most_common(1)[0]
        if most_common_count >= self.repetition_threshold - 1:
            return StagnationReport(
                agent_id=agent_id,
                task_id=task_id,
                stagnation_type="repetition",
                severity="medium",
                details=f"Tool '{most_common_tool}' used {most_common_count}/{self.repetition_threshold} recent iterations",
                recommendation=f"Consider alternatives to '{most_common_tool}'",
                observation_count=len(observations),
                duplicate_count=most_common_count,
                elapsed_seconds=elapsed,
            )

        return None

    def _check_no_progress(
        self,
        agent_id: str,
        task_id: str,
        observations: List[AgentObservation],
        elapsed: float,
    ) -> Optional[StagnationReport]:
        """Detect lack of confidence progress."""
        if len(observations) < self.no_progress_iterations:
            return None

        recent = observations[-self.no_progress_iterations :]
        confidences = [o.confidence for o in recent]
        initial = sum(confidences[:3]) / 3
        final = sum(confidences[-3:]) / 3
        delta = final - initial

        if delta <= 0.01 and len(set(o.tool_name for o in recent)) == 1:
            return StagnationReport(
                agent_id=agent_id,
                task_id=task_id,
                stagnation_type="no_progress",
                severity="high",
                details=f"No confidence gain over {self.no_progress_iterations} iterations (delta={delta:.4f}), single tool",
                recommendation="Switch tools or complete the task",
                observation_count=len(observations),
                confidence_delta=delta,
                elapsed_seconds=elapsed,
            )

        return None

    def clear_agent(self, agent_id: str) -> None:
        """Clear tracking for a completed agent."""
        self._history.pop(agent_id, None)
        self._start_times.pop(agent_id, None)

    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics."""
        return {
            "tracked_agents": len(self._history),
            "total_observations": sum(len(h) for h in self._history.values()),
        }
