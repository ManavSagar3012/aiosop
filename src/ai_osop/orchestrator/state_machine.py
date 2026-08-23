from datetime import datetime
from typing import Any

from ai_osop.core.config import PHASE_POLICY, VALID_TRANSITIONS, AgentType, EngagementPhase
from ai_osop.core.engagement_state import EngagementState
from ai_osop.core.exceptions import WorkflowException
from ai_osop.core.models import Task
from ai_osop.memory.session_memory import SessionMemory


class EngagementStateMachine:
    # GAP-3-1: phase/task contract. Only safety-critical agent types are restricted
    # to specific phases; everything else (workflow chains, recon helpers that span
    # phases) is allowed. The hard rule: exploit validation may run ONLY in
    # EXPLOITATION, so a stale-queued or agent-injected exploit task cannot execute
    # while the engagement is still in recon/discovery.
    RESTRICTED_AGENT_PHASES = {
        AgentType.EXPLOIT_VALIDATION: {EngagementPhase.EXPLOITATION},
    }

    def __init__(self, session_memory: SessionMemory):
        self.session_memory = session_memory

    def validate_transition(
        self, current_state: EngagementState, next_phase: EngagementPhase
    ) -> bool:
        allowed_phases = VALID_TRANSITIONS.get(current_state.phase, [])
        return next_phase in allowed_phases

    def apply_transition(self, current_state: EngagementState, next_phase: EngagementPhase) -> bool:
        if self.validate_transition(current_state, next_phase):
            current_state.phase = next_phase
            current_state.version += 1
            current_state.updated_at = datetime.utcnow()
            return True
        return False

    async def request_transition(
        self, session_id: str, from_phase: EngagementPhase, to_phase: EngagementPhase
    ):
        session_state = await self.session_memory.get_session_state(session_id)
        if not session_state:
            raise ValueError(f"Session {session_id} not found")

        current_state = EngagementState(
            id=session_state.session_id,
            phase=EngagementPhase(session_state.phase),
            data=session_state.agents,
        )

        if from_phase != current_state.phase:
            raise ValueError(f"Phase mismatch: expected {from_phase}, got {current_state.phase}")

        if self.apply_transition(current_state, to_phase):
            session_state.phase = to_phase.value
            await self.session_memory.store_session_state(session_state)
            return True
        return False

    def assert_task_allowed(self, task: Task, phase: EngagementPhase) -> None:
        """Enforce the phase/task contract. Raises WorkflowException if the task may
        not run in the given phase. Called from TaskScheduler._assign_task."""
        if phase in (EngagementPhase.HALTED, EngagementPhase.COMPLETED):
            raise WorkflowException(f"Tasks not allowed in phase {phase.value}")
        allowed = self.RESTRICTED_AGENT_PHASES.get(task.agent_type)
        if allowed is not None and phase not in allowed:
            raise WorkflowException(
                f"Agent type {task.agent_type.value} not allowed in phase "
                f"{phase.value} (allowed: {[p.value for p in allowed]})"
            )
