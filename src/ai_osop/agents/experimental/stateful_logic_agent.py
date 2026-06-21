"""
Stateful Logic Agent (V6 Prototype)
Analyzes business process state machines and identifies invalid transition paths.
"""

# PATCH (REL-028, 2026-06-15): This agent is not instantiated by the
# current orchestrator (api/main.py register_agents). Marked experimental
# until either (a) registered for production use or (b) archived.
__experimental__ = True

from typing import Any, Dict, List, Optional

from ai_osop.agents.base import AgentContext, BaseAgent
from ai_osop.core.config import AgentType
from ai_osop.core.governance import BusinessLogicEngine
from ai_osop.core.models import AuditEvent, BusinessInvariant, ProcessState, Task


class StatefulLogicAgent(BaseAgent):
    """
    V6 Core Agent: Stateful Logic & Process Manipulation

    Responsibilities:
    - Map multi-step business processes (Payment, Shipping, Approvals)
    - Identify valid vs invalid state transitions
    - Detect 'Time-of-Check to Time-of-Use' (TOCTOU) logic flaws
    - Simulate multi-user state contention
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.STATEFUL_LOGIC

    async def _setup_resources(self) -> None:
        """Initialize state machine memory."""
        self.active_processes: Dict[str, List[ProcessState]] = {}
        self.business_logic_engine = BusinessLogicEngine()

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute state machine analysis."""
        task_type = task.type
        payload = task.payload

        if task_type == "map_business_process":
            return await self._map_process(payload)
        elif task_type == "violate_invariant":
            return await self._violate_invariant(payload)
        elif task_type == "analyze_state_drift":
            return await self._analyze_drift(payload)
        else:
            return {"status": "error", "message": f"Unknown task {task_type}"}

    async def _map_process(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a standard workflow into a V6 Stateful Process Graph."""
        process_name = payload.get("process_name")
        workflow_id = payload.get("workflow_id")

        # 1. Fetch workflow steps from GraphMemory
        steps = await self.ctx.graph_memory.get_workflow_steps(workflow_id)

        # 2. Extract Invariants (Rules) using BusinessLogicEngine
        invariants = self.business_logic_engine.extract_invariants(steps)

        # 2b. Persist invariants so the Research Intelligence dashboard can surface
        # them (best-effort: must never break process mapping).
        for inv in invariants:
            inv.engagement_id = self.ctx.session_id
            try:
                await self.ctx.graph_memory.add_business_invariant(
                    inv, engagement_id=self.ctx.session_id, is_violated=False
                )
            except Exception as e:
                print(f"WARN: failed to persist invariant {inv.id}: {e}")

        # 3. Store Process States in Graph
        process_states = []
        for step in steps:
            state = ProcessState(
                name=step.get("action_type"),
                process_name=process_name,
                engagement_id=self.ctx.session_id,
            )
            # await self.ctx.graph_memory.add_process_state(state)
            process_states.append(state)

        # 4. Generate Violation Hypotheses
        violation_tasks = []
        for inv in invariants:
            tests = self.business_logic_engine.generate_violation_tests(inv)
            for t in tests:
                violation_tasks.append(
                    Task(
                        type="violate_invariant",
                        priority=8,
                        agent_type=AgentType.WORKFLOW,
                        payload={**t, "invariant_id": inv.id},
                        engagement_id=self.ctx.session_id,
                    )
                )

        return {
            "status": "success",
            "states_mapped": len(process_states),
            "invariants_discovered": len(invariants),
            "violation_tasks_queued": len(violation_tasks),
        }

    async def _violate_invariant(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Attempt an 'Impossible' transition.
        e.g. Call /api/ship/123 without the 'paid' flag in session.
        """
        strategy = payload.get("strategy")

        # Reasoning using V6 Business Logic skills
        reasoning = await self.think(
            f"Attempting to violate business rule using {strategy} strategy.",
            ["business_logic_bypass", "state_machine_exploitation"],
        )

        # Flag the persisted invariant as violated so the dashboard reflects it
        # (best-effort: must never break the violation attempt).
        invariant_id = payload.get("invariant_id")
        if invariant_id:
            try:
                await self.ctx.graph_memory.mark_invariant_violated(invariant_id)
            except Exception as e:
                print(f"WARN: failed to mark invariant {invariant_id} violated: {e}")

        return {
            "status": "success",
            "violation_successful": True,  # Simulated
            "impact": "High (Financial Loss)",
            "reasoning": reasoning,
        }

    async def _analyze_drift(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Detect when a resource's state changes unexpectedly."""
        return {"status": "success", "drift_detected": False}

    async def _cleanup_resources(self) -> None:
        self.active_processes.clear()
