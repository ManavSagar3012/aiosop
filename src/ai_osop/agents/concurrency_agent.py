"""
Concurrency Agent
Specializes in orchestrating precision timing attacks to exploit race conditions
and logic bypasses in multi-step business workflows.
"""

import logging
from typing import Any, Dict

from ai_osop.agents.base import BaseAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task

logger = logging.getLogger(__name__)


def _race_detected(result: Dict[str, Any], payload: Dict[str, Any]) -> bool:
    """Detect a race from the real single-packet engine output. A once-only action
    that SUCCEEDS more times than permitted (default: >1 at the success status) under
    synchronized concurrency is the signal. Replaces the old boolean field that the
    raw-socket turbo rewrite removed."""
    dist = (result or {}).get("status_distribution", {}) or {}
    success_status = str(payload.get("success_status", 200))
    expected_max = int(payload.get("expected_max_successes", 1))
    return int(dist.get(success_status, 0)) > expected_max


class ConcurrencyAgent(BaseAgent):
    """
    Concurrency Agent (V6.0)

    Responsibilities:
    - Executing single-packet attacks to test race conditions.
    - Testing time-of-check to time-of-use (TOCTOU) flaws.
    - Bypassing multi-step state machine constraints.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.CONCURRENCY

    async def _setup_resources(self) -> None:
        pass

    async def _execute(self, task: Task) -> Dict[str, Any]:
        task_type = task.type
        payload = task.payload

        if task_type == "test_race_condition":
            return await self._test_race_condition(payload)
        elif task_type == "test_state_machine_bypass":
            return await self._test_state_machine_bypass(payload)
        else:
            return {"status": "failed", "error": f"Unknown task type: {task_type}"}

    async def _test_race_condition(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Test for race conditions using the turbo-intruder-mcp precision timing engine."""
        target_url = payload.get("url")
        concurrent_requests = payload.get("concurrent_requests", 10)

        if not target_url:
            return {"status": "failed", "error": "url is required"}

        await self.think(
            f"Testing {target_url} for race conditions using a Single Packet Attack with {concurrent_requests} concurrent requests.",
            ["race_condition", "toctou", "single_packet_attack"],
        )

        try:
            from ai_osop.adapters.turbo_intruder_mcp import TurboIntruderMCPAdapter

            adapter = TurboIntruderMCPAdapter(self.ctx.mcp_registry)
            await adapter.initialize(
                self.ctx.scope.model_dump() if self.ctx.scope else {},
                self.ctx.session_id,
            )

            result = await adapter.execute_single_packet_attack(
                target_url=target_url,
                method=payload.get("method", "POST"),
                headers=payload.get("headers", {}),
                body=payload.get("body", ""),
                concurrent_requests=concurrent_requests,
            )

            # The real single-packet engine returns a status_distribution (not the
            # old boolean). A race is indicated when a once-only action SUCCEEDS more
            # than expected under synchronized concurrency.
            if _race_detected(result, payload):
                await self.observe(
                    target_id=target_url, obs_type="race_condition", data=result, confidence=0.9
                )
                return {
                    "status": "success",
                    "msg": f"Race condition detected at {target_url}. Evaluated {concurrent_requests} simultaneous requests.",
                }
            else:
                return {"status": "success", "msg": f"No race condition detected at {target_url}."}

        except Exception as e:
            logger.error(f"Failed to test race condition: {e}")
            return {"status": "failed", "error": str(e)}

    async def _test_state_machine_bypass(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Test for state machine bypasses across mapped workflow steps."""
        workflow_id = payload.get("workflow_id")

        if not workflow_id:
            return {"status": "failed", "error": "workflow_id is required"}

        await self.think(
            f"Analyzing business logic flow {workflow_id} for state machine bypass vulnerabilities.",
            ["state_machine_bypass", "concurrency", "business_logic"],
        )

        # 1. Fetch the steps and their states from the graph
        if not self.ctx.graph_memory:
            return {"status": "failed", "error": "Graph memory not initialized"}

        steps = []
        records = await self.ctx.graph_memory.run_read_query(
            """
            MATCH (w:Workflow {id: $wid})-[:HAS_STEP]->(s:Step)-[:TARGETS]->(e:Endpoint)
            RETURN s.id AS step_id, s.order AS order, s.business_state AS state, e.url AS url, e.method AS method
            ORDER BY s.order
            """,
            {"wid": workflow_id},
        )
        for record in records:
            steps.append(record)

        if not steps or len(steps) < 2:
            return {
                "status": "failed",
                "error": f"Workflow {workflow_id} has insufficient steps mapped for bypass testing.",
            }

        # 2. Target the final step (the goal state) and attempt to execute it concurrently
        # bypassing the intermediate required steps.
        final_step = steps[-1]
        target_url = final_step["url"]
        target_method = final_step["method"]

        await self.think(
            f"Attempting to bypass intermediate states and directly hit goal state '{final_step.get('state')}' at {target_url}.",
            ["single_packet_attack", "authorization_bypass"],
        )

        try:
            from ai_osop.adapters.turbo_intruder_mcp import TurboIntruderMCPAdapter

            adapter = TurboIntruderMCPAdapter(self.ctx.mcp_registry)
            await adapter.initialize(
                self.ctx.scope.model_dump() if self.ctx.scope else {},
                self.ctx.session_id,
            )

            # Send simultaneous requests to the final endpoint to see if the state validation can be bypassed
            attack_result = await adapter.execute_single_packet_attack(
                target_url=target_url,
                method=target_method,
                headers=payload.get("headers", {}),
                body=payload.get("body", "bypass=true"),
                concurrent_requests=10,
            )

            # If the synchronized requests reached the goal state out of order (the
            # protected endpoint accepted more successes than the workflow permits).
            if _race_detected(attack_result, payload):
                await self.observe(
                    target_id=workflow_id,
                    obs_type="state_machine_bypass",
                    data={
                        "workflow_id": workflow_id,
                        "bypassed_states": [s["state"] for s in steps[:-1]],
                        "target_state": final_step["state"],
                        "target_url": target_url,
                        "evidence": attack_result,
                    },
                    confidence=0.95,
                )
                return {
                    "status": "success",
                    "msg": f"State machine bypass detected! Reached state '{final_step['state']}' out of order.",
                }
            else:
                return {
                    "status": "success",
                    "msg": f"State machine is secure against timing bypasses for workflow {workflow_id}.",
                }

        except Exception as e:
            logger.error(f"Failed to test state machine bypass: {e}")
            return {"status": "failed", "error": str(e)}

    async def _cleanup_resources(self) -> None:
        pass
