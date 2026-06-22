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
            f"Testing {target_url} for race conditions using a simulated Single Packet Attack with {concurrent_requests} concurrent requests.",
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

            if result.get("race_condition_detected"):
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
        if not self.ctx.graph_memory or not self.ctx.graph_memory._driver:
            return {"status": "failed", "error": "Graph memory driver not initialized"}

        steps = []
        async with self.ctx.graph_memory._driver.session() as session:
            result = await session.run(
                """
                MATCH (w:Workflow {id: $wid})-[:HAS_STEP]->(s:Step)-[:TARGETS]->(e:Endpoint)
                RETURN s.id AS step_id, s.order AS order, s.business_state AS state, e.url AS url, e.method AS method
                ORDER BY s.order
                """,
                {"wid": workflow_id},
            )
            async for record in result:
                steps.append(dict(record))

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

            # If the SPA resulted in a success on an endpoint that should have been protected by prior states
            if attack_result.get("race_condition_detected"):
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
