"""
Stateful Logic Agent (V6 Prototype)
Analyzes business process state machines and identifies invalid transition paths.
"""

import logging
from typing import Any, Dict, List, Optional

import httpx  # noqa: F401

from ai_osop.agents.base import BaseAgent
from ai_osop.core.enums import AgentType, Severity, VulnClass
from ai_osop.core.exceptions import OutOfScopeError, ScopeValidationError
from ai_osop.core.governance import BusinessLogicEngine
from ai_osop.core.models import ProcessState, Task, Vulnerability
from ai_osop.safety.scope import ScopeEnforcer

logger = logging.getLogger(__name__)


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

    # Bound on the real violation request so a hung target can't stall the agent.
    VIOLATION_TIMEOUT_SECONDS = 20.0

    async def _setup_resources(self) -> None:
        """Initialize state machine memory."""
        self.active_processes: Dict[str, List[ProcessState]] = {}
        self.business_logic_engine = BusinessLogicEngine()
        self._scope_manager: Optional[ScopeEnforcer] = None
        if getattr(self.ctx, "scope", None) is not None:
            try:
                self._scope_manager = ScopeEnforcer(self.ctx.scope)
            except Exception as e:  # noqa: BLE001 - scope optional
                logger.warning(f"stateful_logic_scope_init_failed: {e}")

    def _in_scope(self, url: str) -> bool:
        """Return True if url is in scope (or no scope is configured)."""
        if self._scope_manager is None:
            return True
        try:
            return self._scope_manager.validate_target(url)
        except (OutOfScopeError, ScopeValidationError) as e:
            logger.warning(f"stateful_logic_url_out_of_scope: {url}: {e}")
            return False

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
                logger.warning(f"WARN: failed to persist invariant {inv.id}: {e}")

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
        from ai_osop.core.business_state_machine import LogicalBusinessStateMachine

        step_dicts = []
        for step in steps:
            step_dicts.append(
                {
                    "url": step.get("url") or step.get("endpoint") or "",
                    "method": step.get("method") or "GET",
                    "action_type": step.get("action_type") or "NAVIGATE",
                    "order": step.get("order") or 0,
                }
            )

        lbsm = LogicalBusinessStateMachine(step_dicts)
        concrete_payloads = lbsm.generate_bypass_payloads()

        violation_tasks = []
        for inv in invariants:
            tests = self.business_logic_engine.generate_violation_tests(inv)
            for t in tests:
                cp = next((p for p in concrete_payloads if p["strategy"] == t["strategy"]), None)
                payload_data = cp if cp else {**t, "invariant_id": inv.id}

                violation_tasks.append(
                    Task(
                        type="violate_invariant",
                        priority=8,
                        agent_type=AgentType.STATEFUL_LOGIC,
                        payload=payload_data,
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
        Attempt an 'Impossible' transition by executing a REAL HTTP request and
        judging success from the actual response.

        A concrete, executable violation test is supplied in the payload as:
          request = {method, url, headers?, body?/json?}
          success_criteria = {
              status_in?: [int],         # success if response status is in this list
              status_not_in?: [int],     # success only if status is NOT in this list
              body_contains?: str,       # success requires this substring in the body
              body_not_contains?: str,   # success requires this substring absent
          }

        If no concrete request is provided, the strategy is only a hypothesis and
        the agent returns an honest non-executed result instead of fabricating
        success. The persisted invariant is marked violated ONLY when a real
        request actually demonstrates the violation.
        """
        strategy = payload.get("strategy")
        invariant_id = payload.get("invariant_id")

        # Best-effort reasoning (never blocks or fabricates the outcome).
        try:
            reasoning = await self.think(
                f"Attempting to violate business rule using {strategy} strategy.",
                ["business_logic_bypass", "state_machine_exploitation"],
            )
        except Exception as e:  # noqa: BLE001
            reasoning = f"(reasoning skipped: {type(e).__name__})"
            logger.debug(f"stateful_logic_reasoning_skipped: {e}")

        request_spec = payload.get("request") or {}
        url = request_spec.get("url")

        # No concrete request -> cannot honestly claim a violation. Never fabricate.
        if not url:
            return {
                "status": "success",
                "executed": False,
                "violation_successful": False,
                "strategy": strategy,
                "reason": (
                    "No concrete violation request provided. The strategy is a "
                    "hypothesis only; it was not executed and no violation is claimed."
                ),
                "reasoning": reasoning,
            }

        # Scope-gate the target before any network call.
        if not self._in_scope(url):
            return {
                "status": "success",
                "executed": False,
                "violation_successful": False,
                "strategy": strategy,
                "reason": f"Target {url} is out of scope; request not executed.",
                "reasoning": reasoning,
            }

        method = (request_spec.get("method") or "GET").upper()
        headers = request_spec.get("headers") or {}
        json_body = request_spec.get("json")
        raw_body = request_spec.get("body")
        success_criteria = payload.get("success_criteria") or {}

        # Execute the REAL request.
        try:
            async with self.get_governed_client(
                tool="stateful_logic",
                follow_redirects=False,
                timeout=self.VIOLATION_TIMEOUT_SECONDS,
                headers={"User-Agent": "AI-OSOP-StatefulLogic/1.0", **headers},
            ) as client:
                resp = await client.request(
                    method,
                    url,
                    json=json_body if json_body is not None else None,
                    content=raw_body if (raw_body is not None and json_body is None) else None,
                )
                status_code = resp.status_code
                body_text = resp.text
        except Exception as e:  # noqa: BLE001 - network failure is an honest "not demonstrated"
            logger.warning(f"stateful_logic_request_failed: {url}: {e}")
            return {
                "status": "success",
                "executed": True,
                "violation_successful": False,
                "strategy": strategy,
                "reason": f"Request error: {type(e).__name__}: {str(e)[:160]}",
                "reasoning": reasoning,
            }

        violation_successful = self._evaluate_success_criteria(
            success_criteria, status_code, body_text
        )

        evidence_snippet = body_text[:500]
        result: Dict[str, Any] = {
            "status": "success",
            "executed": True,
            "violation_successful": violation_successful,
            "strategy": strategy,
            "request": {"method": method, "url": url},
            "response": {
                "status_code": status_code,
                "body_length": len(body_text),
                "body_snippet": evidence_snippet,
            },
            "criteria_evaluated": success_criteria,
            "reasoning": reasoning,
        }

        # Persist a real finding + mark the invariant ONLY on a demonstrated violation.
        if violation_successful:
            result["impact"] = payload.get("impact", "High (business-logic violation)")
            vuln = Vulnerability(
                title=f"Business-logic violation ({strategy})",
                description=(
                    f"An impossible/unauthorized state transition was demonstrated "
                    f"against {url} using the '{strategy}' strategy. The request "
                    f"returned HTTP {status_code}, satisfying the violation criteria."
                ),
                severity=Severity.HIGH,
                vuln_type=VulnClass.BROKEN_ACCESS_CONTROL,
                confidence=0.85,
                tool_source="stateful_logic",
                engagement_id=self.ctx.session_id,
                exploitability="high",
                evidence=[
                    {
                        "type": "business_logic_violation",
                        "provenance": "live",
                        "strategy": strategy,
                        "request": {"method": method, "url": url},
                        "response_status": status_code,
                        "response_snippet": evidence_snippet,
                        "criteria": success_criteria,
                    }
                ],
            )
            try:
                vid = await self.ctx.graph_memory.add_vulnerability(vuln)
                result["finding_id"] = vid or vuln.id
            except Exception as e:  # noqa: BLE001
                logger.warning(f"stateful_logic_persist_failed: {e}")

            if invariant_id:
                try:
                    await self.ctx.graph_memory.mark_invariant_violated(invariant_id)
                except Exception as e:
                    logger.warning(f"WARN: failed to mark invariant {invariant_id} violated: {e}")

        return result

    @staticmethod
    def _evaluate_success_criteria(
        criteria: Dict[str, Any], status_code: int, body_text: str
    ) -> bool:
        """Judge whether a real response demonstrates the violation.

        If explicit criteria are given, ALL provided conditions must hold. If no
        criteria are given, fall back to a conservative heuristic: a 2xx response
        indicates the impossible transition was allowed (violation demonstrated).
        """
        if not criteria:
            return 200 <= status_code < 300

        if "status_in" in criteria and status_code not in criteria["status_in"]:
            return False
        if "status_not_in" in criteria and status_code in criteria["status_not_in"]:
            return False
        if "body_contains" in criteria and criteria["body_contains"] not in body_text:
            return False
        if "body_not_contains" in criteria and criteria["body_not_contains"] in body_text:
            return False
        return True

    async def _analyze_drift(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Detect when a resource's state changes unexpectedly."""
        return {"status": "success", "drift_detected": False}

    async def _cleanup_resources(self) -> None:
        self.active_processes.clear()
