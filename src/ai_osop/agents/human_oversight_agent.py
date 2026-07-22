"""
Human Oversight Agent
Manages approval flows, risk translation, and operator communication.
"""

from typing import Any, Dict

from ai_osop.agents.base import BaseAgent
from ai_osop.core.enums import AgentType
from ai_osop.core.exceptions import AgentException
from ai_osop.core.models import Task


class HumanOversightAgent(BaseAgent):
    """
    Agent responsible for translating technical risks to operators
    and managing the approval lifecycle for high-risk actions.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.HUMAN_OVERSIGHT

    async def _setup_resources(self) -> None:
        """Initialize oversight resources."""
        self.pending_reviews: Dict[str, Any] = {}

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute oversight tasks like risk summary generation."""
        task_type = task.type
        payload = task.payload

        if task_type == "evaluate_risk":
            return await self._evaluate_risk(payload)
        elif task_type == "format_approval":
            return await self._format_approval(payload)
        else:
            raise AgentException(f"Unknown oversight task type: {task_type}")

    async def _evaluate_risk(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a payload and target to determine blast radius and risk."""
        target = payload.get("target", "unknown")
        vuln_type = payload.get("vuln_type", "unknown")
        action_payload = payload.get("payload", "")

        context = f"Analyze the risk of executing {vuln_type} payload: '{action_payload}' against target '{target}'. What is the blast radius?"

        # We can use the LLM to assess risk
        messages = [
            {
                "role": "system",
                "content": "You are a Senior Security Risk Analyst. Evaluate the impact of proposed exploits. Return a concise risk summary.",
            },
            {"role": "user", "content": context},
        ]

        risk_summary = await self.ctx.llm_client.complete(messages)

        return {
            "status": "success",
            "target": target,
            "risk_assessment": risk_summary,
            "requires_approval": True,  # High-risk actions default to True
        }

    async def _format_approval(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Format an approval request with deep context for the operator."""
        # Extracts raw data and formats it for human consumption
        request_id = payload.get("request_id")
        return {
            "status": "success",
            "formatted_message": f"Approval required for {request_id}. Please review risk assessment.",
        }

    async def _cleanup_resources(self) -> None:
        """Cleanup."""
        self.pending_reviews.clear()
