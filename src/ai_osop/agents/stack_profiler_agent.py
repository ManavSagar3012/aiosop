"""
Stack Profiler Agent
Identifies and maps the target's technology stack (Frontend, Backend, DB, Auth, Cloud).
Enables contextual reasoning based on historical bug bounty patterns.
"""

from typing import Any, Dict, List, Optional

from ai_osop.agents.base import AgentContext, BaseAgent
from ai_osop.core.config import AgentType
from ai_osop.core.exceptions import AgentException
from ai_osop.core.models import Task


class StackProfilerAgent(BaseAgent):
    """
    Stack Profiler Agent
    - Aggregates tech fingerprints from all agents
    - Predicts missing pieces of the stack using LLM reasoning
    - Outputs a structured 'Stack Profile' node for the graph
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.CONTEXT_MANAGER  # We'll reuse context manager type or add a new one

    def supports_task_type(self, task_type: str) -> bool:
        return task_type == "profile_stack"

    async def _setup_resources(self) -> None:
        self.current_profile: Dict[str, str] = {}

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Profile the target stack."""
        task_type = task.type
        if task_type != "profile_stack":
            return {"status": "ignored"}

        engagement_id = self.ctx.session_id

        # 1. Fetch all tech metadata from the graph
        cypher = """
        MATCH (n) WHERE n.engagement_id = $sid 
        AND (n:Asset OR n:Endpoint)
        RETURN n.technologies as tech, n.metadata as meta
        """
        raw_tech = []
        records = await self.ctx.graph_memory.run_read_query(cypher, {"sid": engagement_id})
        for record in records:
            if record["tech"]:
                raw_tech.extend(record["tech"])
            if record["meta"]:
                import json

                try:
                    meta = json.loads(record["meta"])
                    if "framework" in meta:
                        raw_tech.append(meta["framework"])
                    if "auth_scheme" in meta:
                        raw_tech.append(meta["auth_scheme"])
                except json.JSONDecodeError:
                    # PATCH (REL-013, 2026-06-15): Was bare `except: pass` which
                    # swallowed everything including KeyboardInterrupt/SystemExit.
                    # Narrow to JSONDecodeError since meta is sometimes a freeform
                    # string written by older agents (non-JSON tech markers).
                    pass

        # 2. Use LLM to reason over raw tech and build a clean profile
        context = f"Raw technology markers identified for {engagement_id}:\n" + ", ".join(
            str(t) for t in list(set(raw_tech))
        )

        messages = [
            {
                "role": "system",
                "content": "You are a Stack Profiler. Based on raw technology markers, identify the likely Frontend, Backend, Database, Auth, and Cloud providers. Output ONLY a valid JSON object.",
            },
            {"role": "user", "content": context},
        ]

        profile_json = await self.ctx.llm_client.complete(messages)
        import json

        try:
            self.current_profile = json.loads(profile_json)
        except (json.JSONDecodeError, TypeError, ValueError):
            self.current_profile = {"error": "Failed to parse profile reasoning"}

        # 3. Store the profile in the graph
        await self.ctx.graph_memory.add_relationship(
            f"asset-{engagement_id}",
            f"asset-{engagement_id}",  # Self-link for now to engagement root
            "HAS_STACK_PROFILE",
            self.current_profile,
        )

        reasoning = f"Target stack identified: {self.current_profile.get('frontend', 'Unknown')} / {self.current_profile.get('backend', 'Unknown')}. Cross-referencing with Bug Pattern Engine..."
        await self.think(reasoning, [])

        return {"status": "success", "profile": self.current_profile, "reasoning": reasoning}

    async def _cleanup_resources(self) -> None:
        self.current_profile.clear()
