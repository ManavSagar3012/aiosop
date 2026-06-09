"""
Payload Mutation Agent
Generates, mutates, and evolves exploitation payloads using semantic memory
and adaptive intelligence.
"""

import asyncio
import hashlib
from datetime import datetime
from typing import Any, Dict, List, Optional

from ai_osop.adapters.payload_mcp import PayloadMCPAdapter
from ai_osop.agents.base import BaseAgent
from ai_osop.core.config import AgentType, VulnClass, settings
from ai_osop.core.exceptions import AgentException
from ai_osop.core.models import Payload, Task
from ai_osop.payload_engine.engine import AdaptivePayloadEngine


class PayloadMutationAgent(BaseAgent):
    """
    Agent responsible for generating and evolving payloads tailored to specific
    targets, bypassing WAFs, and learning from validation feedback.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.PAYLOAD_MUTATION

    async def _setup_resources(self) -> None:
        """Initialize engine and memory."""
        self.mcp_adapter = PayloadMCPAdapter(self.ctx.mcp_registry)
        self.engine = AdaptivePayloadEngine(self.mcp_adapter, llm_client=self.ctx.llm_client)
        # Vector memory is accessible via self.ctx.vector_memory (to be added to Context)

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute payload mutation tasks."""
        task_type = task.type
        payload = task.payload

        if task_type == "generate_payloads":
            return await self._generate_payloads(payload)
        elif task_type == "mutate_payload":
            return await self._mutate_payload(payload)
        elif task_type == "evolve_population":
            return await self._evolve_population(payload)
        elif task_type == "process_feedback":
            return await self._process_feedback(payload)
        else:
            raise AgentException(f"Unknown payload task type: {task_type}")

    async def _generate_payloads(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Generate initial set of payloads for a target."""
        vuln_type = VulnClass(payload["vuln_type"])
        context = payload.get("context", {})
        count = payload.get("count", 5)

        # 1. Semantic Retrieval from Vector Memory
        # Find historically successful payloads for this vuln type
        similar_payloads = []
        try:
            # Generate embedding for the context
            context_str = str(context)
            embedding = await self.ctx.llm_client.get_embedding(context_str)
            similar_payloads = await self.ctx.vector_memory.search_similar_payloads(
                embedding=embedding, payload_type=vuln_type.value, limit=3
            )
        except Exception as e:
            print(f"WARN: Semantic retrieval failed: {e}")

        # 2. Engine Generation
        population = await self.engine.generate_initial_population(
            vuln_type=vuln_type, context=context, population_size=count
        )

        # 3. LLM Refinement
        # Use LLM to adapt top payloads using specialized skills
        skill_content = self._load_skill(vuln_type.value)
        system_prompt = f"You are an expert at {vuln_type.value} exploitation.\n"
        if skill_content:
            system_prompt += f"\nFollow these specific procedures:\n{skill_content}\n"
        system_prompt += f"\nAdapt the following payload to the target context: {context}"

        refined_payloads = []
        for p in population:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Payload: {p.content}"},
            ]
            adapted_content = await self.ctx.llm_client.complete(messages)
            p.content = adapted_content
            refined_payloads.append(p)

        return {
            "status": "success",
            "payloads": [p.dict() for p in refined_payloads],
            "semantic_hits": len(similar_payloads),
        }

    async def _mutate_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Mutate a specific payload (e.g., after a WAF block)."""
        raw_payload = Payload.parse_obj(payload["payload"])
        strategy = payload.get("strategy", "waf_bypass")

        mutated = await self.mcp_adapter.mutate_payload(
            raw_payload, strategy=strategy, generation=raw_payload.generation + 1
        )

        return {
            "status": "success",
            "original_id": raw_payload.id,
            "mutated_payload": mutated.dict(),
        }

    async def _evolve_population(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Run evolutionary cycle on a payload group."""
        vuln_type = VulnClass(payload["vuln_type"])
        context = payload.get("context", {})
        population = [Payload.parse_obj(p) for p in payload["population"]]

        evolved = await self.engine.evolve_population(
            population=population,
            vuln_type=vuln_type,
            context=context,
            generations=payload.get("generations", 5),
        )

        return {
            "status": "success",
            "evolved_count": len(evolved),
            "top_fitness": evolved[0].fitness_score if evolved else 0.0,
            "population": [p.dict() for p in evolved],
        }

    async def initialize(self) -> None:
        """Initialize agent state from persistent memory."""
        await super().initialize()
        
        # Subscribe to feedback
        asyncio.create_task(self._listen_for_feedback())

    async def _listen_for_feedback(self) -> None:
        """Listen for exploit validation feedback."""
        async for event in self.ctx.coordination_bus.subscribe("feedback.payload_validated"):
            await self._process_feedback(event.payload)

    async def _process_feedback(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Process results from ExploitValidationAgent to update memory."""
        raw_payload = Payload.parse_obj(payload["payload"])
        result = payload["result"]  # Output from ExploitValidationAgent

        # Calculate fitness
        fitness = self.engine.fitness_evaluator.evaluate(
            raw_payload, result, waf_detected=result.get("waf_blocked", False)
        )
        raw_payload.fitness_score = fitness

        # Store in Vector Memory if successful or high fitness
        if fitness > 0.7:
            try:
                embedding = await self.ctx.llm_client.get_embedding(raw_payload.content)
                await self.ctx.vector_memory.store_payload(
                    payload_type=raw_payload.vuln_type.value,
                    content=raw_payload.content,
                    embedding=embedding,
                    metadata={
                        "fitness": fitness,
                        "target": result.get("target"),
                        "timestamp": datetime.utcnow().isoformat(),
                    },
                )
            except Exception as e:
                print(f"ERROR: Failed to store successful payload in vector memory: {e}")

        return {
            "status": "success",
            "updated_fitness": fitness,
            "stored_semantically": fitness > 0.7,
        }

    async def _cleanup_resources(self) -> None:
        """No specific cleanup needed."""
        pass
