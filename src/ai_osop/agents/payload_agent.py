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
from ai_osop.memory.model_usage import ModelBudgetExceeded, ModelOutcomeUncertain
from ai_osop.core.models import FlowRecord, Payload, Task
from ai_osop.core.telemetry import RequestContext
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
                embedding=embedding, payload_type=vuln_type.value, limit=3,
                engagement_id=self.ctx.session_id, task_id=self.ctx.current_task.id,
            )
        except (ModelBudgetExceeded, ModelOutcomeUncertain):
            raise
        except Exception as e:
            # Vector stores and provider SDKs can echo sensitive request
            # data. Log only the exception class, never raw content.
            print(f"WARN: Semantic retrieval unavailable ({type(e).__name__})")

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
            "payloads": [p.model_dump() for p in refined_payloads],
            "semantic_hits": len(similar_payloads),
        }

    async def _mutate_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Mutate a specific payload (e.g., after a WAF block)."""
        raw_payload = Payload.model_validate(payload["payload"])
        strategy = payload.get("strategy", "waf_bypass")

        mutated = await self.mcp_adapter.mutate_payload(
            raw_payload, strategy=strategy, generation=raw_payload.generation + 1
        )

        return {
            "status": "success",
            "original_id": raw_payload.id,
            "mutated_payload": mutated.model_dump(),
        }

    async def _evolve_population(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Run evolutionary cycle on a payload group."""
        vuln_type = VulnClass(payload["vuln_type"])
        context = payload.get("context", {})
        population = [Payload.model_validate(p) for p in payload["population"]]

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
            "population": [p.model_dump() for p in evolved],
        }

    async def initialize(self) -> None:
        """Initialize agent state from persistent memory."""
        await super().initialize()

        # Retain the handle in BaseAgent's lifecycle-owned background tasks.
        # Shutdown cancels/awaits it so a reused agent cannot keep listening
        # to another engagement's best-effort events.
        self._bg_tasks.append(asyncio.create_task(self._listen_for_feedback()))

    async def _listen_for_feedback(self) -> None:
        """Consume only explicitly tagged, local engagement feedback."""
        engagement_id = self.ctx.session_id
        async for event in self.ctx.coordination_bus.subscribe(
            "feedback.payload_validated", engagement_id=engagement_id,
        ):
            if self._shutting_down:
                break
            await self._process_feedback(event.payload)

    async def _feedback_task_authorized(self, payload: Any) -> bool:
        """Fail closed before embedding or vector writes for untrusted feedback."""
        task = self.ctx.current_task
        if (
            not isinstance(payload, dict)
            or not isinstance(task, Task)
            or task.status != "running"
            or task.type != "process_feedback"
            or task.agent_type != AgentType.PAYLOAD_MUTATION
            or self._shutting_down
            or self.ctx.status != "running"
            or not isinstance(self.ctx.session_id, str)
            or not self.ctx.session_id
            or task.engagement_id != self.ctx.session_id
            or payload.get("engagement_id") != task.engagement_id
            or not isinstance(payload.get("payload"), dict)
            or payload["payload"].get("engagement_id") != task.engagement_id
            or not isinstance(payload.get("result"), dict)
            or (
                "engagement_id" in payload["result"]
                and payload["result"]["engagement_id"] != task.engagement_id
            )
            or not isinstance(task.payload, dict)
            or type(task.payload.get("_authorization_version")) is not int
            or task.payload["_authorization_version"] < 1
            # A same-tenant bus publisher is NOT automatically an approved
            # feedback source. Require the exact feedback body already pinned
            # to this executing PostgreSQL Task instead of accepting a new
            # event's arbitrary payload/result while a task happens to run.
            or task.payload.get("engagement_id") != task.engagement_id
            or task.payload.get("payload") != payload.get("payload")
            or task.payload.get("result") != payload.get("result")
        ):
            return False
        # Async task context is advisory, never an authorization source. A
        # stale context must not allow feedback to cross execution identities.
        bound = RequestContext.get()
        if (
            (bound.get("engagement_id") and bound["engagement_id"] != task.engagement_id)
            or (bound.get("task_id") and bound["task_id"] != task.id)
        ):
            return False
        memory = self.ctx.session_memory
        load = getattr(memory, "load_task_authoritative", None)
        authorize = getattr(memory, "assert_signed_authorization", None)
        if not callable(load) or not callable(authorize):
            return False
        try:
            persisted = await asyncio.wait_for(load(task.id), timeout=3)
            if (
                not isinstance(persisted, Task)
                or persisted.id != task.id
                or persisted.engagement_id != task.engagement_id
                or persisted.status != "running"
                or persisted.type != task.type
                or persisted.agent_type != AgentType.PAYLOAD_MUTATION
                or persisted.payload != task.payload
                or persisted.approval_required != task.approval_required
                or persisted.flow_id != task.flow_id
            ):
                return False
            signed = await asyncio.wait_for(
                authorize(task.engagement_id, expected_version=task.payload["_authorization_version"]),
                timeout=3,
            )
            if (
                type(getattr(signed, "version", None)) is not int
                or signed.version != task.payload["_authorization_version"]
            ):
                return False
            if task.flow_id:
                load_flow = getattr(memory, "load_flow", None)
                if not callable(load_flow):
                    return False
                flow = await asyncio.wait_for(load_flow(task.flow_id), timeout=3)
                if (
                    not isinstance(flow, FlowRecord)
                    or flow.id != task.flow_id
                    or flow.engagement_id != task.engagement_id
                    or flow.status not in {"pending", "running"}
                ):
                    return False
            if task.approval_required:
                check_approval = getattr(memory, "is_task_approved", None)
                approval_id = task.payload.get("approval_id")
                if (
                    not callable(check_approval)
                    or not isinstance(approval_id, str)
                    or not approval_id
                    or await asyncio.wait_for(
                        check_approval(task.id, task.engagement_id, approval_id), timeout=3,
                    ) is not True
                ):
                    return False
            return (
                self.ctx.current_task is task
                and task.status == "running"
                and self.ctx.session_id == task.engagement_id
                and not self._shutting_down
            )
        except Exception:
            # Durable lookup, signed ROE and approval checks must fail before
            # spending provider usage or mutating semantic memory.
            return False

    async def _process_feedback(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Process results from ExploitValidationAgent to update memory."""
        if not await self._feedback_task_authorized(payload):
            return {"status": "ignored", "reason": "feedback_scope_or_task_unverified"}
        raw_payload_data = payload.get("payload")
        if not raw_payload_data:
            return {"status": "ignored", "reason": "feedback_payload_invalid"}

        try:
            raw_payload = Payload.model_validate(raw_payload_data)
        except Exception:
            # Pydantic errors can include attacker-controlled payload text.
            return {"status": "ignored", "reason": "feedback_payload_invalid"}

        # Payload.model_validate's acceptance is not a tenant proof; the
        # nested object must agree with the pinned executing engagement.
        if raw_payload.engagement_id != self.ctx.session_id:
            return {"status": "ignored", "reason": "feedback_scope_or_task_unverified"}
        result = payload.get("result", {})

        # Calculate fitness
        fitness = self.engine.fitness_evaluator.evaluate(
            raw_payload, result, waf_detected=result.get("waf_blocked", False)
        )
        raw_payload.fitness_score = fitness

        # Store in Vector Memory if successful or high fitness
        stored_semantically = False
        if fitness > 0.7:
            if not await self._feedback_task_authorized(payload):
                return {"status": "ignored", "reason": "feedback_scope_or_task_unverified"}
            try:
                embedding = await self.ctx.llm_client.get_embedding(raw_payload.content)
                if not await self._feedback_task_authorized(payload):
                    return {"status": "ignored", "reason": "feedback_scope_or_task_unverified"}
                await self.ctx.vector_memory.store_payload(
                    payload_type=raw_payload.vuln_type.value,
                    content=raw_payload.content,
                    embedding=embedding,
                    metadata={
                        "fitness": fitness,
                        "target": result.get("target"),
                        "timestamp": datetime.utcnow().isoformat(),
                    },
                    engagement_id=self.ctx.session_id,
                    task_id=self.ctx.current_task.id,
                )
                stored_semantically = True
            except (ModelBudgetExceeded, ModelOutcomeUncertain):
                raise
            except Exception as e:
                print(f"WARN: Tenant semantic persistence unavailable ({type(e).__name__})")

        return {
            "status": "success",
            "updated_fitness": fitness,
            "stored_semantically": stored_semantically,
        }

    async def _cleanup_resources(self) -> None:
        """No specific cleanup needed."""
        pass
