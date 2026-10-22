"""Durable, read-only research and settled Flow proposal checkpoints.

These records live in the existing PostgreSQL task ledger. They are inert:
recovery may reconstruct an operator-review proposal, but never rerun a model
call or dispatch an execution subtask. A missing receipt is an UNKNOWN outcome.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import select

from ai_osop.core.config import AgentType
from ai_osop.core.models import FlowRecord, Task
from ai_osop.memory.authorization_store import guard_sql
from ai_osop.memory.model_usage import ModelOutcomeUncertain
from ai_osop.memory.session_memory import (
    ApprovalRequestORM,
    ExecutionFlowORM,
    ExecutionSubtaskORM,
    TaskORM,
)
from ai_osop.orchestrator.planner_execution import PlannerAdmission, PlannerExecutionStore


class ResearchCheckpointDenied(PermissionError):
    """A signed or Flow-bound research checkpoint cannot be trusted."""


@dataclass(frozen=True)
class SettledProposal:
    steps: list[dict[str, Any]]
    provenance: str
    revision: int


class ResearchCheckpointStore(PlannerExecutionStore):
    """Single-use planner checkpoints fenced by the existing SQL authority."""

    _SIGNAL_KEYS = frozenset(
        {
            "assets_count",
            "assets_discovered",
            "endpoints_count",
            "endpoints_found",
            "findings_count",
            "vulnerabilities_found",
            "confirmed_findings_count",
            "warnings_count",
            "verified",
        }
    )

    @staticmethod
    def _proposal_digest(steps: Any, provenance: str, source_digest: str) -> str:
        """Bind the exact settled proposal bytes to their research receipt."""
        try:
            if not isinstance(steps, list) or len(steps) > 15:
                raise ValueError("Invalid proposal shape")
            encoded = json.dumps(
                {"steps": steps, "provenance": provenance, "research_digest": source_digest},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
            if len(encoded) > 19000:
                raise ValueError("Proposal digest exceeds bound")
            return hashlib.sha256(encoded).hexdigest()
        except (TypeError, ValueError, OverflowError) as exc:
            raise ModelOutcomeUncertain(
                "Settled proposal integrity unavailable; no replay"
            ) from exc

    @classmethod
    async def _source_fingerprint(
        cls,
        db: Any,
        *,
        planner_id: str,
        flow: FlowRecord,
        parent: Task,
        source_id: Optional[str],
        revision: int,
        authorization_version: int,
        scope_digest: str,
    ) -> str:
        """Re-read exact original research provenance under the same SQL lock.

        A completed planner receipt alone proves neither which bounded graph-
        first research input was used nor whether that input was replaced in
        storage after settlement. Never reconstruct missing evidence or retry
        an uncertain external model call.
        """
        identifier = cls._research_id(planner_id)
        research = (
            await db.execute(
                select(TaskORM)
                .where(
                    TaskORM.id == identifier,
                    TaskORM.engagement_id == flow.engagement_id,
                )
                .with_for_update(read=True)
            )
        ).scalar_one_or_none()
        expected = {
            "schema": 1,
            "authorization_version": authorization_version,
            "flow_revision": revision,
            "scope_digest": scope_digest,
        }
        if (
            research is None
            or research.id != identifier
            or research.engagement_id != flow.engagement_id
            or research.type != "planner_research"
            or research.status != "completed"
            or research.flow_id != flow.id
            or research.parent_task_id != parent.id
            or research.subtask_id != source_id
            or research.assigned_agent_id != "planner-research"
            or not isinstance(research.payload, dict)
            or research.payload.get("planner_task_id") != planner_id
            or not isinstance(research.result, dict)
            or set(research.result) != {*expected, "signals"}
            or any(research.result.get(k) != v for k, v in expected.items())
        ):
            raise ModelOutcomeUncertain(
                "Original signed research checkpoint missing or replaced; no replay"
            )
        signals = research.result["signals"]
        if (
            not isinstance(signals, dict)
            or len(signals) > len(cls._SIGNAL_KEYS)
            or not set(signals).issubset(cls._SIGNAL_KEYS)
            or any(
                type(value) is not bool
                and (type(value) not in {int, float} or not 0 <= value <= 1000000)
                for value in signals.values()
            )
        ):
            raise ModelOutcomeUncertain("Research evidence is not bounded; no replay")
        # Include identity and COMPLETE bounded research data; otherwise
        # altering signals while retaining the version/digest metadata would
        # silently change the provenance of a settled model proposal.
        try:
            canonical = json.dumps(
                {
                    "research_id": identifier,
                    "engagement_id": flow.engagement_id,
                    "flow_id": flow.id,
                    "parent_task_id": parent.id,
                    "subtask_id": source_id,
                    "planner_task_id": planner_id,
                    "result": research.result,
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (ValueError, TypeError, OverflowError) as exc:
            raise ModelOutcomeUncertain(
                "Research source digest cannot be verified; no replay"
            ) from exc
        return hashlib.sha256(canonical).hexdigest()

    @staticmethod
    def _research_id(planner_id: str) -> str:
        return "task-research-" + hashlib.sha256(planner_id.encode()).hexdigest()[:32]

    @staticmethod
    def _digest(engagement: Any) -> str:
        # The current signed version is checked independently; this also
        # rejects mutable scope / ROE replacement under an unchanged version.
        data = json.dumps(
            {"scope": engagement.scope, "roe": engagement.roe},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(data.encode()).hexdigest()

    @staticmethod
    def _identity(
        flow: FlowRecord, parent: Task, purpose: str, source_id: Optional[str], pass_number: int
    ) -> str:
        if (
            purpose not in {"flow_generation", "flow_refinement"}
            or parent.type != "flow_objective"
            or parent.status != "planned"
            or parent.flow_id != flow.id
            or parent.engagement_id != flow.engagement_id
            or flow.status not in {"pending", "running"}
            or (purpose == "flow_refinement") != bool(source_id)
            or type(pass_number) is not int
            or not 0 <= pass_number <= 3
        ):
            raise ResearchCheckpointDenied("Research source is not authorized")
        return PlannerExecutionStore.task_id(
            flow.id,
            parent.id,
            purpose,
            source_id or "",
            pass_number,
        )

    async def _fence(
        self,
        db: Any,
        flow: FlowRecord,
        parent: Task,
        source_id: Optional[str],
        pass_number: int,
        revision: int,
    ) -> tuple[Any, int]:
        engagement, _ = await self._guard(db, flow.engagement_id, require_window=True)
        signed = await guard_sql(db, flow.engagement_id)
        current = (
            await db.execute(
                select(ExecutionFlowORM)
                .where(
                    ExecutionFlowORM.id == flow.id,
                    ExecutionFlowORM.engagement_id == flow.engagement_id,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        source = (
            await db.execute(
                select(TaskORM)
                .where(
                    TaskORM.id == parent.id,
                    TaskORM.engagement_id == flow.engagement_id,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if (
            current is None
            or current.status not in {"pending", "running"}
            or current.revision != revision
            or current.status != flow.status
            or source is None
            or source.type != parent.type
            or source.status != "planned"
            or source.flow_id != flow.id
        ):
            raise ResearchCheckpointDenied("Flow or objective changed during research")
        if source_id:
            step = (
                await db.execute(
                    select(ExecutionSubtaskORM)
                    .where(
                        ExecutionSubtaskORM.id == source_id,
                        ExecutionSubtaskORM.engagement_id == flow.engagement_id,
                        ExecutionSubtaskORM.flow_id == flow.id,
                        ExecutionSubtaskORM.task_id == parent.id,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if (
                step is None
                or step.status != "completed"
                or step.refinement_count != pass_number
                or not step.execution_task_id
            ):
                raise ResearchCheckpointDenied("Research source is no longer confirmed")
            executed = (
                await db.execute(
                    select(TaskORM.id)
                    .where(
                        TaskORM.id == step.execution_task_id,
                        TaskORM.engagement_id == flow.engagement_id,
                        TaskORM.flow_id == flow.id,
                        TaskORM.subtask_id == source_id,
                        TaskORM.status == "completed",
                    )
                    .with_for_update(read=True)
                )
            ).scalar_one_or_none()
            if executed is None:
                raise ResearchCheckpointDenied("Completed source receipt is missing")
        return engagement, signed.version

    async def _approved(self, db: Any, planner: Any, engagement_id: str) -> None:
        if not planner.approval_required:
            return
        payload = planner.payload if isinstance(planner.payload, dict) else {}
        approval = (
            await db.execute(
                select(ApprovalRequestORM).where(
                    ApprovalRequestORM.id == self.approval_id(planner.id),
                    ApprovalRequestORM.engagement_id == engagement_id,
                    ApprovalRequestORM.task_id == planner.id,
                )
            )
        ).scalar_one_or_none()
        if (
            approval is None
            or approval.status != "approved"
            or approval.agent_id != "planner-runtime"
            or approval.action_type != "planner_inference"
            or approval.target != planner.flow_id
            or not approval.operator_id
            or approval.responded_at is None
            or payload.get("operator_approved") is not True
            or payload.get("approval_id") != approval.id
        ):
            raise ResearchCheckpointDenied("Human planner approval is no longer valid")

    async def recover(
        self,
        flow: FlowRecord,
        parent: Task,
        *,
        purpose: str,
        source_id: Optional[str],
        pass_number: int,
    ) -> Optional[SettledProposal]:
        """Replay only a persisted result; never replay provider activity."""
        planner_id = self._identity(flow, parent, purpose, source_id, pass_number)
        async with self._sessions() as db:
            async with db.begin():
                engagement, signed_version = await self._fence(
                    db,
                    flow,
                    parent,
                    source_id,
                    pass_number,
                    flow.revision,
                )
                task = (
                    await db.execute(
                        select(TaskORM)
                        .where(
                            TaskORM.id == planner_id,
                            TaskORM.engagement_id == flow.engagement_id,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if task is None or task.status == "awaiting_approval":
                    return None
                payload = task.payload if isinstance(task.payload, dict) else {}
                result = task.result if isinstance(task.result, dict) else {}
                if (
                    task.type != "planner_inference"
                    or task.flow_id != flow.id
                    or task.parent_task_id != parent.id
                    or task.subtask_id != source_id
                    or task.assigned_agent_id != "planner-runtime"
                    or payload.get("_authorization_version") != signed_version
                    or payload.get("planner_purpose") != purpose
                ):
                    raise ResearchCheckpointDenied("Planner checkpoint binding is stale")
                if task.status != "completed":
                    raise ModelOutcomeUncertain("Previous planner call is unresolved; no replay")
                if (
                    result.get("status") != "completed"
                    or result.get("checkpoint_schema") != 1
                    or result.get("flow_revision") != flow.revision
                    or result.get("scope_digest") != self._digest(engagement)
                    or result.get("provenance") not in {"llm", "deterministic"}
                    or not isinstance(result.get("proposal_steps"), list)
                    or len(result["proposal_steps"]) > 15
                ):
                    raise ModelOutcomeUncertain(
                        "Settled planner output is missing; no provider replay"
                    )
                await self._approved(db, task, flow.engagement_id)
                source_digest = await self._source_fingerprint(
                    db,
                    planner_id=planner_id,
                    flow=flow,
                    parent=parent,
                    source_id=source_id,
                    revision=flow.revision,
                    authorization_version=signed_version,
                    scope_digest=self._digest(engagement),
                )
                # Source evidence is a separate durable record, not an
                # attribute implied by successful model execution. A missing
                # binding is UNKNOWN even for a "completed" planner result.
                if result.get("research_digest") != source_digest:
                    raise ModelOutcomeUncertain(
                        "Research checkpoint lineage changed; no provider replay"
                    )
                if result.get("proposal_sha256") != self._proposal_digest(
                    result["proposal_steps"], result["provenance"], source_digest
                ):
                    raise ModelOutcomeUncertain(
                        "Settled proposal bytes changed; no provider replay"
                    )
                # Re-validate all recovered proposal text using ProposedPlan in
                # the caller; never trust JSON persisted by a previous process.
                return SettledProposal(
                    steps=result["proposal_steps"],
                    provenance=result["provenance"],
                    revision=flow.revision,
                )

    async def prepare(
        self,
        admission: PlannerAdmission,
        flow: FlowRecord,
        parent: Task,
        *,
        source_id: Optional[str],
        pass_number: int,
        signals: dict[str, Any],
    ) -> dict[str, Any]:
        """Commit bounded local evidence before the one allowed model request."""
        purpose = "flow_refinement" if source_id else "flow_generation"
        if self._identity(flow, parent, purpose, source_id, pass_number) != admission.task_id:
            raise ResearchCheckpointDenied("Research admission does not match the source")
        if admission.engagement_id != flow.engagement_id or admission.flow_id != flow.id:
            raise ResearchCheckpointDenied("Research admission belongs to another Flow")
        # Untrusted scan material must never reach research storage or a model.
        allowed = {
            key: value
            for key, value in signals.items()
            if key
            in {
                "assets_count",
                "assets_discovered",
                "endpoints_count",
                "endpoints_found",
                "findings_count",
                "vulnerabilities_found",
                "confirmed_findings_count",
                "warnings_count",
                "verified",
            }
            and (type(value) is bool or (type(value) in {int, float} and 0 <= value <= 1000000))
        }
        identifier = self._research_id(admission.task_id)
        async with self._sessions() as db:
            async with db.begin():
                engagement, version = await self._fence(
                    db,
                    flow,
                    parent,
                    source_id,
                    pass_number,
                    admission.revision,
                )
                planner = (
                    await db.execute(
                        select(TaskORM)
                        .where(
                            TaskORM.id == admission.task_id,
                            TaskORM.engagement_id == flow.engagement_id,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if (
                    planner is None
                    or planner.status != "running"
                    or planner.type != "planner_inference"
                    or planner.parent_task_id != parent.id
                    or planner.subtask_id != source_id
                    or planner.payload.get("_authorization_version") != version
                ):
                    raise ResearchCheckpointDenied("Planner admission is no longer active")
                await self._approved(db, planner, flow.engagement_id)
                expected = {
                    "schema": 1,
                    "authorization_version": version,
                    "flow_revision": admission.revision,
                    "scope_digest": self._digest(engagement),
                    "signals": allowed,
                }
                research = (
                    await db.execute(
                        select(TaskORM)
                        .where(
                            TaskORM.id == identifier,
                            TaskORM.engagement_id == flow.engagement_id,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if research is not None:
                    if (
                        research.type != "planner_research"
                        or research.parent_task_id != parent.id
                        or research.flow_id != flow.id
                        or research.subtask_id != source_id
                        or research.status != "completed"
                        or research.result != expected
                    ):
                        raise ResearchCheckpointDenied("Research checkpoint was changed")
                else:
                    now = datetime.utcnow()
                    db.add(
                        TaskORM(
                            id=identifier,
                            type="planner_research",
                            priority=parent.priority,
                            agent_type=AgentType.CONTEXT_MANAGER.value,
                            payload={"planner_task_id": admission.task_id},
                            dependencies=[],
                            max_retries=0,
                            timeout_seconds=parent.timeout_seconds,
                            scope_check=True,
                            approval_required=False,
                            status="completed",
                            result=expected,
                            retry_count=0,
                            created_at=now,
                            started_at=now,
                            completed_at=now,
                            engagement_id=flow.engagement_id,
                            assigned_agent_id="planner-research",
                            flow_id=flow.id,
                            subtask_id=source_id,
                            parent_task_id=parent.id,
                        )
                    )
                    await db.flush()
                    await self._append_event(
                        db,
                        flow.engagement_id,
                        identifier,
                        "planner.research_checkpoint",
                        "planner-runtime",
                        {"status": "completed", "revision": admission.revision},
                        idempotency_key="planner-research:" + identifier,
                    )
                return dict(allowed)

    async def save_proposal(
        self,
        admission: PlannerAdmission,
        flow: FlowRecord,
        parent: Task,
        *,
        source_id: Optional[str],
        pass_number: int,
        steps: list[dict[str, Any]],
        provenance: str,
    ) -> None:
        """Save bounded model output after its single-use completion receipt."""
        purpose = "flow_refinement" if source_id else "flow_generation"
        if (
            self._identity(flow, parent, purpose, source_id, pass_number) != admission.task_id
            or admission.engagement_id != flow.engagement_id
            or admission.flow_id != flow.id
            or provenance not in {"llm", "deterministic"}
            or len(steps) > 15
            or len(json.dumps(steps, default=str)) > 18000
        ):
            raise ResearchCheckpointDenied("Proposal is not a bounded planner result")
        async with self._sessions() as db:
            async with db.begin():
                engagement, version = await self._fence(
                    db,
                    flow,
                    parent,
                    source_id,
                    pass_number,
                    admission.revision,
                )
                task = (
                    await db.execute(
                        select(TaskORM)
                        .where(
                            TaskORM.id == admission.task_id,
                            TaskORM.engagement_id == flow.engagement_id,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if (
                    task is None
                    or task.status != "completed"
                    or task.type != "planner_inference"
                    or task.parent_task_id != parent.id
                    or task.subtask_id != source_id
                    or task.result != {"status": "completed"}
                    or task.payload.get("_authorization_version") != version
                    or task.payload.get("planner_purpose") != purpose
                ):
                    raise ResearchCheckpointDenied("Completed model receipt is unavailable")
                await self._approved(db, task, flow.engagement_id)
                task.result = {
                    "status": "completed",
                    "checkpoint_schema": 1,
                    "flow_revision": admission.revision,
                    "scope_digest": self._digest(engagement),
                    "provenance": provenance,
                    "proposal_steps": steps,
                }
                await db.flush()
                await self._append_event(
                    db,
                    flow.engagement_id,
                    admission.task_id,
                    "planner.proposal_checkpoint",
                    "planner-runtime",
                    {"status": "completed", "revision": admission.revision},
                    idempotency_key="planner-proposal:" + admission.task_id,
                )

    async def complete_with_proposal_atomic(
        self,
        admission: PlannerAdmission,
        flow: FlowRecord,
        parent: Task,
        *,
        source_id: Optional[str],
        pass_number: int,
        steps: list[dict[str, Any]],
        provenance: str,
    ) -> None:
        """Complete the planner Task and validated proposal in ONE PG commit.

        Failure before this commit remains UNKNOWN; never replay a paid call.
        """
        purpose = "flow_refinement" if source_id else "flow_generation"
        if (
            self._identity(flow, parent, purpose, source_id, pass_number) != admission.task_id
            or admission.engagement_id != flow.engagement_id
            or admission.flow_id != flow.id
            or admission.revision != flow.revision
            or provenance not in {"llm", "deterministic"}
            or not isinstance(steps, list)
            or len(steps) > 15
        ):
            raise ResearchCheckpointDenied("Planner settlement identity invalid")
        try:
            encoded = json.dumps(
                steps, sort_keys=True, separators=(",", ":"), allow_nan=False, ensure_ascii=False
            )
        except (ValueError, TypeError) as exc:
            raise ResearchCheckpointDenied("Invalid planner settlement") from exc
        if len(encoded.encode("utf-8")) > 18000:
            raise ResearchCheckpointDenied("Planner settlement exceeds safe bounds")
        # This method is a durable boundary, not just a caller helper:
        # forbid persisting arbitrary agent/model instructions as proposals.
        try:
            from ai_osop.orchestrator.flow_refinement import ProposedPlan

            validated = ProposedPlan.model_validate({"steps": steps})
            if [step.model_dump(mode="json") for step in validated.steps] != steps:
                raise ValueError("Canonical proposal mismatch")
        except Exception as exc:
            raise ResearchCheckpointDenied("Planner proposal schema invalid") from exc
        async with self._sessions() as db:
            async with db.begin():
                engagement, version = await self._fence(
                    db,
                    flow,
                    parent,
                    source_id,
                    pass_number,
                    admission.revision,
                )
                planner = (
                    await db.execute(
                        select(TaskORM)
                        .where(
                            TaskORM.id == admission.task_id,
                            TaskORM.engagement_id == flow.engagement_id,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if (
                    planner is None
                    or planner.status != "running"
                    or planner.type != "planner_inference"
                    or planner.flow_id != flow.id
                    or planner.parent_task_id != parent.id
                    or planner.subtask_id != source_id
                    or planner.assigned_agent_id != "planner-runtime"
                    or not isinstance(planner.payload, dict)
                    or planner.payload.get("_authorization_version") != version
                    or planner.payload.get("planner_purpose") != purpose
                ):
                    raise ResearchCheckpointDenied("Planner settlement claim unavailable")
                await self._approved(db, planner, flow.engagement_id)
                research = (
                    await db.execute(
                        select(TaskORM)
                        .where(
                            TaskORM.id == self._research_id(admission.task_id),
                            TaskORM.engagement_id == flow.engagement_id,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                expected = {
                    "schema": 1,
                    "authorization_version": version,
                    "flow_revision": admission.revision,
                    "scope_digest": self._digest(engagement),
                }
                if (
                    research is None
                    or research.status != "completed"
                    or research.type != "planner_research"
                    or research.flow_id != flow.id
                    or research.parent_task_id != parent.id
                    or research.subtask_id != source_id
                    or not isinstance(research.result, dict)
                    or any(research.result.get(key) != value for key, value in expected.items())
                ):
                    raise ResearchCheckpointDenied("Source research checkpoint unavailable")
                source_digest = await self._source_fingerprint(
                    db,
                    planner_id=admission.task_id,
                    flow=flow,
                    parent=parent,
                    source_id=source_id,
                    revision=admission.revision,
                    authorization_version=version,
                    scope_digest=expected["scope_digest"],
                )
                planner.status = "completed"
                planner.result = {
                    "status": "completed",
                    "checkpoint_schema": 1,
                    "flow_revision": admission.revision,
                    "scope_digest": self._digest(engagement),
                    "research_digest": source_digest,
                    "provenance": provenance,
                    "proposal_steps": steps,
                    "proposal_sha256": self._proposal_digest(steps, provenance, source_digest),
                }
                planner.completed_at = datetime.utcnow()
                await db.flush()
                await self._append_event(
                    db,
                    flow.engagement_id,
                    admission.task_id,
                    "planner.finished",
                    "planner-runtime",
                    {"status": "completed", "revision": admission.revision},
                    idempotency_key="planner-finished:" + admission.task_id,
                )
                await self._append_event(
                    db,
                    flow.engagement_id,
                    admission.task_id,
                    "planner.proposal_checkpoint",
                    "planner-runtime",
                    {"status": "completed", "revision": admission.revision},
                    idempotency_key="planner-proposal:" + admission.task_id,
                )
