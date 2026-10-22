"""PostgreSQL-authoritative execution finalization and recoverable callback intents.

Only a verified in-progress attempt may atomically transition a TaskORM to a
terminal state. A corresponding pending callback record and redacted event/
outbox row commit in *the same* transaction. Callback leases never prove a
remote action stopped. Lost callback ACKs become explicit 'unknown' work,
requiring reconciliation instead of blindly replaying an external side effect.
"""

import hashlib
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, AsyncIterator, Dict, List, Optional

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, and_, func, or_, select, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import aliased

from ai_osop.core.models import ScopeDefinition
from ai_osop.core.exceptions import OutOfScopeError, ScopeValidationError
from ai_osop.memory.session_memory import (
    Base,
    TaskORM,
    ApprovalRequestORM,
    ExecutionActionORM,
    ExecutionFlowORM,
)
from ai_osop.memory.supervision_store import (
    SupervisionAttemptORM,
    SupervisionControlORM,
    SupervisionExecutionLeaseORM,
    SupervisionConflict,
    SupervisionStore,
)
from ai_osop.safety.scope import ScopeEnforcer, action_requires_approval, validate_payload_targets


_WORKFLOW_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_CALLBACK_EFFECTS = frozenset(
    {
        "sync_subtask",
        "graph_upsert",
        "flow_refinement",
        "downstream_schedule",
        "surface_continuation",
        "adaptive_planner",
        # TerminalCallbackDispatcher already includes this real signed MCP
        # provenance projection in its immutable effect plan. Omitting it here
        # caused every opted-in completed Flow callback to fail planning and
        # become UNKNOWN before any verified graph evidence was projected.
        "signed_graph_research",
        # Inert, PG-sourced comparison of two *separately approved* provider
        # observations. Never retries browser calls or promotes Vulnerability.
        "signed_diff_comparison",
    }
)


def _continuation_metadata(task_type: str, result: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """Keep only bounded identifiers needed by the existing workflow chain.

    No model reasoning, HTTP responses or tool arguments enter task status,
    event streams or the transactionally delivered lifecycle notification.
    """
    if not isinstance(result, dict):
        return {}
    clean: Dict[str, str] = {}
    workflow_id = result.get("workflow_id")
    if (
        task_type in {"map_workflow", "extract_har_api_inventory"}
        and isinstance(workflow_id, str)
        and _WORKFLOW_ID.fullmatch(workflow_id)
    ):
        clean["workflow_id"] = workflow_id
        if task_type == "map_workflow" and result.get("status") in {"success", "workflow_recorded"}:
            # The source task's PG status is still 'completed', but its
            # bounded result marker is required by the signed replay
            # admission and independently checked on every subsequent GET.
            # Do not turn a failed or unknown producer into valid evidence.
            clean["status"] = result["status"]
    har_path = result.get("har_path")
    if task_type == "capture_authenticated_surface" and isinstance(har_path, str):
        # File references are private durable task context, never event or
        # bus metadata. Disallow URL schemes, traversal and control bytes
        # before passing any saved reference to an extractor on recovery.
        normalized = har_path.replace("\\", "/")
        parts = normalized.split("/")
        if (
            1 <= len(har_path) <= 512
            and normalized.lower().endswith(".har")
            and "://" not in normalized
            and ".." not in parts
            and all(32 <= ord(char) < 127 for char in har_path)
            and not re.search(r"(?i)(password|token|secret|apikey)\s*=", har_path)
        ):
            clean["har_path"] = har_path
    return clean


_REPORT_ARTIFACTS = frozenset(
    {
        "md",
        "html",
        "graph.html",
        "json",
        "attestation",
        "manifest",
    }
)
_REPORT_SHA = re.compile(r"[0-9a-f]{64}\Z")
_REPLAY_TASK_ID = re.compile(r"task-[A-Za-z0-9._-]{1,59}\Z")
_REPLAY_EVENT_ID = re.compile(r"evt-[A-Za-z0-9._-]{1,60}\Z")


def _signed_report_terminal_receipt(
    task: TaskORM,
    result: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Preserve only exact digest metadata the v2 read verifier can check.

    A success-shaped LLM or agent result is not independently verified
    evidence. The report API later rehashes all six files and confirms the
    Ed25519 signature, signed policy and this exact completed Task.
    """
    payload = task.payload
    if task.type != "generate_report" or not isinstance(payload, dict):
        return None
    if payload.get("require_attestation") is not True:
        return None  # Legacy unsigned/v1 outputs remain draft snapshots.
    version = payload.get("version")
    expected_id = (
        f"report-{task.engagement_id}-{version}"
        if isinstance(version, str) and 0 < len(version) <= 128
        else None
    )
    hashes = result.get("artifact_sha256") if isinstance(result, dict) else None
    if (
        not task.approval_required
        or task.agent_type != "reporting"
        or task.started_at is None
        or type(payload.get("_authorization_version")) is not int
        or not isinstance(payload.get("signer_key_id"), str)
        or not isinstance(result, dict)
        or result.get("status") != "success"
        or result.get("signature_status") != "ed25519_signed"
        or result.get("requires_approval") is not True
        or result.get("report_id") != expected_id
        or not isinstance(hashes, dict)
        or set(hashes) != _REPORT_ARTIFACTS
        or any(not isinstance(v, str) or not _REPORT_SHA.fullmatch(v) for v in hashes.values())
    ):
        raise SupervisionConflict("Signed report generation lacks immutable artifact receipts")
    return {
        "status": "success",
        "signature_status": "ed25519_signed",
        "report_id": expected_id,
        "requires_approval": True,
        "artifact_sha256": {key: hashes[key] for key in sorted(_REPORT_ARTIFACTS)},
    }


def _signed_replay_terminal_receipt(
    task: TaskORM, result: Optional[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """Retain only bounded, explicitly non-authoritative provider testimony.

    Ordinary terminal continuation intentionally strips agent output, but the
    signed source/target comparator requires the independently persisted
    provider event identity and safe HTTP status/body fingerprint. Losing
    these on terminal COMMIT makes every real comparison inconclusive.
    """
    payload = task.payload
    if (
        task.type != "navigate"
        or not isinstance(payload, dict)
        or payload.get("_comparison_role") not in {"source", "target"}
    ):
        return None
    proof = result.get("provider_evidence") if isinstance(result, dict) else None
    role = payload["_comparison_role"]
    task_ids = (
        (
            result.get("source_task_id"),
            result.get("replay_parent_task_id"),
        )
        if isinstance(result, dict)
        else (None, None)
    )
    digest = result.get("response_body_sha256") if isinstance(result, dict) else None
    if (
        not task.approval_required
        or task.max_retries != 0
        or not isinstance(task.flow_id, str)
        or not isinstance(task.parent_task_id, str)
        or not isinstance(result, dict)
        or result.get("status") != "success"
        or result.get("verification_status") != "provider_testimony_only"
        or result.get("remote_effect_verified") is not False
        or result.get("authorization_violation_verified") is not False
        or result.get("comparison_role") != role
        or result.get("replay_parent_task_id") != task.parent_task_id
        or any(
            not isinstance(value, str) or _REPLAY_TASK_ID.fullmatch(value) is None
            for value in task_ids
        )
        or type(result.get("http_status_code")) is not int
        or not 100 <= result["http_status_code"] <= 599
        or type(result.get("redirected")) is not bool
        or (
            digest is not None
            and (not isinstance(digest, str) or _REPORT_SHA.fullmatch(digest) is None)
        )
        or not isinstance(proof, dict)
        or not isinstance(proof.get("provider_event_id"), str)
        or _REPLAY_EVENT_ID.fullmatch(proof["provider_event_id"]) is None
        or not isinstance(proof.get("provider_receipt_sha256"), str)
        or _REPORT_SHA.fullmatch(proof["provider_receipt_sha256"]) is None
        or proof.get("source_authenticity_verified") is not False
        or proof.get("target_effect_verified") is not False
        or proof.get("finding_verified") is not False
        or type(payload.get("_authorization_version")) is not int
        or payload["_authorization_version"] < 1
        or type(payload.get("_flow_revision")) is not int
        or payload["_flow_revision"] < 0
        or payload.get("method") != "GET"
    ):
        raise SupervisionConflict("Signed replay terminal result lacks bounded provider testimony")
    return {
        "status": "success",
        "source_task_id": result["source_task_id"],
        "replay_parent_task_id": task.parent_task_id,
        "comparison_role": role,
        "http_status_code": result["http_status_code"],
        "redirected": result["redirected"],
        "response_body_sha256": digest,
        "verification_status": "provider_testimony_only",
        "remote_effect_verified": False,
        "authorization_violation_verified": False,
        "provider_evidence": {
            "provider_event_id": proof["provider_event_id"],
            "provider_receipt_sha256": proof["provider_receipt_sha256"],
            "source_authenticity_verified": False,
            "target_effect_verified": False,
            "finding_verified": False,
        },
    }


class TerminalCallbackORM(Base):
    __tablename__ = "supervision_terminal_callbacks"

    id = Column(String(64), primary_key=True)
    engagement_id = Column(String(64), ForeignKey("session_states.session_id"), nullable=False)
    task_id = Column(String(64), nullable=False, unique=True)
    attempt_id = Column(String(64), nullable=False)
    outcome = Column(String(24), nullable=False)
    status = Column(String(24), nullable=False, default="pending")
    worker_id = Column(String(128), nullable=True)
    lease_id = Column(String(64), nullable=True)
    leased_until = Column(DateTime, nullable=True)
    attempts = Column(Integer, nullable=False, default=0)
    receipt = Column(JSONB, nullable=False)
    # A complete manifest is committed before the first side effect. Each
    # transition is independently committed and fenced by the callback lease.
    effect_steps = Column(JSONB, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now())
    completed_at = Column(DateTime, nullable=True)


def _record(row: TerminalCallbackORM) -> Dict[str, Any]:
    return {
        "id": row.id,
        "engagement_id": row.engagement_id,
        "task_id": row.task_id,
        "attempt_id": row.attempt_id,
        "outcome": row.outcome,
        "status": row.status,
        "worker_id": row.worker_id,
        "lease_id": row.lease_id,
        "leased_until": row.leased_until,
        "attempts": row.attempts,
        "receipt": row.receipt,
        "effect_steps": row.effect_steps,
        "created_at": row.created_at,
        "completed_at": row.completed_at,
    }


def _expired_callback_disposition(effect_steps: Optional[Dict[str, Any]], attempts: int) -> str:
    """Recover only a committed prefix whose remaining effects never started.

    The manifest is persisted before *any* callback effect may start. None
    means a worker died between acquiring its callback lease and persisting
    the manifest, so no downstream action could have been admitted.
    A strict done-prefix followed by pending steps has the same property for
    the suffix; the already acknowledged prefix must be skipped on recovery.
    A started/unknown or malformed manifest has an unverified side effect and
    is never replayable.
    """
    if effect_steps is None:
        return "requeue" if attempts < 3 else "unknown"
    if not isinstance(effect_steps, dict):
        return "unknown"
    order, states = effect_steps.get("order"), effect_steps.get("states")
    if (
        not isinstance(order, list)
        or not order
        or len(order) != len(set(str(step) for step in order))
        or any(not isinstance(step, str) or step not in _CALLBACK_EFFECTS for step in order)
        or not isinstance(states, dict)
        or set(states) != set(order)
    ):
        return "unknown"
    if all(states[step] == "done" for step in order):
        return "done"
    # A completed prefix and an untouched suffix can be resumed without
    # dispatching anything again that might already have been sent.
    if attempts < 3 and all(states[step] in {"done", "pending"} for step in order):
        values = [states[step] for step in order]
        if values == sorted(values, key={"done": 0, "pending": 1}.__getitem__):
            return "requeue"
    return "unknown"


class TerminalLifecycleStore(SupervisionStore):
    """Atomic terminal state with lease-fenced, auditable callback disposition."""

    @staticmethod
    def _completed_comparison_query(
        *,
        engagement_id: Optional[str] = None,
        target_task_id: Optional[str] = None,
        after: Optional[str] = None,
    ) -> Any:
        """Select paired PG terminal receipts with no recorded comparison.

        A callback's effect ledger can be DONE even when its peer was pending,
        and its peer's callback can become UNKNOWN. Neither is proof that the
        *remote execution* is unknown: the independent terminal attempts are.
        """
        parent = aliased(TaskORM, name="comparison_parent")
        source = aliased(TaskORM, name="comparison_source")
        target = aliased(TaskORM, name="comparison_target")
        source_callback = aliased(TerminalCallbackORM, name="comparison_source_callback")
        target_callback = aliased(TerminalCallbackORM, name="comparison_target_callback")
        now = datetime.utcnow()

        def settled(callback: Any) -> Any:
            return or_(
                callback.status.in_(("pending", "done", "unknown")),
                and_(callback.status == "leased", callback.leased_until <= now),
            )

        recorded = (
            select(ExecutionActionORM.id)
            .where(
                ExecutionActionORM.engagement_id == target.engagement_id,
                ExecutionActionORM.flow_id == target.flow_id,
                ExecutionActionORM.task_id == parent.id,
                ExecutionActionORM.tool_name == "signed_diff_auth_compare",
                ExecutionActionORM.safe_metadata["target_observation_task_id"].as_string()
                == target.id,
            )
            .exists()
        )
        statement = (
            select(target.engagement_id, target.id)
            .select_from(target)
            .join(
                parent,
                and_(
                    parent.id == target.parent_task_id,
                    parent.engagement_id == target.engagement_id,
                    parent.flow_id == target.flow_id,
                ),
            )
            .join(
                source,
                and_(
                    source.parent_task_id == parent.id,
                    source.engagement_id == target.engagement_id,
                    source.flow_id == target.flow_id,
                    source.id != target.id,
                ),
            )
            .join(
                source_callback,
                and_(
                    source_callback.task_id == source.id,
                    source_callback.engagement_id == source.engagement_id,
                ),
            )
            .join(
                target_callback,
                and_(
                    target_callback.task_id == target.id,
                    target_callback.engagement_id == target.engagement_id,
                ),
            )
            .where(
                parent.type == "replay_for_diff_auth",
                parent.status == "completed",
                source.type == "navigate",
                target.type == "navigate",
                source.status == "completed",
                target.status == "completed",
                source.payload["_comparison_role"].as_string() == "source",
                target.payload["_comparison_role"].as_string() == "target",
                source_callback.outcome == "succeeded",
                target_callback.outcome == "succeeded",
                settled(source_callback),
                settled(target_callback),
                ~recorded,
            )
            .distinct()
        )
        if engagement_id is not None:
            statement = statement.where(target.engagement_id == engagement_id)
        if target_task_id is not None:
            statement = statement.where(target.id == target_task_id)
        if after is not None:
            statement = statement.where(target.id > after)
        return statement.order_by(target.id)

    async def list_completed_comparison_pairs(
        self, *, limit: int = 12, after: Optional[str] = None
    ) -> List[Dict[str, str]]:
        """Bounded keyset scan; never fetch provider bodies or replay tasks."""
        if not 1 <= limit <= 25 or (
            after is not None
            and (not isinstance(after, str) or _REPLAY_TASK_ID.fullmatch(after) is None)
        ):
            raise ValueError("Invalid comparison recovery scan bounds")
        async with self._sessions() as db:
            rows = (
                await db.execute(self._completed_comparison_query(after=after).limit(limit))
            ).all()
        return [
            {"engagement_id": engagement_id, "terminal_task_id": task_id}
            for engagement_id, task_id in rows
        ]

    @asynccontextmanager
    async def claim_completed_comparison_pair(
        self, engagement_id: str, terminal_task_id: str
    ) -> AsyncIterator[bool]:
        """Hold one transaction-scoped PG advisory fence through comparison.

        Concurrent replacement workers cannot both perform the same scan
        effect. No task/callback rows are locked here: the comparator's own
        immutable action insertion locks parent, Flow and signed ROE rows.
        The fence releases on transaction close even if this worker dies.
        """
        if (
            not isinstance(engagement_id, str)
            or not 1 <= len(engagement_id) <= 64
            or not engagement_id.isascii()
            or not isinstance(terminal_task_id, str)
            or _REPLAY_TASK_ID.fullmatch(terminal_task_id) is None
        ):
            raise ValueError("Invalid signed comparison candidate identity")
        key = int.from_bytes(
            hashlib.sha256(
                ("signed-comparison:" + engagement_id + ":" + terminal_task_id).encode()
            ).digest()[:8],
            byteorder="big",
            signed=True,
        )
        async with self._sessions() as db:
            async with db.begin():
                claimed = (
                    await db.execute(
                        text("SELECT pg_try_advisory_xact_lock(:comparison_lock)"),
                        {"comparison_lock": key},
                    )
                ).scalar_one()
                if claimed is not True:
                    yield False
                    return
                ready = (
                    await db.execute(
                        self._completed_comparison_query(
                            engagement_id=engagement_id, target_task_id=terminal_task_id
                        ).limit(1)
                    )
                ).first()
                yield ready is not None

    async def commit_terminal(
        self,
        engagement_id: str,
        task_id: str,
        attempt_id: str,
        expected_revision: int,
        outcome: str,
        *,
        owner_id: Optional[str] = None,
        lease_id: Optional[str] = None,
        receipt_code: str = "model_completed",
        continuation: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        if outcome not in {"succeeded", "failed", "unknown"}:
            raise ValueError("Terminal outcome must be succeeded, failed or unknown")
        if (
            not isinstance(receipt_code, str)
            or not receipt_code.isascii()
            or len(receipt_code) > 64
        ):
            raise ValueError("Receipt code must be bounded")
        now = datetime.utcnow()
        async with self._sessions() as db:
            async with db.begin():
                engagement, task = await self._guard(
                    db, engagement_id, task_id, require_window=(outcome != "unknown")
                )
                if task.status not in {"running", "dispatching", "scheduled"}:
                    if task.status in {"completed", "failed"}:
                        prior = (
                            await db.execute(
                                select(TerminalCallbackORM).where(
                                    TerminalCallbackORM.engagement_id == engagement_id,
                                    TerminalCallbackORM.task_id == task_id,
                                )
                            )
                        ).scalar_one_or_none()
                        if (
                            prior
                            and prior.attempt_id == attempt_id
                            # Unknown terminal outcomes are not failed
                            # executions. Boolean success equivalence alone
                            # wrongly treated UNKNOWN as an idempotent FAILED
                            # callback on an already failed Task.
                            and prior.outcome == outcome
                            and ((task.status == "completed") == (outcome == "succeeded"))
                        ):
                            return {**_record(prior), "created": False}
                    return None
                attempt = (
                    await db.execute(
                        select(SupervisionAttemptORM)
                        .where(
                            SupervisionAttemptORM.id == attempt_id,
                            SupervisionAttemptORM.engagement_id == engagement_id,
                            SupervisionAttemptORM.task_id == task_id,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if (
                    attempt is None
                    or attempt.revision != expected_revision
                    or attempt.status != "running"
                ):
                    return None
                lease = (
                    await db.execute(
                        select(SupervisionExecutionLeaseORM)
                        .where(
                            SupervisionExecutionLeaseORM.task_id == task_id,
                            SupervisionExecutionLeaseORM.engagement_id == engagement_id,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if lease is not None:
                    if (
                        not owner_id
                        or not lease_id
                        or (
                            lease.owner_id != owner_id
                            or lease.lease_id != lease_id
                            or lease.state != "dispatched"
                            or lease.expires_at <= now
                        )
                    ):
                        raise SupervisionConflict("Current execution lease proof required")
                elif owner_id is not None or lease_id is not None:
                    raise SupervisionConflict("Supplied execution lease does not exist")
                if outcome != "unknown":
                    scope = ScopeDefinition(**engagement.scope)
                    # A signed target list can shrink after execution was
                    # scheduled. Refuse to finalize or schedule follow-up
                    # under an obsolete target scope.
                    try:
                        validate_payload_targets(ScopeEnforcer(scope), task.payload or {})
                    except (OutOfScopeError, ScopeValidationError, ValueError, TypeError) as exc:
                        raise SupervisionConflict(
                            "Current engagement targets do not authorize this task"
                        ) from exc
                    if task.approval_required or action_requires_approval(task.type, scope):
                        from ai_osop.safety.approval_binding import matches_pinned_payload

                        approval_id = (task.payload or {}).get("approval_id")
                        if not isinstance(approval_id, str) or not approval_id:
                            raise SupervisionConflict("Current signed task approval required")
                        approved = (
                            await db.execute(
                                select(ApprovalRequestORM).where(
                                    ApprovalRequestORM.id == approval_id,
                                    ApprovalRequestORM.engagement_id == engagement_id,
                                    ApprovalRequestORM.task_id == task_id,
                                    ApprovalRequestORM.status == "approved",
                                )
                            )
                        ).scalar_one_or_none()
                        if approved is None or (
                            task.type != "planner_inference"
                            and not matches_pinned_payload(approved.evidence, task.payload)
                        ):
                            raise SupervisionConflict(
                                "Current payload-bound task approval required"
                            )
                    if task.flow_id:
                        flow = (
                            await db.execute(
                                select(ExecutionFlowORM).where(
                                    ExecutionFlowORM.id == task.flow_id,
                                    ExecutionFlowORM.engagement_id == engagement_id,
                                )
                            )
                        ).scalar_one_or_none()
                        if flow is None or flow.status not in {"pending", "running"}:
                            raise SupervisionConflict("Flow is paused or unavailable")
                    latest = (
                        await db.execute(
                            select(SupervisionControlORM)
                            .where(
                                SupervisionControlORM.engagement_id == engagement_id,
                                SupervisionControlORM.task_id == task_id,
                                SupervisionControlORM.action.in_(
                                    ["pause", "resume", "cancel", "stop"]
                                ),
                            )
                            .order_by(
                                SupervisionControlORM.created_at.desc(),
                                SupervisionControlORM.request_id.desc(),
                            )
                            .limit(1)
                        )
                    ).scalar_one_or_none()
                    if latest and latest.action in {"pause", "cancel", "stop"}:
                        raise SupervisionConflict("Unresolved operator control prevents completion")
                attempt.status = outcome
                attempt.revision += 1
                attempt.updated_at = now
                attempt.receipt = {"result_code": receipt_code}
                task.status = (
                    "completed"
                    if outcome == "succeeded"
                    else "failed" if outcome == "failed" else "dispatch_unknown"
                )
                safe_continuation = (
                    _continuation_metadata(task.type, continuation)
                    if outcome == "succeeded"
                    else {}
                )
                # Never duplicate or expose arbitrary model results/raw errors
                # into broad task status reads or shared event streams.
                report_receipt = (
                    _signed_report_terminal_receipt(task, continuation)
                    if outcome == "succeeded"
                    else None
                )
                replay_receipt = (
                    _signed_replay_terminal_receipt(task, continuation)
                    if outcome == "succeeded"
                    else None
                )
                task.result = (
                    report_receipt
                    if report_receipt is not None
                    else (
                        replay_receipt
                        if replay_receipt is not None
                        else {"status": task.status, **safe_continuation}
                    )
                )
                task.completed_at = now
                if outcome == "unknown":
                    await self._append_event(
                        db,
                        engagement_id,
                        task_id,
                        "agent.terminal_unknown",
                        "orchestrator",
                        {"status": "dispatch_unknown", "attempt_id": attempt_id},
                        idempotency_key="terminal-unknown:" + attempt_id,
                    )
                    return {"created": True, "status": "dispatch_unknown", "callback": None}
                pending = TerminalCallbackORM(
                    id="cb-" + uuid.uuid4().hex,
                    engagement_id=engagement_id,
                    task_id=task_id,
                    attempt_id=attempt_id,
                    outcome=outcome,
                    status="pending",
                    receipt={
                        "attempt_id": attempt_id,
                        "result_code": receipt_code,
                        "continuation": safe_continuation,
                    },
                    attempts=0,
                )
                db.add(pending)
                await db.flush()
                await self._append_event(
                    db,
                    engagement_id,
                    task_id,
                    "task.completed" if outcome == "succeeded" else "task.failed",
                    "orchestrator",
                    {"status": task.status, "attempt_id": attempt_id},
                    idempotency_key="terminal:" + attempt_id,
                )
                return {**_record(pending), "created": True}

    @staticmethod
    async def _owned_callback(
        db: Any, callback_id: str, lease_id: str, worker_id: str
    ) -> Optional[TerminalCallbackORM]:
        """Lock the exact *unexpired* callback claim before any effect transition."""
        if not all(
            isinstance(value, str) and 0 < len(value) <= bound
            for value, bound in ((callback_id, 64), (lease_id, 64), (worker_id, 128))
        ):
            raise ValueError("Invalid callback ownership token")
        return (
            await db.execute(
                select(TerminalCallbackORM)
                .where(
                    TerminalCallbackORM.id == callback_id,
                    TerminalCallbackORM.lease_id == lease_id,
                    TerminalCallbackORM.worker_id == worker_id,
                    TerminalCallbackORM.status == "leased",
                    TerminalCallbackORM.leased_until > datetime.utcnow(),
                )
                .with_for_update()
            )
        ).scalar_one_or_none()

    async def plan_callback_effects(
        self, callback_id: str, lease_id: str, worker_id: str, steps: List[str]
    ) -> bool:
        """Persist the *entire* expected effect sequence before dispatch.

        A crashed worker must never be taken as having completed an omitted
        step. An existing manifest is immutable, including its order.
        """
        if (
            not isinstance(steps, list)
            or not steps
            or len(steps) != len(set(steps))
            or any(step not in _CALLBACK_EFFECTS for step in steps)
        ):
            raise ValueError("Callback effect plan is invalid")
        async with self._sessions() as db:
            async with db.begin():
                callback = await self._owned_callback(db, callback_id, lease_id, worker_id)
                if callback is None:
                    return False
                if callback.effect_steps is not None:
                    if callback.effect_steps.get("order") != steps:
                        raise SupervisionConflict("Callback effect plan changed after dispatch")
                    return True
                callback.effect_steps = {
                    "order": list(steps),
                    "states": {step: "pending" for step in steps},
                }
                return True

    async def start_callback_effect(
        self, callback_id: str, lease_id: str, worker_id: str, step: str
    ) -> bool:
        """Write-ahead intent: false means already acknowledged, never replay it."""
        if step not in _CALLBACK_EFFECTS:
            raise ValueError("Invalid callback effect")
        async with self._sessions() as db:
            async with db.begin():
                callback = await self._owned_callback(db, callback_id, lease_id, worker_id)
                if callback is None:
                    raise SupervisionConflict("Callback ownership lost before effect")
                plan = callback.effect_steps
                if not isinstance(plan, dict) or step not in plan.get("order", []):
                    raise SupervisionConflict("Callback effect has no durable intent")
                current = plan.get("states", {}).get(step)
                if current == "done":
                    return False
                if current != "pending":
                    raise SupervisionConflict("Callback effect has an uncertain prior dispatch")
                before = plan["order"][: plan["order"].index(step)]
                if any(plan["states"].get(previous) != "done" for previous in before):
                    raise SupervisionConflict("Previous callback effect is not acknowledged")
                updated = {"order": list(plan["order"]), "states": dict(plan["states"])}
                updated["states"][step] = "started"
                callback.effect_steps = updated
                callback.updated_at = datetime.utcnow()
                await self._append_event(
                    db,
                    callback.engagement_id,
                    callback.task_id,
                    "agent.callback_effect_started",
                    "orchestrator",
                    {"callback_id": callback.id, "step": step, "status": "started"},
                    idempotency_key="callback-effect-start:" + callback.id + ":" + step,
                )
                return True

    async def confirm_callback_effect(
        self, callback_id: str, lease_id: str, worker_id: str, step: str
    ) -> bool:
        """Record a returned callback operation, never an invented remote receipt."""
        if step not in _CALLBACK_EFFECTS:
            raise ValueError("Invalid callback effect")
        async with self._sessions() as db:
            async with db.begin():
                callback = await self._owned_callback(db, callback_id, lease_id, worker_id)
                if callback is None:
                    return False
                plan = callback.effect_steps
                if not isinstance(plan, dict) or plan.get("states", {}).get(step) != "started":
                    return False
                updated = {"order": list(plan["order"]), "states": dict(plan["states"])}
                updated["states"][step] = "done"
                callback.effect_steps = updated
                callback.updated_at = datetime.utcnow()
                await self._append_event(
                    db,
                    callback.engagement_id,
                    callback.task_id,
                    "agent.callback_effect_returned",
                    "orchestrator",
                    {"callback_id": callback.id, "step": step, "status": "done"},
                    idempotency_key="callback-effect-return:" + callback.id + ":" + step,
                )
                return True

    async def claim_callbacks(
        self, worker_id: str, *, limit: int = 20, lease_seconds: int = 30
    ) -> List[Dict[str, Any]]:
        """Claim new work; retry expired work only if no effect ever started.

        An immutable manifest with every step still pending is proof that
        this dispatcher never crossed its write-ahead side-effect boundary.
        Otherwise quarantine uncertain execution rather than replay it.
        """
        if (
            not worker_id
            or len(worker_id) > 128
            or not 1 <= limit <= 100
            or not 1 <= lease_seconds <= 3600
        ):
            raise ValueError("Invalid callback owner, size or lease")
        now = datetime.utcnow()
        result: List[Dict[str, Any]] = []
        async with self._sessions() as db:
            async with db.begin():
                expired = (
                    (
                        await db.execute(
                            select(TerminalCallbackORM)
                            .where(
                                TerminalCallbackORM.status == "leased",
                                TerminalCallbackORM.leased_until <= now,
                            )
                            .order_by(TerminalCallbackORM.created_at, TerminalCallbackORM.id)
                            .limit(min(100, max(limit * 4, limit)))
                            .with_for_update(skip_locked=True)
                        )
                    )
                    .scalars()
                    .all()
                )
                for stale in expired:
                    # Effect might have happened before owner crashed.
                    # If *every* step returned and was durably acknowledged,
                    # only the final callback ACK was lost. Recover that ACK
                    # without calling any downstream function again.
                    plan = stale.effect_steps
                    states = plan.get("states", {}) if isinstance(plan, dict) else {}
                    ordered = plan.get("order", []) if isinstance(plan, dict) else []
                    disposition = _expired_callback_disposition(plan, stale.attempts)
                    if disposition == "requeue":
                        # A missing plan proves no effects were admitted, and
                        # a done-prefix/pending-suffix proves the remaining
                        # effects were never admitted. Preserve the immutable
                        # manifest and its acknowledged checkpoint.
                        stale.status = "pending"
                        stale.worker_id = None
                        stale.lease_id = None
                        stale.leased_until = None
                        stale.updated_at = now
                        await self._append_event(
                            db,
                            stale.engagement_id,
                            stale.task_id,
                            "agent.callback_requeued",
                            "recovery",
                            {"status": "pending", "attempt_id": stale.attempt_id},
                            idempotency_key="callback-requeued:"
                            + stale.id
                            + ":"
                            + str(stale.attempts),
                        )
                        continue
                    stale.status = disposition
                    stale.completed_at = now if disposition == "done" else None
                    if (
                        disposition != "done"
                        and isinstance(ordered, list)
                        and isinstance(states, dict)
                    ):
                        patched = {"order": list(ordered), "states": dict(states)}
                        for step in ordered:
                            if patched["states"].get(step) == "started":
                                patched["states"][step] = "unknown"
                        stale.effect_steps = patched
                    stale.updated_at = now
                    await self._append_event(
                        db,
                        stale.engagement_id,
                        stale.task_id,
                        (
                            "agent.callback_done"
                            if disposition == "done"
                            else "agent.callback_unknown"
                        ),
                        "recovery",
                        {"status": stale.status, "attempt_id": stale.attempt_id},
                        idempotency_key="callback-" + stale.status + ":" + stale.id,
                    )
                pending = (
                    (
                        await db.execute(
                            select(TerminalCallbackORM)
                            .where(TerminalCallbackORM.status == "pending")
                            .order_by(TerminalCallbackORM.created_at, TerminalCallbackORM.id)
                            .limit(limit)
                            .with_for_update(skip_locked=True)
                        )
                    )
                    .scalars()
                    .all()
                )
                for item in pending:
                    item.status = "leased"
                    item.worker_id = worker_id
                    item.lease_id = "lease-" + uuid.uuid4().hex
                    item.leased_until = now + timedelta(seconds=lease_seconds)
                    item.attempts += 1
                    item.updated_at = now
                    result.append(_record(item))
        return result

    async def finish_callback(
        self,
        callback_id: str,
        lease_id: str,
        *,
        status: str = "done",
    ) -> bool:
        if status not in {"done", "unknown"}:
            raise ValueError("Cannot return callbacks to pending after possible side effects")
        now = datetime.utcnow()
        async with self._sessions() as db:
            async with db.begin():
                item = (
                    await db.execute(
                        select(TerminalCallbackORM)
                        .where(TerminalCallbackORM.id == callback_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if (
                    item is None
                    or item.status != "leased"
                    or item.lease_id != lease_id
                    or item.leased_until <= now
                ):
                    return False
                plan = item.effect_steps
                if status == "done" and (
                    not isinstance(plan, dict)
                    or not plan.get("order")
                    or any(plan.get("states", {}).get(step) != "done" for step in plan["order"])
                ):
                    # An ACK without independently committed step receipts
                    # would mask an incomplete downstream workflow.
                    return False
                if status == "unknown" and isinstance(plan, dict):
                    changed = {"order": list(plan["order"]), "states": dict(plan["states"])}
                    for step in changed["order"]:
                        if changed["states"].get(step) == "started":
                            changed["states"][step] = "unknown"
                    item.effect_steps = changed
                item.status = status
                item.completed_at = now if status == "done" else None
                item.updated_at = now
                await self._append_event(
                    db,
                    item.engagement_id,
                    item.task_id,
                    "agent.callback_" + status,
                    "orchestrator",
                    {"status": status, "attempt_id": item.attempt_id},
                    idempotency_key="callback-" + status + ":" + item.id,
                )
                return True

    async def renew_callback_lease(
        self, callback_id: str, lease_id: str, worker_id: str, *, lease_seconds: int = 30
    ) -> bool:
        """Renew only a still-valid, exact PostgreSQL callback owner.

        The worker must stop issuing new downstream effects as soon as this
        fence is lost; a stale callback may not reclaim ownership by renewal.
        """
        if (
            not all(
                isinstance(value, str) and 0 < len(value) <= limit
                for value, limit in ((callback_id, 64), (lease_id, 64), (worker_id, 128))
            )
            or not 1 <= lease_seconds <= 3600
        ):
            raise ValueError("Invalid callback lease token")
        now = datetime.utcnow()
        async with self._sessions() as db:
            async with db.begin():
                callback = (
                    await db.execute(
                        select(TerminalCallbackORM)
                        .where(
                            TerminalCallbackORM.id == callback_id,
                            TerminalCallbackORM.lease_id == lease_id,
                            TerminalCallbackORM.worker_id == worker_id,
                            TerminalCallbackORM.status == "leased",
                            TerminalCallbackORM.leased_until > now,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if callback is None:
                    return False
                callback.leased_until = now + timedelta(seconds=lease_seconds)
                callback.updated_at = now
                return True

    async def list_callbacks(
        self, engagement_id: str, task_id: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        stmt = select(TerminalCallbackORM).where(TerminalCallbackORM.engagement_id == engagement_id)
        if task_id:
            stmt = stmt.where(TerminalCallbackORM.task_id == task_id)
        async with self._sessions() as db:
            rows = (
                (
                    await db.execute(
                        stmt.order_by(TerminalCallbackORM.created_at.desc()).limit(
                            max(1, min(limit, 200))
                        )
                    )
                )
                .scalars()
                .all()
            )
        result = []
        for row in rows:
            public = _record(row)
            # Workflow continuation may contain a private local HAR locator.
            # It is essential for the internal callback worker but not for
            # the browser's callback-status inspection surface.
            public["receipt"] = {
                key: value
                for key, value in (row.receipt or {}).items()
                if key in {"attempt_id", "result_code"}
            }
            result.append(public)
        return result
