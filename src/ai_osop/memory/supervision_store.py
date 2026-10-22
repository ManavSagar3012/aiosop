"""Transactional PostgreSQL supervision state, redacted histories and outbox.

Every command and its event/outbox receipt share one database transaction.
The store never interprets a delivery acknowledgement as remote task termination.
"""

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import BigInteger, Column, DateTime, ForeignKey, Identity, Integer, String
from sqlalchemy import UniqueConstraint, Index, select, update, func, or_, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ai_osop.core.models import ScopeDefinition
from ai_osop.core.exceptions import OutOfScopeError, ScopeValidationError
from ai_osop.memory.session_memory import (
    Base,
    SessionMemory,
    SessionStateORM,
    TaskORM,
    ApprovalRequestORM,
)
from ai_osop.safety.scope import ScopeEnforcer


class SupervisionConflict(ValueError):
    """The requested mutation conflicts with committed state or authorization."""


class SupervisionEventORM(Base):
    __tablename__ = "supervision_events"
    sequence = Column(BigInteger, Identity(), primary_key=True)
    id = Column(String(64), nullable=False, unique=True)
    engagement_id = Column(String(64), ForeignKey("session_states.session_id"), nullable=False)
    task_id = Column(String(64), nullable=True)
    kind = Column(String(64), nullable=False)
    actor_id = Column(String(64), nullable=False)
    payload = Column(JSONB, nullable=False)
    idempotency_key = Column(String(128), nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    __table_args__ = (
        UniqueConstraint("engagement_id", "idempotency_key", name="uq_supervision_event_dedupe"),
        Index("ix_supervision_events_timeline", "engagement_id", "sequence"),
        Index("ix_supervision_events_task", "engagement_id", "task_id", "sequence"),
    )


class SupervisionMessageORM(Base):
    __tablename__ = "supervision_messages"
    id = Column(String(64), primary_key=True)
    engagement_id = Column(String(64), ForeignKey("session_states.session_id"), nullable=False)
    session_id = Column(String(64), nullable=False)
    task_id = Column(String(64), nullable=True)
    role = Column(String(24), nullable=False)
    actor_id = Column(String(64), nullable=False)
    content = Column(String(4096), nullable=False)
    idempotency_key = Column(String(128), nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    delivery_state = Column(String(24), nullable=False, default="queued", server_default="queued")
    inbox_consumer_id = Column(String(128), nullable=True)
    inbox_leased_until = Column(DateTime, nullable=True)
    delivery_attempts = Column(Integer, nullable=False, default=0, server_default="0")
    consumed_at = Column(DateTime, nullable=True)
    __table_args__ = (
        UniqueConstraint(
            "engagement_id", "session_id", "idempotency_key", name="uq_supervision_message_dedupe"
        ),
        Index("ix_supervision_messages_thread", "engagement_id", "session_id", "created_at"),
        Index(
            "ix_supervision_messages_inbox",
            "engagement_id",
            "task_id",
            "delivery_state",
            "inbox_leased_until",
        ),
    )


class SupervisionControlORM(Base):
    __tablename__ = "supervision_controls"
    request_id = Column(String(128), primary_key=True)
    engagement_id = Column(String(64), ForeignKey("session_states.session_id"), nullable=False)
    task_id = Column(String(64), nullable=False)
    action = Column(String(24), nullable=False)
    actor_id = Column(String(64), nullable=False)
    reason = Column(String(1024), nullable=False)
    status = Column(String(24), nullable=False, default="pending")
    receipt = Column(JSONB, nullable=True)
    revision = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now())
    __table_args__ = (
        Index("ix_supervision_controls_task", "engagement_id", "task_id", "created_at"),
    )


class SupervisionAttemptORM(Base):
    __tablename__ = "supervision_attempts"
    id = Column(String(64), primary_key=True)
    engagement_id = Column(String(64), ForeignKey("session_states.session_id"), nullable=False)
    task_id = Column(String(64), nullable=False)
    attempt = Column(Integer, nullable=False)
    status = Column(String(24), nullable=False)
    external_id = Column(String(128), nullable=True)
    receipt = Column(JSONB, nullable=True)
    revision = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now())
    __table_args__ = (
        UniqueConstraint(
            "engagement_id", "task_id", "attempt", name="uq_supervision_attempt_number"
        ),
        Index("ix_supervision_attempts_task", "engagement_id", "task_id", "attempt"),
    )


class SupervisionOutboxORM(Base):
    __tablename__ = "supervision_outbox"
    id = Column(String(64), primary_key=True)
    event_id = Column(String(64), ForeignKey("supervision_events.id"), nullable=False, unique=True)
    engagement_id = Column(String(64), nullable=False)
    topic = Column(String(64), nullable=False)
    payload = Column(JSONB, nullable=False)
    attempts = Column(Integer, nullable=False, default=0)
    lease_id = Column(String(64), nullable=True)
    leased_until = Column(DateTime, nullable=True)
    delivered_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    __table_args__ = (Index("ix_supervision_outbox_pending", "delivered_at", "leased_until"),)


class SupervisionExecutionLeaseORM(Base):
    __tablename__ = "supervision_execution_leases"
    task_id = Column(String(64), primary_key=True)
    engagement_id = Column(String(64), ForeignKey("session_states.session_id"), nullable=False)
    lease_id = Column(String(64), nullable=False)
    owner_id = Column(String(128), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    state = Column(String(24), nullable=False)
    revision = Column(Integer, nullable=False, default=0, server_default="0")
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now())
    __table_args__ = (
        Index("ix_supervision_execution_leases_owner", "engagement_id", "owner_id", "expires_at"),
    )


class SupervisionMCPDispatchORM(Base):
    """One durable dispatch identity per remote server/request ID across replicas."""
    __tablename__ = "supervision_mcp_dispatches"
    server_id = Column(String(128), primary_key=True)
    request_id = Column(String(128), primary_key=True)
    engagement_id = Column(String(64), ForeignKey("session_states.session_id"), nullable=False)
    task_id = Column(String(64), nullable=False)
    tool_name = Column(String(128), nullable=False)
    authorization_version = Column(Integer, nullable=False)
    status = Column(String(32), nullable=False)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now())
    __table_args__ = (
        Index("ix_supervision_mcp_dispatch_task", "engagement_id", "task_id", "created_at"),
    )


def _next_mcp_dispatch_status(current: str, kind: str, status: str) -> str:
    """Monotonic durable state, keeping remote cancellation single-attempt.

    A late execution_started or unsigned/unknown reconciliation after the
    *committed* cancellation intent must not resurrect an eligible claim for a
    second consequential stop. Only signed confirmed remote outcomes may
    replace a previous cancellation intent, and confirmation is not evidence
    of physical effects beyond the provider's signed assertion.
    """
    final = {"confirmed_stopped", "confirmed_finished"}
    if current in final:
        return current
    if kind in {"cancellation_result", "reconciliation_result"} and status in final:
        return status
    if current == "cancel_requested":
        return current
    if kind == "cancellation_requested":
        return "cancel_requested"
    if current == "provider_returned":
        return current
    if kind == "execution_finished" and status == "success":
        return "provider_returned"
    if current == "provider_running":
        return current
    if kind == "reconciliation_result" and status == "running":
        return "provider_running"
    if current == "outcome_unknown":
        return current
    if kind == "execution_started":
        return "started_unknown"
    return current


_SECRET_KEY = re.compile(
    r"password|secret|token|cookie|authorization|private.key|credential|api.key|raw|payload|argument|response|header",
    re.IGNORECASE,
)
_SECRET_TEXT = re.compile(
    r"(?i)(?:bearer\s+\S+|(?:api[_-]?key|password|token|secret)\s*[:=]\s*\S+)"
)
_SAFE_KEYS = frozenset(
    {
        "status",
        "outcome",
        "state",
        "source",
        "engine",
        "agent_id",
        "attempt_id",
        "flow_id",
        "task_id",
        "session_id",
        "receipt_id",
        "external_id",
        "error_code",
        "duration_ms",
        "revision",
        "step",
        "event",
        "action",
        "request_id",
        # Cryptographic receipt *metadata* only. The full provider signature,
        # tool arguments and response bodies must never enter the event bus.
        "provider_receipt_sha256",
        "provider_signing_kid",
        "provider_receipt_status",
        "result_code",
        "remote_stopped",
        "confirmed",
        "count",
        "reason",
        "execution_stopped",
        "receipts",
        "local_coroutine",
        "temporal",
        "mcp",
    }
)
_CONTROL_STATUSES = frozenset({"pending", "acknowledged", "unknown", "confirmed_stopped"})
_ATTEMPT_STATUSES = frozenset(
    {
        "queued",
        "running",
        "unknown",
        "succeeded",
        "failed",
        "cancelled",
        "confirmed_stopped",
    }
)
_CONTROL_ACTIONS = frozenset({"cancel", "stop", "pause", "resume", "reconcile"})


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


def _bounded(value: Any, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Nonempty text is required")
    return _SECRET_TEXT.sub("[redacted]", value.replace("\x00", "")[:limit])


def _identifier(value: Any, limit: int) -> str:
    """Never truncate or redact primary/deduplication keys into collisions."""
    if not isinstance(value, str) or not value.strip() or len(value) > limit or "\x00" in value:
        raise ValueError("Invalid or oversized identifier")
    return value


def _safe_payload(payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Retain only pre-approved scalar metadata; never persist tool arguments."""
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise ValueError("Event metadata must be an object")
    safe: Dict[str, Any] = {}
    for key, value in list(payload.items())[:40]:
        if key not in _SAFE_KEYS or _SECRET_KEY.search(key):
            continue
        if isinstance(value, bool) or isinstance(value, int) or value is None:
            safe[key] = value
        elif isinstance(value, str):
            safe[key] = _SECRET_TEXT.sub("[redacted]", value[:256])
        elif key == "receipts" and isinstance(value, dict):
            # Expose bounded provider status only; never persist raw MCP results.
            receipt_summary: Dict[str, Any] = {}
            for provider in ("local_coroutine", "temporal", "mcp"):
                provider_value = value.get(provider)
                if isinstance(provider_value, str):
                    receipt_summary[provider] = _SECRET_TEXT.sub("[redacted]", provider_value[:128])
                elif isinstance(provider_value, dict):
                    receipt_summary[provider] = {
                        item_key: _SECRET_TEXT.sub("[redacted]", item_value[:128])
                        for item_key, item_value in provider_value.items()
                        if item_key in {"status", "receipt_id", "source"}
                        and isinstance(item_value, str)
                    }
            safe[key] = receipt_summary
    if len(json.dumps(safe)) > 2048:
        raise ValueError("Event metadata exceeds limit")
    return safe


def _row(row: Any, fields: List[str]) -> Dict[str, Any]:
    return {field: getattr(row, field) for field in fields}


_EVENT_FIELDS = [
    "id",
    "sequence",
    "engagement_id",
    "task_id",
    "kind",
    "actor_id",
    "payload",
    "created_at",
]
_MESSAGE_FIELDS = [
    "id",
    "engagement_id",
    "session_id",
    "task_id",
    "role",
    "actor_id",
    "content",
    "created_at",
    "delivery_state",
    "delivery_attempts",
    "consumed_at",
]
_INBOX_FIELDS = _MESSAGE_FIELDS + ["inbox_consumer_id", "inbox_leased_until"]
_CONTROL_FIELDS = [
    "request_id",
    "engagement_id",
    "task_id",
    "action",
    "actor_id",
    "reason",
    "status",
    "receipt",
    "revision",
    "created_at",
    "updated_at",
]
_ATTEMPT_FIELDS = [
    "id",
    "engagement_id",
    "task_id",
    "attempt",
    "status",
    "external_id",
    "receipt",
    "revision",
    "created_at",
    "updated_at",
]
_LEASE_FIELDS = [
    "engagement_id",
    "task_id",
    "owner_id",
    "lease_id",
    "expires_at",
    "state",
    "revision",
]


class SupervisionStore:
    """Portable adapter over SessionMemory._async_session, with no Redis dependency."""

    def __init__(self, session_memory: SessionMemory):
        self.session_memory = session_memory

    def _sessions(self) -> Any:
        if self.session_memory._async_session is None:
            raise RuntimeError("Durable supervision requires connected PostgreSQL")
        return self.session_memory._async_session()

    async def assert_access(
        self,
        engagement_id: str,
        actor_id: str,
        actor_role: str,
        task_id: Optional[str] = None,
    ) -> None:
        """Re-check signed operator claims against authoritative persisted ownership."""
        if actor_role not in {"operator", "senior_operator"} or not actor_id:
            raise SupervisionConflict("An authenticated operator is required")
        async with self._sessions() as session:
            row = (
                await session.execute(
                    select(SessionStateORM).where(SessionStateORM.session_id == engagement_id)
                )
            ).scalar_one_or_none()
            if row is None:
                raise SupervisionConflict("Engagement not found")
            if actor_role != "senior_operator" and row.created_by != actor_id:
                raise SupervisionConflict("Operator does not own this engagement")
            if task_id is not None:
                task = (
                    await session.execute(
                        select(TaskORM.id).where(
                            TaskORM.id == task_id,
                            TaskORM.engagement_id == engagement_id,
                        )
                    )
                ).scalar_one_or_none()
                if task is None:
                    raise SupervisionConflict("Task does not belong to engagement")

    @staticmethod
    async def _guard(
        session: Any,
        engagement_id: str,
        task_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        actor_role: str = "system",
        require_window: bool = False,
        *, row_lock: bool = True,
    ) -> Any:
        # Mutating control/dispatch admission retains the exclusive PG guard.
        # Read-only signed receipt lookups must NOT acquire FOR UPDATE on a
        # second connection while a report release transaction already holds
        # the engagement row FOR SHARE: that waits on our own outer lock and
        # deadlocks the independently verified senior release call.
        engagement_query = select(SessionStateORM).where(
            SessionStateORM.session_id == engagement_id
        )
        if row_lock:
            engagement_query = engagement_query.with_for_update()
        result = await session.execute(
            engagement_query
        )
        engagement = result.scalar_one_or_none()
        if engagement is None:
            raise SupervisionConflict("Engagement does not exist in durable storage")
        if actor_role not in {"system", "senior_operator"} and (
            not actor_id or engagement.created_by != actor_id
        ):
            raise SupervisionConflict("Operator does not own this engagement")
        active_authorization = None
        if require_window:
            if engagement.phase in {"halted", "completed"}:
                raise SupervisionConflict("Engagement is closed")
            try:
                scope = ScopeDefinition(**engagement.scope)
                if (
                    scope.engagement_id != engagement_id
                    or not scope.authorization_ref
                    or not (scope.domains or scope.ips)
                ):
                    raise SupervisionConflict("Durable engagement lacks explicit authorized scope")
                ScopeEnforcer(scope).validate_time_window()
            except (OutOfScopeError, ScopeValidationError, TypeError, ValueError) as exc:
                raise SupervisionConflict(
                    "Engagement authorization or testing window is invalid"
                ) from exc
            # This happens while the engagement row is locked in the same
            # PostgreSQL transaction as the impending state transition.
            # A concurrently revoked policy must never admit work merely
            # because authorization_ref is nonempty.
            from ai_osop.memory.authorization_store import guard_sql
            from sqlalchemy.ext.asyncio import AsyncSession

            if isinstance(session, AsyncSession):
                try:
                    active_authorization = await guard_sql(session, engagement_id)
                except Exception as exc:
                    raise SupervisionConflict(
                        "Cryptographic engagement authorization is not active"
                    ) from exc
        if task_id is not None:
            task = (
                await session.execute(
                    select(TaskORM).where(
                        TaskORM.id == task_id, TaskORM.engagement_id == engagement_id
                    )
                )
            ).scalar_one_or_none()
            if task is None:
                raise SupervisionConflict("Task is not part of the engagement")
            if active_authorization is not None and (
                not isinstance(task.payload, dict)
                or type(task.payload.get("_authorization_version")) is not int
                or task.payload["_authorization_version"] != active_authorization.version
            ):
                raise SupervisionConflict(
                    "Task authorization version is missing or stale"
                )
            return engagement, task
        return engagement, None

    @staticmethod
    async def _append_event(
        session: Any,
        engagement_id: str,
        task_id: Optional[str],
        kind: str,
        actor_id: str,
        payload: Dict[str, Any],
        idempotency_key: Optional[str] = None,
    ) -> Any:
        # PostgreSQL sequences are allocated before transaction commit. Without
        # a per-engagement transactional lock, a later sequence could commit
        # first and make an SSE cursor skip the earlier, uncommitted event.
        # This lock orders commit visibility for every event producer.
        bind = getattr(session, "bind", None)
        if getattr(getattr(bind, "dialect", None), "name", None) == "postgresql":
            await session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:engagement_id, 8044))"),
                {"engagement_id": engagement_id},
            )
        if idempotency_key is not None:
            existing = (
                await session.execute(
                    select(SupervisionEventORM).where(
                        SupervisionEventORM.engagement_id == engagement_id,
                        SupervisionEventORM.idempotency_key == idempotency_key,
                    )
                )
            ).scalar_one_or_none()
            if existing is not None:
                if (existing.kind, existing.task_id, existing.actor_id, existing.payload) != (
                    kind,
                    task_id,
                    actor_id,
                    payload,
                ):
                    raise SupervisionConflict("Idempotency key was used for a different event")
                return existing
        event = SupervisionEventORM(
            id=_id("evt"),
            engagement_id=engagement_id,
            task_id=task_id,
            kind=kind,
            actor_id=actor_id,
            payload=payload,
            idempotency_key=idempotency_key,
        )
        session.add(event)
        await session.flush()
        session.add(
            SupervisionOutboxORM(
                id=_id("out"),
                event_id=event.id,
                engagement_id=engagement_id,
                topic=kind,
                payload={
                    "event_id": event.id,
                    "engagement_id": engagement_id,
                    "task_id": task_id,
                    "kind": kind,
                    "metadata": payload,
                },
            )
        )
        return event

    async def append_event(
        self,
        engagement_id: str,
        task_id: Optional[str] = None,
        kind: str = "agent.event",
        actor_id: str = "system",
        payload: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        kind = _identifier(kind, 64)
        actor_id = _identifier(actor_id, 64)
        if idempotency_key is not None:
            idempotency_key = _identifier(idempotency_key, 128)
        metadata = _safe_payload(payload)
        async with self._sessions() as session:
            async with session.begin():
                await self._guard(session, engagement_id, task_id)
                event = await self._append_event(
                    session, engagement_id, task_id, kind, actor_id, metadata, idempotency_key
                )
                result = _row(event, _EVENT_FIELDS)
        return result

    async def claim_mcp_dispatch(
        self,
        engagement_id: str,
        task_id: str,
        server_id: str,
        request_id: str,
        tool_name: str,
    ) -> bool:
        """Atomically reserve the global server/request pair BEFORE remote I/O.

        A second process may observe an accepted-but-unknown prior dispatch.
        It must not replay it, even if the first process died before sending.
        The signed task and event/outbox are committed in the same transaction.
        """
        server_id = _identifier(server_id, 128)
        request_id = _identifier(request_id, 128)
        tool_name = _identifier(tool_name, 128)
        async with self._sessions() as session:
            async with session.begin():
                _, task = await self._guard(
                    session, engagement_id, task_id, require_window=True
                )
                if task.status != "running":
                    raise SupervisionConflict("MCP dispatch requires a running signed task")
                version = task.payload["_authorization_version"]
                claimed = (
                    await session.execute(
                        pg_insert(SupervisionMCPDispatchORM)
                        .values(
                            server_id=server_id,
                            request_id=request_id,
                            engagement_id=engagement_id,
                            task_id=task_id,
                            tool_name=tool_name,
                            authorization_version=version,
                            status="accepted_unconfirmed",
                        )
                        .on_conflict_do_nothing(index_elements=["server_id", "request_id"])
                        .returning(SupervisionMCPDispatchORM.request_id)
                    )
                ).scalar_one_or_none()
                if claimed is None:
                    return False
                await self._append_event(
                    session, engagement_id, task_id, "agent.mcp.dispatch_accepted",
                    "mcp-registry",
                    {"request_id": request_id, "status": "accepted_unconfirmed"},
                    idempotency_key="mcp:" + hashlib.sha256(
                        (server_id + ":" + request_id + ":dispatch_accepted").encode()
                    ).hexdigest(),
                )
                return True

    async def record_mcp_dispatch_event(
        self,
        engagement_id: str,
        task_id: str,
        server_id: str,
        request_id: str,
        kind: str,
        status: str,
        attested_receipt: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Persist provider observation and outbox under original dispatch ID.

        Reconciliation receipts can arrive *after* authorization revocation;
        they record history without granting a new external action.
        """
        server_id = _identifier(server_id, 128)
        request_id = _identifier(request_id, 128)
        if kind not in {
            "execution_started", "execution_finished", "execution_failed",
            "execution_unknown", "cancellation_requested", "cancellation_result",
            "reconciliation_requested", "reconciliation_result",
        }:
            raise SupervisionConflict("Invalid remote execution event kind")
        # Remote providers are not trusted to inject raw error text into the
        # transactional event/outbox or bypass bounded status reporting.
        if status not in {
            "success", "error", "unknown", "timeout", "cancelled", "canceled",
            "accepted", "running", "pending", "confirmed_stopped",
            "confirmed_finished", "not_supported", "denied", "duplicate_request",
        }:
            status = "unknown"
        confirmed = {"confirmed_finished", "confirmed_stopped"}
        receipt_evidence: Dict[str, Any] = {}
        if status in confirmed:
            from ai_osop.core.config import settings
            from ai_osop.mcp.receipt_attestation import provider_receipt_is_signed

            proof_ok = provider_receipt_is_signed(
                attested_receipt, server_id, request_id, engagement_id, task_id,
            )
            # The *signed assertion* must itself say what the caller intends
            # to persist. A valid signed RUNNING receipt cannot be replayed as
            # CONFIRMED_STOPPED by a compromised intermediate transport.
            if proof_ok:
                signed_status = attested_receipt.get("status")
                proof_ok = (
                    attested_receipt.get("verified") is True
                    and (
                        (
                            status == "confirmed_stopped"
                            and signed_status in {
                                "cancelled", "canceled", "confirmed_stopped",
                            }
                            and attested_receipt.get("stopped") is True
                        )
                        or (
                            status == "confirmed_finished"
                            and signed_status in {
                                "finished", "completed", "succeeded", "failed",
                            }
                        )
                    )
                )
            if proof_ok:
                receipt_evidence = {
                    "provider_receipt_sha256": hashlib.sha256(
                        json.dumps(
                            attested_receipt, sort_keys=True,
                            separators=(",", ":"), ensure_ascii=False,
                            allow_nan=False,
                        ).encode("utf-8")
                    ).hexdigest(),
                    "provider_signing_kid": attested_receipt["attestation"]["kid"],
                    # A signed `failed`/`finished` assertion is not proof of
                    # success. Projections must distinguish signed outcomes.
                    "provider_receipt_status": attested_receipt["status"],
                }
            elif settings.environment.strip().lower() in {"production", "prod"}:
                # Do not trust a caller-supplied status or bool at the durable
                # PostgreSQL boundary. An unsigned observation stays UNKNOWN.
                status = "unknown"
        async with self._sessions() as session:
            async with session.begin():
                await self._guard(session, engagement_id, task_id)
                row = (
                    await session.execute(
                        select(SupervisionMCPDispatchORM).where(
                            SupervisionMCPDispatchORM.server_id == server_id,
                            SupervisionMCPDispatchORM.request_id == request_id,
                            SupervisionMCPDispatchORM.engagement_id == engagement_id,
                            SupervisionMCPDispatchORM.task_id == task_id,
                        ).with_for_update()
                    )
                ).scalar_one_or_none()
                if row is None:
                    return False
                observed = _next_mcp_dispatch_status(row.status, kind, status)
                if observed != row.status:
                    row.status = observed
                    row.updated_at = datetime.utcnow()
                await self._append_event(
                    session, engagement_id, task_id, "agent.mcp." + kind,
                    "mcp-registry",
                    {
                        "request_id": request_id, "status": status or "unknown",
                        **receipt_evidence,
                    },
                    idempotency_key="mcp:" + hashlib.sha256(
                        (server_id + ":" + request_id + ":" + kind + ":" + status).encode()
                    ).hexdigest(),
                )
                return True

    async def list_mcp_dispatches(
        self, engagement_id: str, task_id: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Read bounded non-sensitive persisted remote execution identities."""
        query = select(SupervisionMCPDispatchORM).where(
            SupervisionMCPDispatchORM.engagement_id == engagement_id
        )
        if task_id is not None:
            query = query.where(SupervisionMCPDispatchORM.task_id == task_id)
        async with self._sessions() as session:
            rows = (
                await session.execute(
                    query.order_by(SupervisionMCPDispatchORM.created_at.desc())
                    .limit(max(1, min(limit, 200)))
                )
            ).scalars().all()
        return [
            {
                "server_id": item.server_id,
                "request_id": item.request_id,
                "task_id": item.task_id,
                "tool_name": item.tool_name,
                "status": item.status,
                "authorization_version": item.authorization_version,
            }
            for item in rows
        ]

    async def get_mcp_dispatch(
        self,
        engagement_id: str,
        task_id: str,
        server_id: str,
        request_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Return only a previously committed, attributable remote request."""
        server_id = _identifier(server_id, 128)
        request_id = _identifier(request_id, 128)
        async with self._sessions() as session:
            await self._guard(session, engagement_id, task_id, row_lock=False)
            row = (
                await session.execute(
                    select(SupervisionMCPDispatchORM).where(
                        SupervisionMCPDispatchORM.engagement_id == engagement_id,
                        SupervisionMCPDispatchORM.task_id == task_id,
                        SupervisionMCPDispatchORM.server_id == server_id,
                        SupervisionMCPDispatchORM.request_id == request_id,
                    )
                )
            ).scalar_one_or_none()
        if row is None:
            return None
        return {
            "server_id": row.server_id,
            "request_id": row.request_id,
            "engagement_id": row.engagement_id,
            "task_id": row.task_id,
            "tool_name": row.tool_name,
            "status": row.status,
            "authorization_version": row.authorization_version,
        }

    async def claim_mcp_cancellation_once(
        self, engagement_id: str, task_id: str, server_id: str,
        request_id: str, *, actor_id: str, reason: str,
        expected_authorization_version: int,
    ) -> bool:
        """Admit one globally unique remote stop request before HTTP I/O.

        This is an idempotent *attempt*, not an assertion of termination.
        A crash after SQL commit leaves cancel_requested/UNKNOWN and forbids
        replaying a potentially delivered remote cancellation. It never
        reconstructs original tool arguments or launches the original tool.
        """
        server_id = _identifier(server_id, 128)
        request_id = _identifier(request_id, 128)
        actor_id = _identifier(actor_id, 64)
        if (
            type(expected_authorization_version) is not int
            or expected_authorization_version < 1
            or not isinstance(reason, str)
            or not 10 <= len(reason.strip()) <= 500
        ):
            raise SupervisionConflict("Signed MCP cancellation reason/version invalid")
        async with self._sessions() as session:
            async with session.begin():
                _, task = await self._guard(
                    session, engagement_id, task_id,
                    actor_id=actor_id, actor_role="senior_operator",
                )
                from ai_osop.memory.authorization_store import guard_sql
                from sqlalchemy.ext.asyncio import AsyncSession

                if isinstance(session, AsyncSession):
                    try:
                        await guard_sql(
                            session, engagement_id,
                            expected_version=expected_authorization_version,
                        )
                    except Exception as exc:
                        raise SupervisionConflict(
                            "Signed MCP cancellation authorization unavailable"
                        ) from exc
                if (
                    not isinstance(task.payload, dict)
                    or task.payload.get("_authorization_version")
                    != expected_authorization_version
                ):
                    raise SupervisionConflict("MCP cancellation Task signer changed")
                row = (
                    await session.execute(
                        select(SupervisionMCPDispatchORM).where(
                            SupervisionMCPDispatchORM.engagement_id == engagement_id,
                            SupervisionMCPDispatchORM.task_id == task_id,
                            SupervisionMCPDispatchORM.server_id == server_id,
                            SupervisionMCPDispatchORM.request_id == request_id,
                        ).with_for_update()
                    )
                ).scalar_one_or_none()
                if row is None or row.authorization_version != expected_authorization_version:
                    raise SupervisionConflict("Original signed MCP dispatch unavailable")
                if row.status not in {
                    "accepted_unconfirmed", "started_unknown", "outcome_unknown",
                    "provider_returned", "provider_running",
                }:
                    return False
                row.status = "cancel_requested"
                row.updated_at = datetime.utcnow()
                await self._append_event(
                    session, engagement_id, task_id,
                    "agent.mcp.persisted_cancellation_requested",
                    actor_id,
                    {
                        "request_id": request_id,
                        "status": "cancel_requested",
                        "reason": _bounded(reason.strip(), 500),
                    },
                    idempotency_key="mcp-persisted-stop:" + hashlib.sha256(
                        (server_id + ":" + request_id).encode()
                    ).hexdigest(),
                )
                return True

    async def list_events(
        self,
        engagement_id: str,
        task_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        stmt = select(SupervisionEventORM).where(SupervisionEventORM.engagement_id == engagement_id)
        if task_id is not None:
            stmt = stmt.where(SupervisionEventORM.task_id == task_id)
        async with self._sessions() as session:
            rows = (
                (
                    await session.execute(
                        stmt.order_by(SupervisionEventORM.sequence.desc()).limit(
                            max(1, min(limit, 200))
                        )
                    )
                )
                .scalars()
                .all()
            )
        return [_row(item, _EVENT_FIELDS) for item in reversed(rows)]

    async def list_events_after(
        self,
        engagement_id: str,
        after_sequence: int = 0,
        task_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Retrieve committed timeline rows strictly after an SSE cursor."""
        if after_sequence < 0:
            raise ValueError("Cursor must be nonnegative")
        stmt = select(SupervisionEventORM).where(
            SupervisionEventORM.engagement_id == engagement_id,
            SupervisionEventORM.sequence > after_sequence,
        )
        if task_id is not None:
            stmt = stmt.where(SupervisionEventORM.task_id == task_id)
        async with self._sessions() as session:
            rows = (
                (
                    await session.execute(
                        stmt.order_by(SupervisionEventORM.sequence.asc()).limit(
                            max(1, min(limit, 200))
                        )
                    )
                )
                .scalars()
                .all()
            )
        return [_row(row, _EVENT_FIELDS) for row in rows]

    async def list_tasks(
        self,
        engagement_id: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Discover persisted tasks across API/Temporal replicas without payloads."""
        async with self._sessions() as session:
            rows = (
                (
                    await session.execute(
                        select(TaskORM)
                        .where(TaskORM.engagement_id == engagement_id)
                        .order_by(TaskORM.created_at.desc(), TaskORM.id.desc())
                        .limit(max(1, min(limit, 200)))
                    )
                )
                .scalars()
                .all()
            )
        return [
            {
                "task_id": row.id,
                "task_type": row.type,
                "status": row.status,
                "retry_count": row.retry_count,
                "max_retries": row.max_retries,
                "assigned_agent_id": row.assigned_agent_id,
            }
            for row in rows
        ]

    async def append_message(
        self,
        engagement_id: str,
        session_id: str,
        task_id: Optional[str],
        role: str,
        actor_id: str,
        content: str,
        idempotency_key: Optional[str] = None,
        actor_role: str = "system",
    ) -> Dict[str, Any]:
        if role not in {"operator", "assistant", "agent", "system", "tool"}:
            raise ValueError("Unknown message role")
        session_id = _identifier(session_id, 64)
        actor_id = _identifier(actor_id, 64)
        content = _bounded(content, 4096)
        if idempotency_key is not None:
            idempotency_key = _identifier(idempotency_key, 128)
        async with self._sessions() as session:
            async with session.begin():
                await self._guard(
                    session,
                    engagement_id,
                    task_id,
                    actor_id,
                    actor_role,
                    require_window=(role == "operator"),
                )
                existing = None
                if idempotency_key is not None:
                    existing = (
                        await session.execute(
                            select(SupervisionMessageORM).where(
                                SupervisionMessageORM.engagement_id == engagement_id,
                                SupervisionMessageORM.session_id == session_id,
                                SupervisionMessageORM.idempotency_key == idempotency_key,
                            )
                        )
                    ).scalar_one_or_none()
                if existing is not None:
                    if (existing.task_id, existing.role, existing.actor_id, existing.content) != (
                        task_id,
                        role,
                        actor_id,
                        content,
                    ):
                        raise SupervisionConflict("Idempotency key was used for different input")
                    row = existing
                else:
                    row = SupervisionMessageORM(
                        id=_id("msg"),
                        engagement_id=engagement_id,
                        session_id=session_id,
                        task_id=task_id,
                        role=role,
                        actor_id=actor_id,
                        content=content,
                        idempotency_key=idempotency_key,
                        delivery_state="queued" if role == "operator" else "not_applicable",
                        delivery_attempts=0,
                    )
                    session.add(row)
                    await session.flush()
                    await self._append_event(
                        session,
                        engagement_id,
                        task_id,
                        "agent.message",
                        actor_id,
                        {"session_id": session_id, "event": role},
                    )
                result = _row(row, _MESSAGE_FIELDS)
        return result

    async def list_messages(
        self,
        engagement_id: str,
        session_id: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        async with self._sessions() as session:
            rows = (
                (
                    await session.execute(
                        select(SupervisionMessageORM)
                        .where(
                            SupervisionMessageORM.engagement_id == engagement_id,
                            SupervisionMessageORM.session_id == session_id,
                        )
                        .order_by(
                            SupervisionMessageORM.created_at.desc(), SupervisionMessageORM.id.desc()
                        )
                        .limit(max(1, min(limit, 200)))
                    )
                )
                .scalars()
                .all()
            )
        return [_row(item, _MESSAGE_FIELDS) for item in reversed(rows)]

    async def claim_inbox(
        self,
        engagement_id: str,
        task_id: str,
        consumer_id: str,
        lease_seconds: int = 30,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Atomically reserve undelivered operator guidance for a model boundary.

        Bus/outbox delivery is unrelated to model consumption. Expired claims
        become eligible for at-least-once redelivery, including after a crash.
        """
        consumer_id = _identifier(consumer_id, 128)
        if not 1 <= lease_seconds <= 3600 or not 1 <= limit <= 100:
            raise ValueError("Invalid inbox lease or batch limit")
        now = datetime.utcnow()
        claimed: List[Dict[str, Any]] = []
        async with self._sessions() as session:
            async with session.begin():
                await self._guard(session, engagement_id, task_id, require_window=True)
                rows = (
                    (
                        await session.execute(
                            select(SupervisionMessageORM)
                            .where(
                                SupervisionMessageORM.engagement_id == engagement_id,
                                SupervisionMessageORM.task_id == task_id,
                                SupervisionMessageORM.role == "operator",
                                SupervisionMessageORM.delivery_state.in_(["queued", "leased"]),
                                or_(
                                    SupervisionMessageORM.delivery_state == "queued",
                                    SupervisionMessageORM.inbox_leased_until < now,
                                ),
                            )
                            .order_by(
                                SupervisionMessageORM.created_at,
                                SupervisionMessageORM.id,
                            )
                            .with_for_update(skip_locked=True)
                            .limit(limit)
                        )
                    )
                    .scalars()
                    .all()
                )
                for row in rows:
                    row.delivery_state = "leased"
                    row.inbox_consumer_id = consumer_id
                    row.inbox_leased_until = now + timedelta(seconds=lease_seconds)
                    row.delivery_attempts += 1
                    claimed.append(_row(row, _INBOX_FIELDS))
        return claimed

    async def ack_inbox(
        self,
        message_id: str,
        consumer_id: str,
        ack_status: str = "consumed",
    ) -> Optional[Dict[str, Any]]:
        """Record model-boundary consumption under the active unexpired lease."""
        message_id = _identifier(message_id, 64)
        consumer_id = _identifier(consumer_id, 128)
        if ack_status != "consumed":
            raise ValueError("Only model-confirmed consumption can acknowledge inbox messages")
        now = datetime.utcnow()
        async with self._sessions() as session:
            async with session.begin():
                location = (
                    await session.execute(
                        select(
                            SupervisionMessageORM.engagement_id,
                            SupervisionMessageORM.task_id,
                        ).where(SupervisionMessageORM.id == message_id)
                    )
                ).one_or_none()
                if location is None or location.task_id is None:
                    return None
                # Match claim_inbox lock order: engagement then message.
                # Avoid deadlocks when consumers race on the same inbox.
                await self._guard(session, location.engagement_id, location.task_id)
                row = (
                    await session.execute(
                        select(SupervisionMessageORM)
                        .where(SupervisionMessageORM.id == message_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if row is None or row.role != "operator":
                    return None
                if row.engagement_id != location.engagement_id or row.task_id != location.task_id:
                    return None
                if row.inbox_consumer_id != consumer_id:
                    return None
                if row.delivery_state == "consumed":
                    return _row(row, _MESSAGE_FIELDS)
                if (
                    row.delivery_state != "leased"
                    or row.inbox_leased_until is None
                    or row.inbox_leased_until <= now
                ):
                    return None
                row.delivery_state = "consumed"
                row.consumed_at = now
                row.inbox_leased_until = None
                await self._append_event(
                    session,
                    row.engagement_id,
                    row.task_id,
                    "agent.message.consumed",
                    consumer_id[:64],
                    {"session_id": row.session_id, "event": "model_input_consumed"},
                    idempotency_key="consumed:" + row.id,
                )
                result = _row(row, _MESSAGE_FIELDS)
        return result

    async def request_control(
        self,
        engagement_id: str,
        task_id: str,
        action: str,
        actor_id: str,
        reason: str,
        request_id: str,
        actor_role: str = "operator",
    ) -> Dict[str, Any]:
        if action not in _CONTROL_ACTIONS:
            raise ValueError("Unknown control action")
        actor_id = _identifier(actor_id, 64)
        reason = _bounded(reason, 1024)
        request_id = _identifier(request_id, 128)
        async with self._sessions() as session:
            async with session.begin():
                _, task = await self._guard(
                    session,
                    engagement_id,
                    task_id,
                    actor_id,
                    actor_role,
                    require_window=(action == "resume"),
                )
                if action == "reconcile" and task.status in {"completed", "failed", "cancelled"}:
                    raise SupervisionConflict("Terminal tasks cannot be reconciled as running")
                if action == "resume":
                    if task.status in {"completed", "failed", "cancelled", "dispatch_unknown"}:
                        raise SupervisionConflict("Cannot resume a closed or uncertain task")
                    unresolved = (
                        await session.execute(
                            select(SupervisionControlORM.request_id)
                            .where(
                                SupervisionControlORM.engagement_id == engagement_id,
                                SupervisionControlORM.task_id == task_id,
                                SupervisionControlORM.status.in_(["pending", "unknown"]),
                            )
                            .limit(1)
                        )
                    ).scalar_one_or_none()
                    uncertain_attempt = (
                        await session.execute(
                            select(SupervisionAttemptORM.id)
                            .where(
                                SupervisionAttemptORM.engagement_id == engagement_id,
                                SupervisionAttemptORM.task_id == task_id,
                                SupervisionAttemptORM.status == "unknown",
                            )
                            .limit(1)
                        )
                    ).scalar_one_or_none()
                    if unresolved is not None or uncertain_attempt is not None:
                        raise SupervisionConflict(
                            "Cannot resume while execution outcome is unknown"
                        )
                existing = (
                    await session.execute(
                        select(SupervisionControlORM).where(
                            SupervisionControlORM.request_id == request_id
                        )
                    )
                ).scalar_one_or_none()
                if existing is not None:
                    if (
                        existing.engagement_id,
                        existing.task_id,
                        existing.action,
                        existing.actor_id,
                        existing.reason,
                    ) != (engagement_id, task_id, action, actor_id, reason):
                        raise SupervisionConflict("Idempotency key was used for another command")
                    row = existing
                else:
                    row = SupervisionControlORM(
                        request_id=request_id,
                        engagement_id=engagement_id,
                        task_id=task_id,
                        action=action,
                        actor_id=actor_id,
                        reason=reason,
                        status="pending",
                        revision=0,
                    )
                    session.add(row)
                    await session.flush()
                    await self._append_event(
                        session,
                        engagement_id,
                        task_id,
                        "agent.control.requested",
                        actor_id,
                        {"action": action, "request_id": request_id},
                    )
                result = _row(row, _CONTROL_FIELDS)
        return result

    async def get_control(
        self,
        task_id: str,
        engagement_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        stmt = select(SupervisionControlORM).where(SupervisionControlORM.task_id == task_id)
        if engagement_id is not None:
            stmt = stmt.where(SupervisionControlORM.engagement_id == engagement_id)
        async with self._sessions() as session:
            row = (
                await session.execute(
                    stmt.order_by(
                        SupervisionControlORM.created_at.desc(),
                        SupervisionControlORM.request_id.desc(),
                    ).limit(1)
                )
            ).scalar_one_or_none()
        return _row(row, _CONTROL_FIELDS) if row else None

    async def load_control(self, request_id: str) -> Optional[Dict[str, Any]]:
        async with self._sessions() as session:
            row = (
                await session.execute(
                    select(SupervisionControlORM).where(
                        SupervisionControlORM.request_id == request_id
                    )
                )
            ).scalar_one_or_none()
        return _row(row, _CONTROL_FIELDS) if row else None

    async def list_controls(
        self,
        engagement_id: str,
        task_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        stmt = select(SupervisionControlORM).where(
            SupervisionControlORM.engagement_id == engagement_id
        )
        if task_id is not None:
            stmt = stmt.where(SupervisionControlORM.task_id == task_id)
        async with self._sessions() as session:
            rows = (
                (
                    await session.execute(
                        stmt.order_by(
                            SupervisionControlORM.created_at.desc(),
                            SupervisionControlORM.request_id.desc(),
                        ).limit(max(1, min(limit, 200)))
                    )
                )
                .scalars()
                .all()
            )
        return [_row(row, _CONTROL_FIELDS) for row in rows]

    async def resolve_control(
        self,
        request_id: str,
        outcome: str,
        receipt: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        if outcome not in _CONTROL_STATUSES:
            raise ValueError("Unknown control outcome")
        clean_receipt = _safe_payload(receipt)
        if outcome == "confirmed_stopped" and not (
            clean_receipt.get("remote_stopped") is True and clean_receipt.get("receipt_id")
        ):
            raise SupervisionConflict("Remote stop requires a verifiable stop receipt")
        async with self._sessions() as session:
            async with session.begin():
                row = (
                    await session.execute(
                        select(SupervisionControlORM)
                        .where(SupervisionControlORM.request_id == request_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if row is None:
                    return None
                if row.status == "confirmed_stopped" and outcome != row.status:
                    raise SupervisionConflict("A confirmed stop cannot be overwritten")
                if row.status != outcome or (row.receipt or {}) != clean_receipt:
                    previous_revision = row.revision
                    changed = await session.execute(
                        update(SupervisionControlORM)
                        .where(
                            SupervisionControlORM.request_id == request_id,
                            SupervisionControlORM.revision == previous_revision,
                        )
                        .values(
                            status=outcome,
                            receipt=clean_receipt,
                            revision=previous_revision + 1,
                            updated_at=datetime.utcnow(),
                        )
                    )
                    if changed.rowcount != 1:
                        raise SupervisionConflict("Control changed concurrently")
                    await self._append_event(
                        session,
                        row.engagement_id,
                        row.task_id,
                        "agent.control.resolved",
                        "system",
                        {"action": row.action, "status": outcome, "request_id": request_id},
                    )
                    await session.refresh(row)
                result = _row(row, _CONTROL_FIELDS)
        return result

    async def claim_execution_lease(
        self,
        engagement_id: str,
        task_id: str,
        owner_id: str,
        ttl_seconds: int = 30,
    ) -> Dict[str, Any]:
        """Fence new work; permit bounded retries only with verified closure.

        Expired reservations with unknown external outcomes remain ineligible.
        Retry ownership requires each prior attempt's positive remote-stop
        receipt, a durable failed status, and an incremented bounded retry.
        """
        owner_id = _identifier(owner_id, 128)
        if not 1 <= ttl_seconds <= 3600:
            raise ValueError("Execution TTL outside supported range")
        now = datetime.utcnow()
        async with self._sessions() as session:
            async with session.begin():
                _, task = await self._guard(session, engagement_id, task_id, require_window=True)
                if task.status in {
                    "completed",
                    "failed",
                    "cancelled",
                    "halted",
                    "dispatch_unknown",
                }:
                    return {"acquired": False, "reason": "task_closed"}
                row = (
                    await session.execute(
                        select(SupervisionExecutionLeaseORM)
                        .where(
                            SupervisionExecutionLeaseORM.task_id == task_id,
                            SupervisionExecutionLeaseORM.engagement_id == engagement_id,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                attempts = (
                    (
                        await session.execute(
                            select(SupervisionAttemptORM)
                            .where(
                                SupervisionAttemptORM.engagement_id == engagement_id,
                                SupervisionAttemptORM.task_id == task_id,
                            )
                            .order_by(SupervisionAttemptORM.attempt)
                        )
                    )
                    .scalars()
                    .all()
                )
                if attempts:
                    next_number = (task.retry_count or 0) + 1
                    verified_closed = all(
                        attempt.status == "failed"
                        and isinstance(attempt.receipt, dict)
                        and attempt.receipt.get("remote_stopped") is True
                        and isinstance(attempt.receipt.get("receipt_id"), str)
                        and bool(attempt.receipt["receipt_id"])
                        for attempt in attempts
                    )
                    within_budget = (
                        isinstance(task.max_retries, int)
                        and 0 <= (task.retry_count or 0) < task.max_retries
                        and next_number > max(attempt.attempt for attempt in attempts)
                    )
                    released_or_proven_expired = row is not None and (
                        row.state == "released" or row.expires_at <= now
                    )
                    if not (verified_closed and within_budget and released_or_proven_expired):
                        return {"acquired": False, "reason": "attempt_exists_unreconciled"}
                if row is not None:
                    if row.state != "released" and not (attempts and row.expires_at <= now):
                        if row.expires_at <= now and row.state != "unknown":
                            row.state = "unknown"
                            row.revision += 1
                            row.updated_at = now
                        return {"acquired": False, "reason": "prior_lease_unreconciled"}
                    row.lease_id = _id("lease")
                    row.owner_id = owner_id
                    row.expires_at = now + timedelta(seconds=ttl_seconds)
                    row.state = "reserved"
                    row.revision += 1
                    row.updated_at = now
                else:
                    row = SupervisionExecutionLeaseORM(
                        engagement_id=engagement_id,
                        task_id=task_id,
                        lease_id=_id("lease"),
                        owner_id=owner_id,
                        expires_at=now + timedelta(seconds=ttl_seconds),
                        state="reserved",
                        revision=0,
                    )
                    session.add(row)
                    await session.flush()
                result = {"acquired": True, **_row(row, _LEASE_FIELDS)}
        return result

    async def check_execution_lease(
        self, engagement_id: str, task_id: str, owner_id: str, lease_id: str
    ) -> bool:
        owner_id = _identifier(owner_id, 128)
        lease_id = _identifier(lease_id, 64)
        async with self._sessions() as session:
            row = (
                await session.execute(
                    select(SupervisionExecutionLeaseORM.task_id).where(
                        SupervisionExecutionLeaseORM.engagement_id == engagement_id,
                        SupervisionExecutionLeaseORM.task_id == task_id,
                        SupervisionExecutionLeaseORM.owner_id == owner_id,
                        SupervisionExecutionLeaseORM.lease_id == lease_id,
                        SupervisionExecutionLeaseORM.state.in_(["reserved", "dispatched"]),
                        SupervisionExecutionLeaseORM.expires_at > datetime.utcnow(),
                    )
                )
            ).scalar_one_or_none()
        return row is not None

    async def renew_execution_lease(
        self,
        engagement_id: str,
        task_id: str,
        owner_id: str,
        lease_id: str,
        ttl_seconds: int = 30,
    ) -> Optional[Dict[str, Any]]:
        owner_id = _identifier(owner_id, 128)
        lease_id = _identifier(lease_id, 64)
        if not 1 <= ttl_seconds <= 3600:
            raise ValueError("Execution TTL outside supported range")
        now = datetime.utcnow()
        async with self._sessions() as session:
            async with session.begin():
                await self._guard(session, engagement_id, task_id, require_window=True)
                updated = await session.execute(
                    update(SupervisionExecutionLeaseORM)
                    .where(
                        SupervisionExecutionLeaseORM.engagement_id == engagement_id,
                        SupervisionExecutionLeaseORM.task_id == task_id,
                        SupervisionExecutionLeaseORM.owner_id == owner_id,
                        SupervisionExecutionLeaseORM.lease_id == lease_id,
                        SupervisionExecutionLeaseORM.state.in_(["reserved", "dispatched"]),
                        SupervisionExecutionLeaseORM.expires_at > now,
                    )
                    .values(
                        expires_at=now + timedelta(seconds=ttl_seconds),
                        revision=SupervisionExecutionLeaseORM.revision + 1,
                        updated_at=now,
                    )
                    .returning(SupervisionExecutionLeaseORM)
                )
                row = updated.scalar_one_or_none()
                result = _row(row, _LEASE_FIELDS) if row is not None else None
        return result

    async def mark_execution_dispatched(
        self,
        engagement_id: str,
        task_id: str,
        owner_id: str,
        lease_id: str,
    ) -> bool:
        """The holder records dispatch before sending work to a remote worker."""
        owner_id = _identifier(owner_id, 128)
        lease_id = _identifier(lease_id, 64)
        now = datetime.utcnow()
        async with self._sessions() as session:
            async with session.begin():
                await self._guard(session, engagement_id, task_id, require_window=True)
                changed = await session.execute(
                    update(SupervisionExecutionLeaseORM)
                    .where(
                        SupervisionExecutionLeaseORM.engagement_id == engagement_id,
                        SupervisionExecutionLeaseORM.task_id == task_id,
                        SupervisionExecutionLeaseORM.owner_id == owner_id,
                        SupervisionExecutionLeaseORM.lease_id == lease_id,
                        SupervisionExecutionLeaseORM.state == "reserved",
                        SupervisionExecutionLeaseORM.expires_at > now,
                    )
                    .values(
                        state="dispatched",
                        revision=SupervisionExecutionLeaseORM.revision + 1,
                        updated_at=now,
                    )
                )
                marked = changed.rowcount == 1
        return marked

    async def release_execution_lease(
        self,
        engagement_id: str,
        task_id: str,
        owner_id: str,
        lease_id: str,
    ) -> bool:
        owner_id = _identifier(owner_id, 128)
        lease_id = _identifier(lease_id, 64)
        now = datetime.utcnow()
        async with self._sessions() as session:
            async with session.begin():
                await self._guard(session, engagement_id, task_id)
                row = (
                    await session.execute(
                        select(SupervisionExecutionLeaseORM)
                        .where(
                            SupervisionExecutionLeaseORM.engagement_id == engagement_id,
                            SupervisionExecutionLeaseORM.task_id == task_id,
                            SupervisionExecutionLeaseORM.owner_id == owner_id,
                            SupervisionExecutionLeaseORM.lease_id == lease_id,
                            SupervisionExecutionLeaseORM.state.in_(["reserved", "dispatched"]),
                            SupervisionExecutionLeaseORM.expires_at > now,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if row is None:
                    return False
                if row.state == "dispatched":
                    attempted = (
                        await session.execute(
                            select(SupervisionAttemptORM.id)
                            .where(
                                SupervisionAttemptORM.engagement_id == engagement_id,
                                SupervisionAttemptORM.task_id == task_id,
                            )
                            .limit(1)
                        )
                    ).scalar_one_or_none()
                    if attempted is None:
                        # Dispatch could have escaped into an external
                        # provider before attempt persistence; poison the lease
                        # instead of making the task claimable by another owner.
                        row.state = "unknown"
                        row.revision += 1
                        row.updated_at = now
                        return False
                row.state = "released"
                row.revision += 1
                row.updated_at = now
        return True

    async def start_attempt(
        self,
        engagement_id: str,
        task_id: str,
        attempt: int,
        status: str = "queued",
        external_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if attempt < 1 or status not in {"queued", "running", "unknown"}:
            raise ValueError("Invalid initial attempt")
        if external_id is not None:
            external_id = _identifier(external_id, 128)
        async with self._sessions() as session:
            async with session.begin():
                engagement, task = await self._guard(
                    session, engagement_id, task_id, require_window=True
                )
                if task.status in {
                    "completed",
                    "failed",
                    "cancelled",
                    "halted",
                    "dispatch_unknown",
                }:
                    raise SupervisionConflict("Cannot create an attempt for a closed task")
                if task.approval_required:
                    from ai_osop.safety.approval_binding import matches_pinned_payload
                    approval_id = (
                        (task.payload or {}).get("approval_id")
                        if isinstance(task.payload, dict)
                        else None
                    )
                    if not isinstance(approval_id, str) or not (task.payload or {}).get(
                        "operator_approved"
                    ):
                        raise SupervisionConflict("Task has no current persisted approval grant")
                    approval = (
                        await session.execute(
                            select(ApprovalRequestORM)
                            .where(
                                ApprovalRequestORM.id == approval_id,
                                ApprovalRequestORM.task_id == task_id,
                                ApprovalRequestORM.engagement_id == engagement_id,
                                ApprovalRequestORM.status == "approved",
                            )
                            .limit(1)
                        )
                    ).scalar_one_or_none()
                    if approval is None or (
                        task.type != "planner_inference"
                        and not matches_pinned_payload(approval.evidence, task.payload)
                    ):
                        raise SupervisionConflict("Task requires a current payload-bound approved request")
                row = (
                    await session.execute(
                        select(SupervisionAttemptORM).where(
                            SupervisionAttemptORM.engagement_id == engagement_id,
                            SupervisionAttemptORM.task_id == task_id,
                            SupervisionAttemptORM.attempt == attempt,
                        )
                    )
                ).scalar_one_or_none()
                created = row is None
                # Engagement row is locked for this transaction. Counting
                # already committed attempts under that lock gives a
                # cross-replica atomic execution budget, independent of
                # per-tool Redis quotas. Replayed same attempts do not debit.
                roe = engagement.roe or {}
                budget_raw = roe.get("execution_attempt_budget_total")
                if created and budget_raw is not None:
                    if (
                        isinstance(budget_raw, bool)
                        or not isinstance(budget_raw, int)
                        or not 0 <= budget_raw <= 1_000_000
                    ):
                        raise SupervisionConflict("Invalid engagement execution attempt quota")
                    consumed = (
                        await session.execute(
                            select(func.count(SupervisionAttemptORM.id)).where(
                                SupervisionAttemptORM.engagement_id == engagement_id
                            )
                        )
                    ).scalar_one()
                    if consumed >= budget_raw:
                        raise SupervisionConflict("Engagement execution attempt quota exhausted")
                if row is None:
                    row = SupervisionAttemptORM(
                        id=_id("run"),
                        engagement_id=engagement_id,
                        task_id=task_id,
                        attempt=attempt,
                        status=status,
                        external_id=external_id,
                        revision=0,
                    )
                    session.add(row)
                    await session.flush()
                    await self._append_event(
                        session,
                        engagement_id,
                        task_id,
                        "agent.attempt.started",
                        "system",
                        {"attempt_id": row.id, "status": status},
                    )
                result = _row(row, _ATTEMPT_FIELDS)
                result["created"] = created
        return result

    async def update_attempt(
        self,
        attempt_id: str,
        expected_revision: int,
        status: str,
        receipt: Optional[Dict[str, Any]] = None,
        external_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        if status not in _ATTEMPT_STATUSES:
            raise ValueError("Unknown attempt status")
        if external_id is not None:
            external_id = _identifier(external_id, 128)
        clean_receipt = _safe_payload(receipt)
        if status == "confirmed_stopped" and not (
            clean_receipt.get("remote_stopped") is True and clean_receipt.get("receipt_id")
        ):
            raise SupervisionConflict("Confirmed stop requires a remote receipt")
        async with self._sessions() as session:
            async with session.begin():
                row = (
                    await session.execute(
                        select(SupervisionAttemptORM)
                        .where(SupervisionAttemptORM.id == attempt_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if row is None:
                    return None
                if row.revision != expected_revision:
                    return None
                if (
                    row.status in {"succeeded", "failed", "cancelled", "confirmed_stopped"}
                    and row.status != status
                ):
                    raise SupervisionConflict("Terminal attempt cannot be reopened")
                changed = await session.execute(
                    update(SupervisionAttemptORM)
                    .where(
                        SupervisionAttemptORM.id == attempt_id,
                        SupervisionAttemptORM.revision == expected_revision,
                    )
                    .values(
                        revision=expected_revision + 1,
                        status=status,
                        receipt=clean_receipt,
                        external_id=external_id if external_id is not None else row.external_id,
                        updated_at=datetime.utcnow(),
                    )
                )
                if changed.rowcount != 1:
                    return None
                await self._append_event(
                    session,
                    row.engagement_id,
                    row.task_id,
                    "agent.attempt.updated",
                    "system",
                    {"attempt_id": attempt_id, "status": status},
                )
                await session.refresh(row)
                result = _row(row, _ATTEMPT_FIELDS)
        return result

    async def list_attempts(
        self,
        engagement_id: str,
        task_id: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        async with self._sessions() as session:
            rows = (
                (
                    await session.execute(
                        select(SupervisionAttemptORM)
                        .where(
                            SupervisionAttemptORM.engagement_id == engagement_id,
                            SupervisionAttemptORM.task_id == task_id,
                        )
                        .order_by(SupervisionAttemptORM.attempt.desc())
                        .limit(max(1, min(limit, 200)))
                    )
                )
                .scalars()
                .all()
            )
        return [_row(row, _ATTEMPT_FIELDS) for row in rows]

    async def claim_outbox(self, limit: int = 50, lease_seconds: int = 60) -> List[Dict[str, Any]]:
        if not 1 <= lease_seconds <= 3600:
            raise ValueError("Lease must be between 1 and 3600 seconds")
        now = datetime.utcnow()
        claimed: List[Dict[str, Any]] = []
        async with self._sessions() as session:
            async with session.begin():
                rows = (
                    (
                        await session.execute(
                            select(SupervisionOutboxORM)
                            .where(
                                SupervisionOutboxORM.delivered_at.is_(None),
                                (SupervisionOutboxORM.leased_until.is_(None))
                                | (SupervisionOutboxORM.leased_until < now),
                            )
                            .order_by(SupervisionOutboxORM.created_at, SupervisionOutboxORM.id)
                            .with_for_update(skip_locked=True)
                            .limit(max(1, min(limit, 100)))
                        )
                    )
                    .scalars()
                    .all()
                )
                for row in rows:
                    row.lease_id = _id("lease")
                    row.leased_until = now + timedelta(seconds=lease_seconds)
                    row.attempts = row.attempts + 1
                    claimed.append(
                        _row(
                            row,
                            [
                                "id",
                                "event_id",
                                "engagement_id",
                                "topic",
                                "payload",
                                "lease_id",
                                "attempts",
                            ],
                        )
                    )
        return claimed

    async def ack_outbox(self, item_id: str, lease_id: str) -> bool:
        """Acknowledge only a *currently live* claim.

        A restarted worker can hold a historical lease token after its expiry
        but before another replica has reclaimed the row.  Token equality by
        itself is not authority to mark a notification delivered.
        """
        now = datetime.utcnow()
        async with self._sessions() as session:
            async with session.begin():
                result = await session.execute(
                    update(SupervisionOutboxORM)
                    .where(
                        SupervisionOutboxORM.id == item_id,
                        SupervisionOutboxORM.lease_id == lease_id,
                        SupervisionOutboxORM.delivered_at.is_(None),
                        SupervisionOutboxORM.leased_until > now,
                    )
                    .values(delivered_at=now, lease_id=None, leased_until=None)
                )
                acknowledged = result.rowcount == 1
        return acknowledged
