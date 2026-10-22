"""
Session Memory Layer
Multi-tier storage: Redis (hot) + PostgreSQL (warm) + S3 (cold).
Manages session state, agent working memory, and checkpoints.
"""

import hashlib
import json
import pickle
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlsplit

import redis.asyncio as redis
from sqlalchemy import JSON, Boolean, Column, DateTime, Integer, String, and_, case, cast, func, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker

from ai_osop.core.config import settings
from ai_osop.core.exceptions import MemoryException
from ai_osop.core.models import (
    ApprovalRequest,
    AuditEvent,
    EvidenceArtifact,
    ExecutionActionRecord,
    FlowRecord,
    ScopeDefinition,
    SessionState,
    SubtaskRecord,
    Task,
)
from ai_osop.core.telemetry import RequestContext
from ai_osop.core.tracing import trace_span
from ai_osop.reliability.retry import retry_with_backoff

import structlog

logger = structlog.get_logger("ai_osop.memory.session_memory")

Base = declarative_base()


class ApprovalRequestORM(Base):
    __tablename__ = "approval_requests"

    id = Column(String(64), primary_key=True)
    task_id = Column(String(64), index=True)
    agent_id = Column(String(64))
    action_type = Column(String(64))
    target = Column(String(512))
    payload_summary = Column(String(1024))
    risk_assessment = Column(String(1024))
    evidence = Column(JSON)
    status = Column(String(16), index=True)  # pending, approved, rejected, modified, timeout
    operator_id = Column(String(64), nullable=True)
    operator_notes = Column(String(2048), nullable=True)
    requested_at = Column(DateTime)
    responded_at = Column(DateTime, nullable=True)
    engagement_id = Column(String(64), index=True)


class TaskORM(Base):
    __tablename__ = "tasks"

    id = Column(String(64), primary_key=True)
    type = Column(String(64))
    priority = Column(Integer)
    agent_type = Column(String(64))
    payload = Column(JSON)
    dependencies = Column(JSON)
    max_retries = Column(Integer)
    timeout_seconds = Column(Integer)
    scope_check = Column(Boolean, default=True)
    approval_required = Column(Boolean, default=False)
    status = Column(
        String(32), index=True
    )  # includes awaiting_approval (17 chars) and durable uncertain states
    result = Column(JSON, nullable=True)
    retry_count = Column(Integer)
    created_at = Column(DateTime)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    engagement_id = Column(String(64), index=True)
    assigned_agent_id = Column(String(64), nullable=True)
    flow_id = Column(String(64), nullable=True, index=True)
    subtask_id = Column(String(64), nullable=True)
    parent_task_id = Column(String(64), nullable=True)


class EvidenceArtifactORM(Base):
    __tablename__ = "evidence_artifacts"

    id = Column(String(64), primary_key=True)
    engagement_id = Column(String(64), nullable=False, index=True)
    finding_id = Column(String(128), nullable=False, index=True)
    source_tool = Column(String(128), nullable=False)
    source_tool_version = Column(String(64), nullable=False, default="1.0.0")
    target_url = Column(String(1024), nullable=False)
    http_method = Column(String(16), nullable=False, default="GET")
    request_headers_sha256 = Column(String(64), nullable=False)
    request_body_sha256 = Column(String(64), nullable=False)
    response_status = Column(Integer, nullable=False)
    response_headers_sha256 = Column(String(64), nullable=False)
    response_body_sha256 = Column(String(64), nullable=False)
    raw_storage_uri = Column(String(512), nullable=False, default="")
    approval_id = Column(String(64), nullable=True)
    replay_recipe = Column(JSON, nullable=False)
    merkle_leaf_hash = Column(String(64), nullable=False, index=True)
    captured_at = Column(DateTime, nullable=False, default=datetime.utcnow)


_EVIDENCE_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_EVIDENCE_ID = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_EVIDENCE_REPLAY_FIELDS = frozenset({
    "schema", "source_task_id", "method", "url", "original_url_sha256",
    "request_header_names", "request_body_sha256", "replayable",
    "finding_verified", "target_effect_verified",
})


def evidence_artifact_leaf_sha256(artifact: EvidenceArtifact) -> str:
    """Bind every immutable metadata field, NOT certify target-side truth.

    A digest is proof of record integrity only, never source/owner evidence or
    a finding promotion. The schema cannot directly persist raw HTTP content.
    """
    if not isinstance(artifact, EvidenceArtifact):
        raise MemoryException("Evidence artifact model required")
    try:
        encoded = json.dumps(
            artifact.model_dump(mode="json", exclude={"merkle_leaf_hash"}),
            sort_keys=True, separators=(",", ":"), allow_nan=False, ensure_ascii=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise MemoryException("Evidence artifact canonicalization failed") from exc
    if len(encoded) > 8192:
        raise MemoryException("Evidence artifact metadata exceeds durable bound")
    return hashlib.sha256(b"ai-osop-evidence-artifact-v1\0" + encoded).hexdigest()


def _checked_evidence_artifact(artifact: EvidenceArtifact) -> EvidenceArtifact:
    """Reject legacy raw replay secrets and unbound/tampered digests."""
    if not isinstance(artifact, EvidenceArtifact):
        raise MemoryException("Evidence artifact type is invalid")
    recipe = artifact.replay_recipe
    try:
        parsed = urlsplit(artifact.target_url)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        safe_target = (
            parsed.scheme in {"http", "https"} and bool(parsed.hostname)
            and parsed.username is None and parsed.password is None and not parsed.fragment
            and not any(ord(char) < 33 or ord(char) == 127 for char in artifact.target_url)
            and len(query) <= 32
            and all(re.fullmatch(r"[A-Za-z0-9._~-]{1,128}", key) and value == "REDACTED"
                    for key, value in query)
        )
    except (TypeError, ValueError, AttributeError):
        safe_target = False
    if (
        not isinstance(recipe, dict)
        or set(recipe) != _EVIDENCE_REPLAY_FIELDS
        or recipe.get("schema") != "ai-osop.redacted-evidence-reference.v1"
        or recipe.get("replayable") is not False
        or recipe.get("finding_verified") is not False
        or recipe.get("target_effect_verified") is not False
        or not isinstance(recipe.get("source_task_id"), str)
        or not re.fullmatch(r"task-[A-Za-z0-9._-]{1,59}", recipe["source_task_id"])
        or recipe.get("method") != artifact.http_method
        or recipe.get("url") != artifact.target_url
        or recipe.get("request_body_sha256") != artifact.request_body_sha256
        or not isinstance(recipe.get("request_header_names"), list)
        or len(recipe["request_header_names"]) > 64
        or any(not isinstance(name, str)
               or not re.fullmatch(r"[a-z0-9-]{1,128}", name)
               or name in {"authorization", "cookie", "proxy-authorization", "x-api-key"}
               for name in recipe["request_header_names"])
        or any(not isinstance(value, str) or not _EVIDENCE_DIGEST.fullmatch(value)
               for value in (
                   artifact.request_headers_sha256, artifact.request_body_sha256,
                   artifact.response_headers_sha256, artifact.response_body_sha256,
                   recipe.get("original_url_sha256"), artifact.merkle_leaf_hash,
               ))
        or not isinstance(artifact.target_url, str)
        or len(artifact.target_url) > 1024
        or not safe_target
        or not isinstance(artifact.source_tool, str)
        or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", artifact.source_tool)
        or not isinstance(artifact.source_tool_version, str)
        or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", artifact.source_tool_version)
        or artifact.raw_storage_uri != ""
        or not isinstance(artifact.finding_id, str)
        or not _EVIDENCE_ID.fullmatch(artifact.finding_id)
        or type(artifact.response_status) is not int
        or not 100 <= artifact.response_status <= 599
        or not isinstance(artifact.engagement_id, str)
        or not _EVIDENCE_ID.fullmatch(artifact.engagement_id)
        or not isinstance(artifact.id, str)
        or not re.fullmatch(r"ev-[A-Za-z0-9._-]{1,61}", artifact.id)
        or not isinstance(artifact.http_method, str)
        or not re.fullmatch(r"[A-Z]{3,16}", artifact.http_method)
        or not isinstance(artifact.captured_at, datetime)
        or evidence_artifact_leaf_sha256(artifact) != artifact.merkle_leaf_hash
    ):
        raise MemoryException("Evidence metadata is not bounded, redacted, or integrity-bound")
    return artifact


class ExecutionFlowORM(Base):
    __tablename__ = "execution_flows"

    id = Column(String(64), primary_key=True)
    engagement_id = Column(String(64), nullable=False, index=True)
    objective = Column(String(2048), nullable=False)
    status = Column(String(32), nullable=False)
    revision = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class ExecutionSubtaskORM(Base):
    __tablename__ = "execution_subtasks"

    id = Column(String(64), primary_key=True)
    engagement_id = Column(String(64), nullable=False, index=True)
    flow_id = Column(String(64), nullable=False)
    task_id = Column(String(64), nullable=False)
    title = Column(String(256), nullable=False)
    description = Column(String(4096), nullable=False)
    task_type = Column(String(128), nullable=False)
    agent_type = Column(String(64), nullable=False)
    approval_required = Column(Boolean, nullable=False, default=False)
    order = Column(Integer, nullable=False)
    dependencies = Column(JSON, nullable=False)
    status = Column(String(32), nullable=False)
    refinement_count = Column(Integer, nullable=False)
    result_summary = Column(String(4096), nullable=True)
    execution_task_id = Column(String(64), nullable=True)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class ExecutionActionORM(Base):
    __tablename__ = "execution_actions"

    id = Column(String(64), primary_key=True)
    engagement_id = Column(String(64), nullable=False, index=True)
    flow_id = Column(String(64), nullable=True)
    task_id = Column(String(64), nullable=True, index=True)
    subtask_id = Column(String(64), nullable=True)
    tool_name = Column(String(128), nullable=False)
    outcome = Column(String(32), nullable=False)
    duration_ms = Column(Integer, nullable=True)
    safe_metadata = Column(JSON, nullable=False)
    created_at = Column(DateTime, nullable=False)


class SessionStateORM(Base):
    __tablename__ = "session_states"

    session_id = Column(String(64), primary_key=True)
    scope = Column(JSON)
    roe = Column(JSON)
    phase = Column(String(32))
    agents = Column(JSON)
    checkpoint_id = Column(String(64))
    audit_log_position = Column(String(64))
    created_by = Column(String(64), nullable=True)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)
    last_accessed = Column(DateTime, default=datetime.utcnow)


class AuditLogORM(Base):
    __tablename__ = "audit_logs"

    event_id = Column(String(64), primary_key=True)
    timestamp = Column(DateTime, index=True)
    event_type = Column(String(64), index=True)
    severity = Column(String(16))
    actor_type = Column(String(32))
    actor_id = Column(String(64), index=True)
    action = Column(JSON)
    result = Column(JSON)
    context = Column(JSON)
    integrity_hash = Column(String(128))
    engagement_id = Column(String(64), index=True)


class DLQEntryORM(Base):
    __tablename__ = "dlq_entries"

    id = Column(String(64), primary_key=True)
    task_id = Column(String(64), index=True)
    engagement_id = Column(String(64), index=True)
    task_type = Column(String(64))
    agent_type = Column(String(64))
    reason = Column(String(128))
    final_error = Column(String(2048))
    task_payload = Column(JSON)
    status = Column(String(32), index=True)  # pending_review, requeued, discarded
    operator_notes = Column(String(2048), nullable=True)
    created_at = Column(DateTime)
    resolved_at = Column(DateTime, nullable=True)


class FindingCorpusORM(Base):
    __tablename__ = "finding_corpus"

    id = Column(String(64), primary_key=True)
    original_finding_id = Column(String(64), index=True)
    category = Column(String(64), index=True)
    severity = Column(String(16))
    outcome = Column(String(32), index=True)  # accepted, duplicate, etc.
    payload = Column(JSON)
    engagement_id = Column(String(64), index=True)
    created_at = Column(DateTime)
    finalized_at = Column(DateTime)


class SessionMemory:
    """
    Multi-tier session memory with hot/warm/cold storage.

    Hot (Redis): Active session state, agent working memory, task queues
    Warm (PostgreSQL): Session snapshots, audit logs, structured data
    Cold (S3): Evidence artifacts, large blobs, archives
    """

    def __init__(self):
        self._redis: Optional[redis.Redis] = None
        self._pg_engine = None
        self._async_session = None

    async def assert_signed_authorization(
        self, engagement_id: str, expected_version: Optional[int] = None
    ) -> Any:
        """Check the current PostgreSQL ROE signature, key trust and revocation.

        Use this before invoking any model, agent, Temporal activity or MCP
        provider. Redis and cached session objects never confer authority.
        """
        from ai_osop.memory.authorization_store import AuthorizationStore

        return await AuthorizationStore(self).assert_active(
            engagement_id, expected_version=expected_version
        )

    async def verify_signed_graph_action(
        self, engagement_id: str, task_id: str, source_event_id: str,
        provider_receipt_sha256: str, authorization_version: int,
    ) -> bool:
        """Independently bind a graph research action to PostgreSQL receipt."""
        from ai_osop.memory.graph_research_projection import verify_signed_action_event
        from ai_osop.memory.supervision_store import SupervisionStore

        return await verify_signed_action_event(
            supervision=SupervisionStore(self),
            engagement_id=engagement_id,
            task_id=task_id,
            event_id=source_event_id,
            provider_receipt_sha256=provider_receipt_sha256,
            authorization_version=authorization_version,
        )

    async def connect(self) -> None:
        """Initialize all storage connections with retry.

        Sprint 7: Survives Redis/Postgres restarts during startup without
        crashing the platform. Uses exponential backoff for each tier.
        """

        # Redis with retry
        async def _connect_redis() -> None:
            self._redis = redis.from_url(
                settings.redis_uri, decode_responses=True, max_connections=50
            )
            await self._redis.ping()

        await retry_with_backoff(
            _connect_redis,
            max_retries=5,
            base_delay=1.0,
            max_delay=30.0,
            exceptions=(Exception,),
            retry_name="redis.connect",
        )

        # PostgreSQL with retry
        async def _connect_postgres() -> None:
            self._pg_engine = create_async_engine(
                settings.postgres_uri, pool_size=20, max_overflow=10, echo=False
            )
            # Run ordered migrations before create_all. create_all cannot alter
            # existing columns and silently leaves old installations unusable.
            from ai_osop.memory.schema_migrations import ensure_schema

            await ensure_schema(self._pg_engine, settings.postgres_uri)
            self._async_session = sessionmaker(
                self._pg_engine, class_=AsyncSession, expire_on_commit=False
            )
            # Some legacy auxiliary tables are not yet part of the base schema
            # migration; retain their existing safe create-if-missing behavior.
            async with self._pg_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

        await retry_with_backoff(
            _connect_postgres,
            max_retries=5,
            base_delay=1.0,
            max_delay=30.0,
            exceptions=(Exception,),
            retry_name="postgres.connect",
        )

    # ============== HOT TIER (Redis) ==============

    async def _ensure_redis(self) -> redis.Redis:
        """Return a healthy Redis connection, reconnecting if needed.

        Sprint 7: Auto-reconnect on Redis disconnect so the platform survives
        Redis restarts without requiring an application restart.
        """
        if self._redis is None:
            self._redis = redis.from_url(
                settings.redis_uri, decode_responses=True, max_connections=50
            )
            return self._redis
        try:
            await self._redis.ping()
            return self._redis
        except Exception:
            logger.warning("Redis connection lost, reconnecting...")
            self._redis = redis.from_url(
                settings.redis_uri, decode_responses=True, max_connections=50
            )
            return self._redis

    async def store_hot(self, key: str, value: Any, ttl: int = 3600) -> None:
        """Store in Redis with TTL."""
        r = await self._ensure_redis()
        with trace_span("redis.setex", attributes={"ai_osop.redis.key": key}):
            serialized = json.dumps(value, default=str)
            await r.setex(key, ttl, serialized)

    async def retrieve_hot(self, key: str) -> Optional[Any]:
        """Retrieve from Redis."""
        r = await self._ensure_redis()
        with trace_span("redis.get", attributes={"ai_osop.redis.key": key}):
            data = await r.get(key)
            if data:
                return json.loads(data)
            return None

    async def delete_hot(self, key: str) -> None:
        with trace_span("redis.delete", attributes={"ai_osop.redis.key": key}):
            r = await self._ensure_redis()
            await r.delete(key)

    async def acquire_lock(self, lock_key: str, lock_value: str, ttl_seconds: int = 30) -> bool:
        """Acquire a distributed Redis lock."""
        r = await self._ensure_redis()
        with trace_span("redis.acquire_lock", attributes={"ai_osop.redis.key": lock_key}):
            result = await r.set(lock_key, lock_value, nx=True, ex=ttl_seconds)
            return bool(result)

    async def release_lock(self, lock_key: str, lock_value: str) -> bool:
        """Release a distributed Redis lock safely, ensuring only the owner can release it."""
        r = await self._ensure_redis()
        with trace_span("redis.release_lock", attributes={"ai_osop.redis.key": lock_key}):
            lua_script = """
            if redis.call("get", KEYS[1]) == ARGV[1] then
                return redis.call("del", KEYS[1])
            else
                return 0
            end
            """
            result = await r.eval(lua_script, 1, lock_key, lock_value)
            return bool(result)

    async def acquire_task_lease(self, task_id: str, worker_id: str, ttl_seconds: int = 60) -> bool:
        """Acquire distributed task lease in Redis with TTL."""
        key = f"lease:task:{task_id}"
        return await self.acquire_lock(key, worker_id, ttl_seconds=ttl_seconds)

    async def renew_task_lease(self, task_id: str, worker_id: str, ttl_seconds: int = 60) -> bool:
        """Renew active distributed task lease in Redis."""
        key = f"lease:task:{task_id}"
        r = await self._ensure_redis()
        lua = """
        if redis.call("get", KEYS[1]) == ARGV[1] then
            return redis.call("expire", KEYS[1], ARGV[2])
        else
            return 0
        end
        """
        result = await r.eval(lua, 1, key, worker_id, ttl_seconds)
        return bool(result)

    async def release_task_lease(self, task_id: str, worker_id: str) -> bool:
        """Release distributed task lease upon completion."""
        key = f"lease:task:{task_id}"
        return await self.release_lock(key, worker_id)

    async def has_task_lease(self, task_id: str) -> bool:
        """Check whether active lease exists in Redis."""
        key = f"lease:task:{task_id}"
        r = await self._ensure_redis()
        val = await r.get(key)
        return val is not None

    async def store_session_state(self, state: SessionState) -> None:
        """Store active session state in Redis."""
        key = f"session:{state.session_id}"
        await self.store_hot(key, state.model_dump(), ttl=86400)

    async def get_session_state(self, session_id: str) -> Optional[SessionState]:
        """Retrieve active session state from Redis."""
        with trace_span("redis.get_session_state", attributes={"ai_osop.session_id": session_id}):
            data = await self.retrieve_hot(f"session:{session_id}")
            if data:
                return SessionState(**data)
            return None

    async def store_agent_state(
        self, agent_id: str, state: Dict[str, Any], ttl: int = 3600
    ) -> None:
        """Store agent working memory."""
        key = f"agent:{agent_id}"
        await self.store_hot(key, state, ttl)

    async def get_agent_state(self, agent_id: str) -> Optional[Dict[str, Any]]:
        return await self.retrieve_hot(f"agent:{agent_id}")

    async def publish_event(self, channel: str, event: Dict[str, Any]) -> None:
        """Publish event to Redis pub/sub."""
        with trace_span("redis.publish", attributes={"ai_osop.redis.channel": channel}):
            r = await self._ensure_redis()
            await r.publish(channel, json.dumps(event, default=str))

    async def subscribe_events(self, channel: str):
        """Subscribe to Redis pub/sub channel."""
        r = await self._ensure_redis()
        pubsub = r.pubsub()
        await pubsub.subscribe(channel)
        return pubsub

    async def push_task_queue(self, queue_name: str, task: Dict[str, Any]) -> None:
        """Push task to priority queue."""
        with trace_span("redis.zadd", attributes={"ai_osop.redis.queue": queue_name}):
            r = await self._ensure_redis()
            priority = task.get("priority", 5)
            await r.zadd(f"queue:{queue_name}", {json.dumps(task, default=str): priority})

    async def pop_task_queue(self, queue_name: str) -> Optional[Dict[str, Any]]:
        """Pop highest priority task from queue."""
        with trace_span("redis.zpopmax", attributes={"ai_osop.redis.queue": queue_name}):
            r = await self._ensure_redis()
            result = await r.zpopmax(f"queue:{queue_name}")
            if result:
                task_json, _ = result[0]
                return json.loads(task_json)
            return None

    # ============== WARM TIER (PostgreSQL) ==============

    async def persist_session_state(self, state: SessionState) -> None:
        """Update lifecycle fields without ever UPSERTing an unsigned scope.

        Session creation and authorization-version replacement happen ONLY
        through the signed ROE ledger's separately fenced PostgreSQL
        transactions. Old code used a broad UPSERT here, allowing stale
        checkpoint snapshots to overwrite newly narrowed signed policy.
        """
        async with self._async_session() as session:
            async with session.begin():
                row = (
                    await session.execute(
                        select(SessionStateORM)
                        .where(SessionStateORM.session_id == state.session_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if row is None:
                    raise MemoryException(
                        "Create engagements via atomic verified signed authorization"
                    )
                try:
                    authoritative_scope = ScopeDefinition.model_validate(row.scope)
                except (TypeError, ValueError) as exc:
                    raise MemoryException("Persisted signed scope is invalid") from exc
                if (
                    row.created_by != state.created_by
                    or authoritative_scope.model_dump(mode="json")
                    != state.scope.model_dump(mode="json")
                    or row.roe != state.roe
                ):
                    raise MemoryException(
                        "Cannot overwrite signed scope, owner, or ROE through session snapshot"
                    )
                if state.phase not in {"halted", "completed"}:
                    from ai_osop.memory.authorization_store import guard_sql
                    try:
                        await guard_sql(session, state.session_id)
                    except Exception as exc:
                        raise MemoryException(
                            "Session update requires active signed authorization"
                        ) from exc
                # A halted engagement remains terminable after revocation;
                # never reinstate policy or rewrite target-scope columns.
                row.phase = state.phase
                row.agents = state.agents
                row.checkpoint_id = state.checkpoint_id
                row.audit_log_position = state.audit_log_position
                row.updated_at = datetime.utcnow()

    async def load_session_state(self, session_id: str) -> Optional[SessionState]:
        """Load session state from PostgreSQL."""
        async with self._async_session() as session:
            result = await session.execute(
                select(SessionStateORM).where(SessionStateORM.session_id == session_id)
            )
            orm = result.scalar_one_or_none()

            if orm:
                return SessionState(
                    session_id=orm.session_id,
                    scope=ScopeDefinition(**orm.scope),
                    roe=orm.roe,
                    phase=orm.phase,
                    agents=orm.agents,
                    checkpoint_id=orm.checkpoint_id,
                    audit_log_position=orm.audit_log_position,
                    created_by=orm.created_by,
                    created_at=orm.created_at,
                    updated_at=orm.updated_at,
                )
            return None

    async def write_audit_event(self, event: AuditEvent) -> None:
        """Write cryptographically signed audit event with tracing."""
        with trace_span(
            "postgres.write_audit_event",
            attributes={
                "ai_osop.event_id": event.event_id,
                "ai_osop.engagement_id": event.engagement_id,
                "ai_osop.event_type": event.event_type,
            },
        ):
            import hmac

            configured = settings.audit_hmac_key
            production = settings.environment.strip().lower() in {"prod", "production"}
            # The old fixed fallback is not a secret. Production must refuse
            # unauthenticated audit writes rather than produce a forgeable
            # integrity digest with a publicly known key.
            if production and (
                not isinstance(configured, str)
                or len(configured.encode("utf-8")) < 32
                or configured == "default-insecure-audit-key"
            ):
                raise MemoryException("Production audit HMAC signing key unavailable")
            secret_key = (
                configured.encode("utf-8")
                if isinstance(configured, str) and configured
                else b"default-insecure-audit-key"  # local development only
            )

            # The session row serializes writers across process replicas.
            # Fetching the predecessor in a separate transaction allowed
            # two writers to sign independent branches from the same hash.
            async with self._async_session() as session:
                async with session.begin():
                    ownership = (
                        await session.execute(
                            select(SessionStateORM.session_id)
                            .where(SessionStateORM.session_id == event.engagement_id)
                            .with_for_update()
                        )
                    ).scalar_one_or_none()
                    if ownership is None:
                        raise MemoryException("Audit engagement is not durably registered")
                    predecessor = (
                        await session.execute(
                            select(AuditLogORM.integrity_hash, AuditLogORM.timestamp)
                            .where(AuditLogORM.engagement_id == event.engagement_id)
                            .order_by(AuditLogORM.timestamp.desc(), AuditLogORM.event_id.desc())
                            .limit(1)
                        )
                    ).one_or_none()
                    event_data = (
                        f"{event.event_id}:{event.timestamp.isoformat()}:"
                        f"{event.actor_id}:{event.event_type}"
                    )
                    if predecessor is not None:
                        # A backdated or equal timestamp would reorder the
                        # chain at read time and make verification ambiguous.
                        if event.timestamp <= predecessor[1]:
                            raise MemoryException("Audit timestamp is not monotonic")
                        event_data = f"{predecessor[0]}:{event_data}"
                    digest = hmac.new(
                        secret_key, event_data.encode(), hashlib.sha256
                    ).hexdigest()
                    await session.execute(insert(AuditLogORM).values(
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                        event_type=event.event_type,
                        severity=event.severity,
                        actor_type=event.actor_type,
                        actor_id=event.actor_id,
                        action=event.action,
                        result=event.result,
                        context=event.context,
                        integrity_hash=digest,
                        engagement_id=event.engagement_id,
                    ))
            # Only a committed transaction is an accepted audit record.
            event.integrity_hash = digest

    async def query_audit_log(
        self,
        engagement_id: str,
        event_types: Optional[List[str]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[AuditEvent]:
        """Query audit log with filters."""
        async with self._async_session() as session:
            query = select(AuditLogORM).where(AuditLogORM.engagement_id == engagement_id)

            if event_types:
                query = query.where(AuditLogORM.event_type.in_(event_types))
            if start_time:
                query = query.where(AuditLogORM.timestamp >= start_time)
            if end_time:
                query = query.where(AuditLogORM.timestamp <= end_time)

            query = query.order_by(AuditLogORM.timestamp.desc()).limit(limit)
            result = await session.execute(query)

            events = []
            for orm in result.scalars():
                events.append(
                    AuditEvent(
                        event_id=orm.event_id,
                        timestamp=orm.timestamp,
                        event_type=orm.event_type,
                        severity=orm.severity,
                        actor_type=orm.actor_type,
                        actor_id=orm.actor_id,
                        action=orm.action,
                        result=orm.result,
                        context=orm.context,
                        integrity_hash=orm.integrity_hash,
                        engagement_id=orm.engagement_id,
                    )
                )
            return events

    # ============== APPROVAL REQUESTS ==============

    async def store_approval_request(self, request: ApprovalRequest) -> None:
        """Register pending or fail-closed denial; NEVER grant approval here.

        Approved decisions must use resolve_approval_atomic, which commits a
        signed task grant + event/outbox in the same transaction. This legacy
        registration/timeout/halt path cannot overwrite a winning approval.
        """
        from ai_osop.safety.approval_binding import pinned_evidence
        with trace_span(
            "postgres.store_approval",
            attributes={
                "ai_osop.approval_id": request.id,
                "ai_osop.engagement_id": request.engagement_id,
                "ai_osop.status": request.status,
            },
        ):
            if request.status not in {"pending", "rejected", "timeout"}:
                raise PermissionError("Approval grants require atomic signed resolution")
            # Lock the durable row before mutating anything; Redis never acts
            # as a grant and never becomes authoritative on PostgreSQL errors.
            async with self._async_session() as session:
                async with session.begin():
                    existing = (
                        await session.execute(
                            select(ApprovalRequestORM)
                            .where(ApprovalRequestORM.id == request.id)
                            .with_for_update()
                        )
                    ).scalar_one_or_none()
                    if existing is None:
                        if request.status != "pending":
                            raise PermissionError("Cannot resolve an unknown approval")
                        # The operator approves a particular immutable task
                        # payload, not just a top-level target string. Pin
                        # every nested parameter from the persisted task, not
                        # the untrusted payload summary in the request.
                        source_task = (
                            await session.execute(
                                select(TaskORM).where(
                                    TaskORM.id == request.task_id,
                                    TaskORM.engagement_id == request.engagement_id,
                                ).with_for_update()
                            )
                        ).scalar_one_or_none()
                        if (
                            source_task is None
                            or source_task.status != "awaiting_approval"
                            or source_task.type != request.action_type
                            or not source_task.approval_required
                            or not isinstance(source_task.payload, dict)
                            or "approval_id" in source_task.payload
                            or source_task.payload.get("operator_approved") is True
                            or str(source_task.payload.get(
                                "url", source_task.payload.get("target", "unknown")
                            )) != request.target
                        ):
                            raise PermissionError("Approval registration task binding invalid")
                        if not isinstance(request.requested_at, datetime):
                            raise PermissionError("Approval registration requires a UTC timestamp")
                        registered_at = (
                            request.requested_at.astimezone(timezone.utc).replace(tzinfo=None)
                            if request.requested_at.tzinfo is not None
                            else request.requested_at
                        )
                        # Registration only bounds obviously forged timestamps;
                        # acceptance/timeout uses the PostgreSQL clock under
                        # the approval lock in the two decision transactions.
                        if registered_at > datetime.utcnow() + timedelta(minutes=1):
                            raise PermissionError("Approval registration timestamp is in the future")
                        binding_evidence = pinned_evidence(request.evidence, source_task.payload)
                        session.add(ApprovalRequestORM(
                        id=request.id,
                        task_id=request.task_id,
                        agent_id=request.agent_id,
                        action_type=request.action_type,
                        target=request.target,
                        payload_summary=request.payload_summary,
                        risk_assessment=request.risk_assessment,
                        evidence=binding_evidence,
                        status=request.status,
                        operator_id=request.operator_id,
                        operator_notes=request.operator_notes,
                        requested_at=request.requested_at,
                        responded_at=request.responded_at,
                        engagement_id=request.engagement_id,
                        ))
                    else:
                        if (
                            existing.engagement_id != request.engagement_id
                            or existing.task_id != request.task_id
                            or existing.action_type != request.action_type
                            or existing.agent_id != request.agent_id
                        ):
                            raise PermissionError("Immutable approval identity changed")
                        if existing.status == request.status:
                            # Idempotent storage only. Never replace a prior
                            # verified operator, timestamp or payload summary.
                            pass
                        elif (
                            existing.status == "pending"
                            and request.status in {"rejected", "timeout"}
                        ):
                            # Signed approvals must settle the Task, decision
                            # and audit/outbox in one transaction. This legacy
                            # row-only write is never their timeout path.
                            source_task = (await session.execute(
                                select(TaskORM).where(
                                    TaskORM.id == request.task_id,
                                    TaskORM.engagement_id == request.engagement_id,
                                ).with_for_update()
                            )).scalar_one_or_none()
                            if (
                                source_task is None
                                or isinstance(source_task.payload, dict)
                                and "_authorization_version" in source_task.payload
                            ):
                                raise PermissionError("Signed approval needs atomic resolution")
                            existing.status = request.status
                            existing.operator_id = request.operator_id
                            existing.operator_notes = request.operator_notes
                            existing.responded_at = request.responded_at
                        else:
                            raise PermissionError("Approval resolution already finalized")

            # This is display/recovery acceleration only. Do not turn a
            # committed decision into an API failure if Redis is unavailable.
            try:
                await self.store_hot(f"approval:{request.id}", request.model_dump(), ttl=86400 * 7)
            except Exception as exc:
                logger.warning("approval_redis_cache_unavailable", error_type=type(exc).__name__)

    async def load_approval_request(self, request_id: str) -> Optional[ApprovalRequest]:
        """Read the durable PostgreSQL decision, never a stale Redis grant."""
        async with self._async_session() as session:
            result = await session.execute(
                select(ApprovalRequestORM).where(ApprovalRequestORM.id == request_id)
            )
            orm = result.scalar_one_or_none()
            if orm:
                return ApprovalRequest(
                    id=orm.id,
                    task_id=orm.task_id,
                    agent_id=orm.agent_id,
                    action_type=orm.action_type,
                    target=orm.target,
                    payload_summary=orm.payload_summary,
                    risk_assessment=orm.risk_assessment,
                    evidence=orm.evidence,
                    status=orm.status,
                    operator_id=orm.operator_id,
                    operator_notes=orm.operator_notes,
                    requested_at=orm.requested_at,
                    responded_at=orm.responded_at,
                    engagement_id=orm.engagement_id,
                )
        return None

    @staticmethod
    def deterministic_task_approval_id(engagement_id: str, task_id: str) -> str:
        """Stable single-use identity for the approval associated with a Task."""
        if not engagement_id or not task_id:
            raise ValueError("A durable approval requires task and engagement")
        return "apr-task-" + hashlib.sha256(
            f"{engagement_id}:{task_id}:approval-v1".encode("utf-8")
        ).hexdigest()[:32]

    @staticmethod
    async def _approval_deadline_elapsed(db: AsyncSession, requested_at: datetime) -> bool:
        """Use PostgreSQL's clock after locking the approval, across replicas.

        The existing timestamp column stores naive UTC; do not reset a deadline
        from a newly started timeout watcher or local machine wall clock.
        """
        if not isinstance(requested_at, datetime):
            raise PermissionError("Approval request has no durable deadline")
        timestamp = (
            requested_at.astimezone(timezone.utc).replace(tzinfo=None)
            if requested_at.tzinfo is not None else requested_at
        )
        now = (await db.execute(select(func.clock_timestamp()))).scalar_one()
        if now.tzinfo is not None:
            now = now.astimezone(timezone.utc).replace(tzinfo=None)
        if timestamp > now:
            raise PermissionError("Approval registration timestamp is in the future")
        timeout = settings.approval_timeout_seconds
        if type(timeout) is not int or timeout < 0:
            raise PermissionError("Approval timeout is misconfigured")
        return now >= timestamp + timedelta(seconds=timeout)

    async def park_task_for_approval_atomic(
        self, task_snapshot: Task, request: ApprovalRequest,
    ) -> bool:
        """Persist a parked signed Task, pinned approval, and outbox together.

        Returns True only for the transaction that registered the approval.
        Subsequent scheduler replicas must use the already durable request;
        they cannot mint a second independent approval for the same Task.
        """
        from ai_osop.memory.authorization_store import guard_sql
        from ai_osop.memory.supervision_store import SupervisionStore
        from ai_osop.safety.approval_binding import pinned_evidence, task_payload_sha256
        from ai_osop.safety.scope import ScopeEnforcer, validate_payload_targets

        if (
            not isinstance(task_snapshot, Task)
            or not isinstance(request, ApprovalRequest)
            or not task_snapshot.approval_required
            or request.id != self.deterministic_task_approval_id(
                task_snapshot.engagement_id, task_snapshot.id,
            )
            or request.engagement_id != task_snapshot.engagement_id
            or request.task_id != task_snapshot.id
            or request.action_type != task_snapshot.type
            or request.status != "pending"
            or request.operator_id is not None
            or request.responded_at is not None
            or not isinstance(task_snapshot.payload, dict)
            or task_snapshot.payload.get("operator_approved") is True
            or task_snapshot.payload.get("approval_id") is not None
        ):
            raise PermissionError("Task approval registration identity is invalid")
        async with self._async_session() as db:
            async with db.begin():
                engagement, _ = await SupervisionStore._guard(
                    db, task_snapshot.engagement_id, require_window=True,
                )
                task = (await db.execute(select(TaskORM).where(
                    TaskORM.id == task_snapshot.id,
                    TaskORM.engagement_id == task_snapshot.engagement_id,
                ).with_for_update())).scalar_one_or_none()
                if task is None or task.status not in {"pending", "awaiting_approval"}:
                    return False
                if (
                    task.type != task_snapshot.type
                    or task.agent_type != task_snapshot.agent_type.value
                    or not task.approval_required
                    or not isinstance(task.payload, dict)
                    or task_payload_sha256(task.payload) != task_payload_sha256(task_snapshot.payload)
                    or task.flow_id != task_snapshot.flow_id
                    or task.subtask_id != task_snapshot.subtask_id
                    or task.parent_task_id != task_snapshot.parent_task_id
                    or task.dependencies != task_snapshot.dependencies
                    or task.payload.get("operator_approved") is True
                    or task.payload.get("approval_id") is not None
                    or str(task.payload.get("url", task.payload.get("target", "unknown"))) != request.target
                ):
                    raise PermissionError("Approval cannot be registered for a changed Task")
                signed = await guard_sql(db, task.engagement_id)
                if (
                    type(task.payload.get("_authorization_version")) is not int
                    or task.payload["_authorization_version"] != signed.version
                ):
                    raise PermissionError("Task approval signed version is stale")
                scope = ScopeDefinition.model_validate(engagement.scope)
                validate_payload_targets(ScopeEnforcer(scope), task.payload)
                if task.flow_id:
                    flow = (await db.execute(select(ExecutionFlowORM).where(
                        ExecutionFlowORM.id == task.flow_id,
                        ExecutionFlowORM.engagement_id == task.engagement_id,
                    ).with_for_update())).scalar_one_or_none()
                    if flow is None or flow.status not in {"pending", "running"}:
                        raise PermissionError("Flow is not active for task approval")
                    if task.subtask_id:
                        step = (await db.execute(select(ExecutionSubtaskORM).where(
                            ExecutionSubtaskORM.id == task.subtask_id,
                            ExecutionSubtaskORM.flow_id == task.flow_id,
                            ExecutionSubtaskORM.engagement_id == task.engagement_id,
                        ).with_for_update())).scalar_one_or_none()
                        if (
                            step is None or step.execution_task_id != task.id
                            or step.task_id != task.parent_task_id
                            or step.status not in {"dispatched", "running"}
                        ):
                            raise PermissionError("Task approval subtask lineage is not valid")
                previous = (await db.execute(select(ApprovalRequestORM).where(
                    ApprovalRequestORM.task_id == task.id,
                    ApprovalRequestORM.engagement_id == task.engagement_id,
                ).with_for_update())).scalars().all()
                if previous:
                    # Legacy random-ID rows cannot be replaced by another
                    # approval. A pending or settled request already owns it.
                    return False
                task.status = "awaiting_approval"
                db.add(ApprovalRequestORM(
                    id=request.id,
                    task_id=request.task_id,
                    agent_id=request.agent_id,
                    action_type=request.action_type,
                    target=request.target,
                    payload_summary=request.payload_summary[:1024],
                    risk_assessment=request.risk_assessment[:1024],
                    evidence=pinned_evidence(request.evidence or [], task.payload),
                    status="pending",
                    operator_id=None,
                    operator_notes=None,
                    requested_at=request.requested_at,
                    responded_at=None,
                    engagement_id=request.engagement_id,
                ))
                await db.flush()
                await SupervisionStore._append_event(
                    db, task.engagement_id, task.id,
                    "approval.requested", "scheduler",
                    {"status": "pending", "task_id": task.id, "approval_id": request.id},
                    idempotency_key="approval-requested:" + task.id,
                )
        return True

    async def resolve_approval_atomic(
        self,
        request_id: str,
        engagement_id: str,
        task_id: str,
        decision: str,
        operator_id: str,
        notes: Optional[str] = None,
    ) -> tuple[ApprovalRequest, bool]:
        """One PostgreSQL-authoritative, signed, fenced human decision.

        The engagement lock serializes revocation/halt and the approval/task
        locks serialize competing replicas. The task's grant, immutable human
        decision, event and outbox commit together. No Redis or local cache
        is consulted to grant authority; a repeated decision never dispatches.
        """
        from ai_osop.memory.authorization_store import guard_sql
        from ai_osop.memory.supervision_store import SupervisionStore
        from ai_osop.safety.approval_binding import matches_pinned_payload

        if (
            decision not in {"approved", "rejected"}
            or not all(isinstance(item, str) and item and len(item) <= 64
                       for item in (request_id, engagement_id, task_id, operator_id))
            or notes is not None and (not isinstance(notes, str) or len(notes) > 2048)
        ):
            raise ValueError("Invalid approval decision identity")

        async with self._async_session() as db:
            async with db.begin():
                engagement = (
                    await db.execute(
                        select(SessionStateORM)
                        .where(SessionStateORM.session_id == engagement_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if engagement is None or engagement.phase in {"halted", "completed"}:
                    raise PermissionError("Approval engagement is unavailable")
                # Signature, signer trust, signed owner, technique restrictions,
                # expiration and testing window checked in this very transaction.
                current = await guard_sql(db, engagement_id)
                row = (
                    await db.execute(
                        select(ApprovalRequestORM)
                        .where(ApprovalRequestORM.id == request_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if (
                    row is None
                    or row.engagement_id != engagement_id
                    or row.task_id != task_id
                ):
                    raise PermissionError("Approval request does not match its task")

                def approval_record() -> ApprovalRequest:
                    return ApprovalRequest(
                        id=row.id, task_id=row.task_id,
                        engagement_id=row.engagement_id, agent_id=row.agent_id,
                        action_type=row.action_type, target=row.target,
                        payload_summary=row.payload_summary,
                        risk_assessment=row.risk_assessment, evidence=row.evidence or [],
                        status=row.status, operator_id=row.operator_id,
                        operator_notes=row.operator_notes,
                        requested_at=row.requested_at, responded_at=row.responded_at,
                    )

                if row.status != "pending":
                    # A winning replica may have committed already. Do not
                    # reauthorize or overwrite its actor or decision.
                    return approval_record(), False

                if await self._approval_deadline_elapsed(db, row.requested_at):
                    # A late operator action cannot win merely because the
                    # timeout watcher crashed or another process restarted.
                    raise PermissionError("Approval decision deadline has elapsed")

                task = (
                    await db.execute(
                        select(TaskORM)
                        .where(TaskORM.id == task_id, TaskORM.engagement_id == engagement_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if (
                    task is None or task.status != "awaiting_approval"
                    or task.type != row.action_type
                    or task.type == "planner_inference"
                    or not task.approval_required
                    or not isinstance(task.payload, dict)
                    or type(task.payload.get("_authorization_version")) is not int
                    or task.payload["_authorization_version"] != current.version
                ):
                    raise PermissionError("Approval task is stale or not authorized")
                if task.flow_id:
                    flow = (
                        await db.execute(
                            select(ExecutionFlowORM)
                            .where(
                                ExecutionFlowORM.id == task.flow_id,
                                ExecutionFlowORM.engagement_id == engagement_id,
                            )
                            .with_for_update()
                        )
                    ).scalar_one_or_none()
                    if flow is None or flow.status not in {"pending", "running"}:
                        raise PermissionError("Approval flow is no longer executable")

                # Preserve the original request identity. A late approval for
                # a different requested target cannot release the current task.
                task_target = task.payload.get("url", task.payload.get("target", "unknown"))
                if row.target != str(task_target):
                    raise PermissionError("Approval target changed after operator review")
                if not matches_pinned_payload(row.evidence, task.payload):
                    # Includes changes to nested technique/options after the
                    # operator was shown the pending request. Legacy unbound
                    # approvals cannot be granted by silent backfill.
                    raise PermissionError("Approval task payload changed after review")

                row.status = decision
                row.operator_id = operator_id
                row.operator_notes = notes
                row.responded_at = datetime.utcnow()
                if decision == "approved":
                    task.payload = {
                        **task.payload,
                        "approval_id": request_id,
                        "operator_approved": True,
                    }
                else:
                    task.status = "failed"
                    task.result = {"status": "failed", "reason": "operator_rejected"}
                    task.completed_at = datetime.utcnow()
                # A missing event/outbox table, denied signer, failed commit or
                # concurrent revoke rolls back BOTH the grant and the decision.
                await SupervisionStore._append_event(
                    db, engagement_id, task_id, "approval.resolved", operator_id,
                    {"status": decision, "task_id": task_id},
                    idempotency_key="approval-resolution:" + request_id,
                )
                await db.flush()
                decided = approval_record()
        # Cache is never authoritative; do not turn a committed result into a
        # failure if Redis is offline or its reply is lost.
        try:
            await self.store_hot(
                f"approval:{request_id}", decided.model_dump(), ttl=86400 * 7
            )
        except Exception as exc:
            logger.warning("approval_redis_cache_unavailable", error_type=type(exc).__name__)
        return decided, True

    async def expire_approval_atomic(
        self, request_id: str, engagement_id: str, task_id: str,
    ) -> tuple[ApprovalRequest, bool]:
        """Expire one still-pending approval and its parked task atomically.

        A timeout is a *denial*, not a grant. It must still race safely with a
        human approval from another replica: a watcher cannot infer the winner
        from its process-local cache or fail an approved task afterward.
        Signed policy revocation must not prevent closing a pending request.
        """
        from ai_osop.memory.supervision_store import SupervisionStore

        if not all(
            isinstance(value, str) and 0 < len(value) <= 64
            for value in (request_id, engagement_id, task_id)
        ):
            raise ValueError("Invalid approval timeout identity")

        async with self._async_session() as db:
            async with db.begin():
                # Keep lock order identical to signed approval resolution:
                # engagement -> approval -> task. A revoke/halt or competing
                # operator resolver cannot slip between these transitions.
                engagement = (
                    await db.execute(
                        select(SessionStateORM)
                        .where(SessionStateORM.session_id == engagement_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if engagement is None:
                    raise PermissionError("Approval timeout engagement unavailable")
                approval = (
                    await db.execute(
                        select(ApprovalRequestORM)
                        .where(ApprovalRequestORM.id == request_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if (
                    approval is None or approval.engagement_id != engagement_id
                    or approval.task_id != task_id
                ):
                    raise PermissionError("Approval timeout identity mismatch")

                def snapshot() -> ApprovalRequest:
                    return ApprovalRequest(
                        id=approval.id, task_id=approval.task_id,
                        agent_id=approval.agent_id, action_type=approval.action_type,
                        target=approval.target, payload_summary=approval.payload_summary,
                        risk_assessment=approval.risk_assessment,
                        evidence=approval.evidence or [], status=approval.status,
                        operator_id=approval.operator_id,
                        operator_notes=approval.operator_notes,
                        requested_at=approval.requested_at,
                        responded_at=approval.responded_at,
                        engagement_id=approval.engagement_id,
                    )

                if approval.status != "pending":
                    return snapshot(), False

                if not await self._approval_deadline_elapsed(db, approval.requested_at):
                    # A resumed watcher must use the original registration
                    # time, not restart a fresh timeout or revoke early.
                    return snapshot(), False
                task = (
                    await db.execute(
                        select(TaskORM).where(
                            TaskORM.id == task_id,
                            TaskORM.engagement_id == engagement_id,
                        ).with_for_update()
                    )
                ).scalar_one_or_none()
                if (
                    task is None or task.status != "awaiting_approval"
                    or task.type != approval.action_type
                    or not task.approval_required
                    or not isinstance(task.payload, dict)
                    or task.payload.get("operator_approved") is True
                    or task.payload.get("approval_id") is not None
                ):
                    # Do not mutate a running/stale task even if its request is
                    # unexpectedly pending; operator reconciliation is needed.
                    raise PermissionError("Approval timeout task no longer parked")
                approval.status = "timeout"
                approval.operator_id = None
                approval.operator_notes = "Auto-rejected due to timeout"
                approval.responded_at = datetime.utcnow()
                task.status = "failed"
                task.result = {"status": "failed", "reason": "approval_timeout"}
                task.completed_at = datetime.utcnow()
                await SupervisionStore._append_event(
                    db, engagement_id, task_id, "approval.timeout", "system",
                    {"status": "timeout", "task_id": task_id},
                    idempotency_key="approval-timeout:" + request_id,
                )
                await db.flush()
                decided = snapshot()
        try:
            await self.store_hot(
                f"approval:{request_id}", decided.model_dump(), ttl=86400 * 7,
            )
        except Exception as exc:
            logger.warning(
                "approval_redis_cache_unavailable", error_type=type(exc).__name__
            )
        return decided, True

    async def claim_temporal_dispatch(self, candidate: Task) -> str:
        """Reserve a Temporal start once per signed task across all replicas.

        The irrevocable `dispatching` reservation is committed BEFORE calling
        Temporal. If the worker dies thereafter, recovery must keep the
        external outcome unknown, never blindly submit a replacement start.
        """
        from ai_osop.memory.supervision_store import SupervisionStore
        from ai_osop.safety.approval_binding import (
            matches_pinned_payload, task_payload_sha256,
        )
        from ai_osop.safety.scope import action_requires_approval, validate_payload_targets, ScopeEnforcer

        if not isinstance(candidate, Task) or not candidate.id or not candidate.engagement_id:
            raise PermissionError("Temporal dispatch requires a durable task identity")
        claim_id = "temporal-claim-" + uuid.uuid4().hex
        async with self._async_session() as db:
            async with db.begin():
                engagement, _ = await SupervisionStore._guard(
                    db, candidate.engagement_id, require_window=True,
                )
                row = (
                    await db.execute(
                        select(TaskORM).where(
                            TaskORM.id == candidate.id,
                            TaskORM.engagement_id == candidate.engagement_id,
                        ).with_for_update()
                    )
                ).scalar_one_or_none()
                if (
                    row is None
                    or row.status not in {"pending", "awaiting_approval"}
                    or candidate.status != row.status
                    or row.type != candidate.type
                    or row.agent_type != candidate.agent_type.value
                    or row.approval_required != candidate.approval_required
                    or row.flow_id != candidate.flow_id
                    or row.subtask_id != candidate.subtask_id
                    or row.parent_task_id != candidate.parent_task_id
                    or row.dependencies != candidate.dependencies
                    or not isinstance(row.payload, dict)
                    or not isinstance(candidate.payload, dict)
                    or task_payload_sha256(row.payload) != task_payload_sha256(candidate.payload)
                ):
                    raise PermissionError("Temporal dispatch task changed or was already claimed")
                scope = ScopeDefinition.model_validate(engagement.scope)
                # Nonconsequential internal tasks may have no approval; an
                # explicit signed technique or exploit requirement cannot be
                # bypassed via candidate.approval_required=False.
                if (action_requires_approval(row.type, scope) or row.agent_type == "exploit_validation") and not row.approval_required:
                    raise PermissionError("Temporal dispatch requires human approval")
                validate_payload_targets(ScopeEnforcer(scope), row.payload)
                from ai_osop.memory.authorization_store import guard_sql
                signed = await guard_sql(db, candidate.engagement_id)
                if type(row.payload.get("_authorization_version")) is not int or row.payload["_authorization_version"] != signed.version:
                    raise PermissionError("Temporal dispatch signed version changed")
                if row.flow_id:
                    flow = (
                        await db.execute(select(ExecutionFlowORM).where(
                            ExecutionFlowORM.id == row.flow_id,
                            ExecutionFlowORM.engagement_id == candidate.engagement_id,
                        ).with_for_update())
                    ).scalar_one_or_none()
                    if flow is None or flow.status not in {"pending", "running"}:
                        raise PermissionError("Temporal dispatch Flow is closed")
                    if row.subtask_id:
                        # The Flow's committed dispatch intent must still
                        # reference THIS immutable TaskORM. A queued Temporal
                        # snapshot cannot substitute a sibling subtask or an
                        # overwritten task after a planner/CAS race.
                        step = (
                            await db.execute(
                                select(ExecutionSubtaskORM).where(
                                    ExecutionSubtaskORM.id == row.subtask_id,
                                    ExecutionSubtaskORM.flow_id == row.flow_id,
                                    ExecutionSubtaskORM.engagement_id == candidate.engagement_id,
                                ).with_for_update()
                            )
                        ).scalar_one_or_none()
                        if (
                            step is None
                            or step.execution_task_id != row.id
                            or step.task_id != row.parent_task_id
                            or step.status not in {"dispatched", "running"}
                        ):
                            raise PermissionError("Temporal dispatch Flow Task lineage is unverified")
                if row.dependencies:
                    # The process-local dependency check and Redis cache are
                    # advisory only. Verify every original predecessor's
                    # terminal success and tenant under the same SQL claim
                    # transaction BEFORE the irreversible Temporal start.
                    if (
                        not isinstance(row.dependencies, list)
                        or len(row.dependencies) != len(set(row.dependencies))
                        or any(not isinstance(dep, str) or not dep for dep in row.dependencies)
                    ):
                        raise PermissionError("Temporal dispatch dependencies are malformed")
                    parents = (
                        await db.execute(
                            select(TaskORM.id, TaskORM.status).where(
                                TaskORM.id.in_(row.dependencies),
                                TaskORM.engagement_id == candidate.engagement_id,
                            ).with_for_update()
                        )
                    ).all()
                    if {
                        dependency_id
                        for dependency_id, status in parents
                        if status == "completed"
                    } != set(row.dependencies):
                        raise PermissionError("Temporal dispatch dependencies are incomplete")
                if row.approval_required:
                    approval_id = row.payload.get("approval_id")
                    approval = (
                        await db.execute(select(ApprovalRequestORM).where(
                            ApprovalRequestORM.id == approval_id,
                            ApprovalRequestORM.task_id == row.id,
                            ApprovalRequestORM.engagement_id == candidate.engagement_id,
                            ApprovalRequestORM.status == "approved",
                        ).with_for_update())
                    ).scalar_one_or_none() if isinstance(approval_id, str) else None
                    if (
                        approval is None
                        or not approval.operator_id
                        or approval.responded_at is None
                        or row.payload.get("operator_approved") is not True
                        or candidate.payload.get("operator_approved") is not True
                        or not matches_pinned_payload(approval.evidence, row.payload)
                    ):
                        raise PermissionError("Temporal dispatch approval is unverified")
                row.status = "dispatching"
                row.result = {"status": "dispatching", "claim_id": claim_id}
                await SupervisionStore._append_event(
                    db, candidate.engagement_id, candidate.id,
                    "temporal.dispatch_claimed", "scheduler",
                    {"status": "dispatching", "task_id": candidate.id},
                    idempotency_key="temporal-dispatch-claimed:" + candidate.id,
                )
                await db.flush()
        return claim_id

    async def settle_temporal_dispatch(
        self, task_id: str, engagement_id: str, claim_id: str,
        outcome: str, workflow_id: Optional[str] = None,
    ) -> None:
        """Owner-fenced commit of Temporal's start receipt, never target replay."""
        from ai_osop.memory.supervision_store import SupervisionStore

        if (
            not all(isinstance(v, str) and 0 < len(v) <= 64
                    for v in (task_id, engagement_id, claim_id))
            or outcome not in {"scheduled", "dispatch_unknown"}
            or (outcome == "scheduled" and workflow_id != "ai-osop-" + task_id)
            or (outcome == "dispatch_unknown" and workflow_id is not None)
        ):
            raise ValueError("Invalid Temporal dispatch settlement receipt")
        async with self._async_session() as db:
            async with db.begin():
                engagement = (
                    await db.execute(select(SessionStateORM).where(
                        SessionStateORM.session_id == engagement_id,
                    ).with_for_update())
                ).scalar_one_or_none()
                if engagement is None:
                    raise PermissionError("Temporal dispatch engagement unavailable")
                row = (
                    await db.execute(select(TaskORM).where(
                        TaskORM.id == task_id,
                        TaskORM.engagement_id == engagement_id,
                    ).with_for_update())
                ).scalar_one_or_none()
                if (
                    row is None or row.status != "dispatching"
                    or not isinstance(row.result, dict)
                    or row.result.get("claim_id") != claim_id
                ):
                    raise PermissionError("Temporal dispatch claim is stale or foreign")
                row.status = outcome
                row.result = (
                    {"workflow_id": workflow_id, "durable": True}
                    if outcome == "scheduled"
                    else {"status": "unknown", "reason": "temporal_start_unverified"}
                )
                await SupervisionStore._append_event(
                    db, engagement_id, task_id,
                    "temporal.dispatch_receipt", "scheduler",
                    {"status": outcome, "task_id": task_id},
                    idempotency_key="temporal-dispatch-receipt:" + task_id,
                )
                await db.flush()

    async def reconcile_temporal_dispatch_observation(
        self, task_id: str, engagement_id: str, workflow_id: str,
        *, provider_run_id: str, provider_status: str,
    ) -> bool:
        """Record a verified Temporal workflow's *existence*, not its outcome.

        Only the pre-acknowledgement `temporal_start_unverified` uncertainty can
        be reconciled. An activity whose target-side effect became UNKNOWN has
        a different reason and must stay quarantined. The caller must have
        successfully described the exact workflow ID against the actual
        Temporal service and supplied its provider-assigned run ID; this does
        not submit/replay any workflow or attest target execution.

        Returns True only when a new durable observation was committed. A
        second observer sees False and cannot emit duplicate event/outbox.
        """
        from ai_osop.memory.authorization_store import guard_sql
        from ai_osop.memory.supervision_store import SupervisionStore
        from ai_osop.safety.approval_binding import matches_pinned_payload
        from ai_osop.safety.scope import ScopeEnforcer, validate_payload_targets

        if (
            not isinstance(task_id, str) or not 0 < len(task_id) <= 64
            or not isinstance(engagement_id, str) or not 0 < len(engagement_id) <= 64
            or workflow_id != "ai-osop-" + task_id
            or not isinstance(provider_run_id, str)
            or not 0 < len(provider_run_id) <= 128
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}", provider_run_id)
            or provider_status not in {
                "RUNNING", "COMPLETED", "FAILED", "CANCELED", "TERMINATED",
                "TIMED_OUT", "CONTINUED_AS_NEW",
            }
        ):
            raise ValueError("Temporal workflow observation identity is invalid")

        async with self._async_session() as db:
            async with db.begin():
                engagement, _ = await SupervisionStore._guard(
                    db, engagement_id, require_window=True,
                )
                row = (await db.execute(select(TaskORM).where(
                    TaskORM.id == task_id,
                    TaskORM.engagement_id == engagement_id,
                ).with_for_update())).scalar_one_or_none()
                if row is None:
                    raise PermissionError("Temporal observation task is missing")
                if row.status == "scheduled" and isinstance(row.result, dict) and (
                    row.result.get("workflow_id") == workflow_id
                    and row.result.get("provider_run_id") == provider_run_id
                    and row.result.get("reconciled") is True
                ):
                    return False
                if (
                    row.status != "dispatch_unknown"
                    or not isinstance(row.result, dict)
                    or row.result.get("reason") != "temporal_start_unverified"
                    or not isinstance(row.payload, dict)
                ):
                    raise PermissionError("Temporal task is not a reconcilable start")

                signed = await guard_sql(db, engagement_id)
                if (
                    type(row.payload.get("_authorization_version")) is not int
                    or row.payload["_authorization_version"] != signed.version
                    or not row.scope_check
                ):
                    raise PermissionError("Temporal observation signed authority changed")
                scope = ScopeDefinition.model_validate(engagement.scope)
                validate_payload_targets(ScopeEnforcer(scope), row.payload)

                if row.flow_id:
                    flow = (await db.execute(select(ExecutionFlowORM).where(
                        ExecutionFlowORM.id == row.flow_id,
                        ExecutionFlowORM.engagement_id == engagement_id,
                    ).with_for_update())).scalar_one_or_none()
                    if flow is None or flow.status not in {"pending", "running"}:
                        raise PermissionError("Temporal observation Flow is closed")
                    if row.subtask_id:
                        subtask = (await db.execute(select(ExecutionSubtaskORM).where(
                            ExecutionSubtaskORM.id == row.subtask_id,
                            ExecutionSubtaskORM.engagement_id == engagement_id,
                            ExecutionSubtaskORM.flow_id == row.flow_id,
                        ).with_for_update())).scalar_one_or_none()
                        if (
                            subtask is None or subtask.execution_task_id != row.id
                            or subtask.task_id != row.parent_task_id
                            or subtask.status not in {"dispatched", "running"}
                        ):
                            raise PermissionError("Temporal observation lineage changed")
                if row.approval_required:
                    approval_id = row.payload.get("approval_id")
                    approved = (await db.execute(select(ApprovalRequestORM).where(
                        ApprovalRequestORM.id == approval_id,
                        ApprovalRequestORM.task_id == task_id,
                        ApprovalRequestORM.engagement_id == engagement_id,
                        ApprovalRequestORM.status == "approved",
                    ).with_for_update())).scalar_one_or_none() if isinstance(approval_id, str) else None
                    if (
                        approved is None or not approved.operator_id
                        or approved.responded_at is None
                        or row.payload.get("operator_approved") is not True
                        or not matches_pinned_payload(approved.evidence, row.payload)
                    ):
                        raise PermissionError("Temporal observation approval is unverified")

                row.status = "scheduled"
                row.result = {
                    "workflow_id": workflow_id,
                    "durable": True,
                    "reconciled": True,
                    "provider_run_id": provider_run_id,
                    "provider_status_observed": provider_status,
                }
                await SupervisionStore._append_event(
                    db, engagement_id, task_id,
                    "temporal.dispatch_reconciled", "temporal-reconciler",
                    {"status": "scheduled", "task_id": task_id,
                     "workflow_exists": True},
                    idempotency_key="temporal-dispatch-reconciled:" + task_id,
                )
                await db.flush()
        return True

    async def claim_local_agent_start(self, candidate: Task, agent_id: str) -> bool:
        """Fence local agent startup with a one-shot signed PostgreSQL claim.

        A Redis queue entry or a replica's stale Task snapshot cannot start a
        second agent. A crash after the claim is conservatively unresolved;
        recovery must not replay a running task without a terminal receipt.
        """
        from ai_osop.memory.authorization_store import guard_sql
        from ai_osop.memory.supervision_store import SupervisionStore
        from ai_osop.safety.approval_binding import matches_pinned_payload, task_payload_sha256
        from ai_osop.safety.scope import (
            ScopeEnforcer, action_requires_approval, validate_payload_targets,
        )

        if (
            not isinstance(candidate, Task) or not candidate.id
            or not candidate.engagement_id or not isinstance(candidate.payload, dict)
            or not isinstance(agent_id, str) or not agent_id.strip() or len(agent_id) > 64
        ):
            raise PermissionError("Local execution requires durable task and agent identity")

        async with self._async_session() as db:
            async with db.begin():
                engagement, _ = await SupervisionStore._guard(
                    db, candidate.engagement_id, require_window=True,
                )
                task = (await db.execute(select(TaskORM).where(
                    TaskORM.id == candidate.id,
                    TaskORM.engagement_id == candidate.engagement_id,
                ).with_for_update())).scalar_one_or_none()
                if task is None or task.status not in {"pending", "awaiting_approval"}:
                    return False
                if (
                    candidate.status != task.status
                    or candidate.type != task.type
                    or candidate.agent_type.value != task.agent_type
                    or candidate.flow_id != task.flow_id
                    or candidate.subtask_id != task.subtask_id
                    or candidate.parent_task_id != task.parent_task_id
                    or candidate.dependencies != task.dependencies
                    or candidate.approval_required != task.approval_required
                    or not isinstance(task.payload, dict)
                    or task_payload_sha256(candidate.payload) != task_payload_sha256(task.payload)
                ):
                    return False
                signed = await guard_sql(db, candidate.engagement_id)
                if (
                    type(task.payload.get("_authorization_version")) is not int
                    or task.payload["_authorization_version"] != signed.version
                ):
                    raise PermissionError("Local task signed authorization is stale")
                scope = ScopeDefinition.model_validate(engagement.scope)
                validate_payload_targets(
                    ScopeEnforcer(scope), task.payload,
                    require_target=task.agent_type in {"recon", "vuln_analysis"},
                )
                if (
                    action_requires_approval(task.type, scope)
                    or task.agent_type == "exploit_validation"
                ) and not task.approval_required:
                    raise PermissionError("Local task bypassed required human approval")
                if task.flow_id:
                    flow = (await db.execute(select(ExecutionFlowORM).where(
                        ExecutionFlowORM.id == task.flow_id,
                        ExecutionFlowORM.engagement_id == candidate.engagement_id,
                    ).with_for_update())).scalar_one_or_none()
                    if flow is None or flow.status not in {"pending", "running"}:
                        raise PermissionError("Local execution Flow is closed")
                    if task.subtask_id:
                        step = (await db.execute(select(ExecutionSubtaskORM).where(
                            ExecutionSubtaskORM.id == task.subtask_id,
                            ExecutionSubtaskORM.flow_id == task.flow_id,
                            ExecutionSubtaskORM.engagement_id == candidate.engagement_id,
                        ).with_for_update())).scalar_one_or_none()
                        if (
                            step is None or step.execution_task_id != task.id
                            or step.task_id != task.parent_task_id
                            or step.status not in {"dispatched", "running"}
                        ):
                            raise PermissionError("Local task lineage is unverified")
                if task.dependencies:
                    parents = (await db.execute(select(TaskORM.id, TaskORM.status).where(
                        TaskORM.id.in_(task.dependencies),
                        TaskORM.engagement_id == candidate.engagement_id,
                    ).with_for_update())).all()
                    if {id_ for id_, status in parents if status == "completed"} != set(task.dependencies):
                        return False
                if task.approval_required:
                    approval_id = task.payload.get("approval_id")
                    approval = (await db.execute(select(ApprovalRequestORM).where(
                        ApprovalRequestORM.id == approval_id,
                        ApprovalRequestORM.task_id == task.id,
                        ApprovalRequestORM.engagement_id == candidate.engagement_id,
                        ApprovalRequestORM.status == "approved",
                    ).with_for_update())).scalar_one_or_none() if isinstance(approval_id, str) else None
                    if (
                        approval is None or not approval.operator_id
                        or approval.responded_at is None
                        or task.payload.get("operator_approved") is not True
                        or not matches_pinned_payload(approval.evidence, task.payload)
                    ):
                        return False
                task.status = "running"
                task.assigned_agent_id = agent_id
                task.started_at = datetime.utcnow()
                await SupervisionStore._append_event(
                    db, candidate.engagement_id, task.id,
                    "task.local_execution_claimed", "scheduler",
                    {"status": "running", "task_id": task.id},
                    idempotency_key="local-execution-claimed:" + task.id,
                )
        return True

    async def expire_pending_task_atomic(
        self, task_id: str, engagement_id: str, *, created_before: datetime,
    ) -> bool:
        """Expire only a *currently pending* Task and its outbox atomically.

        A reaper's old in-process snapshot is never proof that the durable
        Task is still pending; another replica may have already claimed the
        execution. An executing/unknown task is not evidence of termination.
        """
        from ai_osop.memory.supervision_store import SupervisionStore

        if (
            not isinstance(task_id, str) or not task_id or len(task_id) > 64
            or not isinstance(engagement_id, str) or not engagement_id
            or len(engagement_id) > 64 or not isinstance(created_before, datetime)
        ):
            raise ValueError("Pending-task timeout needs bounded identity and cutoff")
        async with self._async_session() as db:
            async with db.begin():
                parent = (await db.execute(select(SessionStateORM).where(
                    SessionStateORM.session_id == engagement_id,
                ).with_for_update())).scalar_one_or_none()
                if parent is None:
                    raise PermissionError("Reaper engagement record unavailable")
                task = (await db.execute(select(TaskORM).where(
                    TaskORM.id == task_id,
                    TaskORM.engagement_id == engagement_id,
                ).with_for_update())).scalar_one_or_none()
                if (
                    task is None or task.status != "pending"
                    or not task.created_at or task.created_at > created_before
                ):
                    return False
                if task.dependencies:
                    if (
                        not isinstance(task.dependencies, list)
                        or len(task.dependencies) != len(set(task.dependencies))
                        or any(not isinstance(dep, str) or not dep for dep in task.dependencies)
                    ):
                        return False
                    parents = (
                        await db.execute(
                            select(
                                TaskORM.id, TaskORM.status, TaskORM.completed_at
                            ).where(
                                TaskORM.id.in_(task.dependencies),
                                TaskORM.engagement_id == engagement_id,
                            ).with_for_update()
                        )
                    ).all()
                    if len(parents) != len(task.dependencies) or any(
                        status != "completed"
                        or completed_at is None
                        or completed_at > created_before
                        for _, status, completed_at in parents
                    ):
                        # An old task creation timestamp is not an execution
                        # timeout. Every parent must have completed early
                        # enough for this child to receive its entire pending
                        # window; a second replica could have moved it in
                        # the interval since the reaper's first read.
                        return False
                task.status = "failed"
                task.completed_at = datetime.utcnow()
                task.result = {"status": "failed", "reason": "pending_task_timeout"}
                await SupervisionStore._append_event(
                    db, engagement_id, task_id,
                    "task.pending_timeout", "reaper",
                    {"status": "failed", "task_id": task_id},
                    idempotency_key="pending-timeout:" + task_id,
                )
        return True

    async def list_pending_approvals(self) -> List[ApprovalRequest]:
        """List all pending approval requests from warm tier."""
        async with self._async_session() as session:
            result = await session.execute(
                select(ApprovalRequestORM).where(ApprovalRequestORM.status == "pending")
            )
            approvals = []
            for orm in result.scalars():
                approvals.append(
                    ApprovalRequest(
                        id=orm.id,
                        task_id=orm.task_id,
                        agent_id=orm.agent_id,
                        action_type=orm.action_type,
                        target=orm.target,
                        payload_summary=orm.payload_summary,
                        risk_assessment=orm.risk_assessment,
                        evidence=orm.evidence,
                        status=orm.status,
                        operator_id=orm.operator_id,
                        operator_notes=orm.operator_notes,
                        requested_at=orm.requested_at,
                        responded_at=orm.responded_at,
                        engagement_id=orm.engagement_id,
                    )
                )
            return approvals

    # ============== DLQ ==============

    async def store_dlq_entry(self, entry: Any) -> None:
        """Persist DLQ entry to hot (Redis) + warm (Postgres) tier."""
        from ai_osop.reliability.dlq import DLQEntry

        with trace_span(
            "postgres.store_dlq_entry",
            attributes={"ai_osop.dlq_id": entry.id, "ai_osop.engagement_id": entry.engagement_id},
        ):
            # Hot tier (Redis cache)
            await self.store_hot(f"dlq:{entry.id}", entry.model_dump(), ttl=86400 * 7)
            # Warm tier (Postgres)
            async with self._async_session() as session:
                stmt = (
                    insert(DLQEntryORM)
                    .values(
                        id=entry.id,
                        task_id=entry.task_id,
                        engagement_id=entry.engagement_id,
                        task_type=entry.task_type,
                        agent_type=entry.agent_type,
                        reason=entry.reason,
                        final_error=entry.final_error,
                        task_payload=entry.task_payload,
                        status=entry.status,
                        operator_notes=entry.operator_notes,
                        created_at=entry.created_at,
                        resolved_at=entry.resolved_at,
                    )
                    .on_conflict_do_update(
                        index_elements=["id"],
                        set_={
                            "status": entry.status,
                            "operator_notes": entry.operator_notes,
                            "resolved_at": entry.resolved_at,
                        },
                    )
                )
                await session.execute(stmt)
                await session.commit()

    async def get_dlq_entry(self, entry_id: str) -> Optional[Any]:
        """Retrieve DLQ entry from hot (Redis) falling back to warm (Postgres) tier."""
        from ai_osop.reliability.dlq import DLQEntry

        with trace_span("postgres.get_dlq_entry", attributes={"ai_osop.dlq_id": entry_id}):
            # 1. Hot tier check
            data = await self.retrieve_hot(f"dlq:{entry_id}")
            if data:
                return DLQEntry(**data)

            # 2. Warm tier fallback
            async with self._async_session() as session:
                result = await session.execute(
                    select(DLQEntryORM).where(DLQEntryORM.id == entry_id)
                )
                orm = result.scalar_one_or_none()
                if orm:
                    entry = DLQEntry(
                        id=orm.id,
                        task_id=orm.task_id,
                        engagement_id=orm.engagement_id,
                        task_type=orm.task_type,
                        agent_type=orm.agent_type,
                        reason=orm.reason,
                        final_error=orm.final_error,
                        task_payload=orm.task_payload,
                        status=orm.status,
                        operator_notes=orm.operator_notes,
                        created_at=orm.created_at,
                        resolved_at=orm.resolved_at,
                    )
                    # Cache back to Redis
                    await self.store_hot(f"dlq:{entry.id}", entry.model_dump(), ttl=86400 * 7)
                    return entry
            return None

    async def list_dlq_entries(
        self, engagement_id: Optional[str] = None, status: Optional[str] = None
    ) -> List[Any]:
        """List DLQ entries from warm tier (Postgres)."""
        from ai_osop.reliability.dlq import DLQEntry

        with trace_span("postgres.list_dlq_entries"):
            async with self._async_session() as session:
                query = select(DLQEntryORM)
                if engagement_id:
                    query = query.where(DLQEntryORM.engagement_id == engagement_id)
                if status:
                    query = query.where(DLQEntryORM.status == status)
                # Sort by created_at descending
                query = query.order_by(DLQEntryORM.created_at.desc())
                result = await session.execute(query)
                entries = []
                for orm in result.scalars():
                    entries.append(
                        DLQEntry(
                            id=orm.id,
                            task_id=orm.task_id,
                            engagement_id=orm.engagement_id,
                            task_type=orm.task_type,
                            agent_type=orm.agent_type,
                            reason=orm.reason,
                            final_error=orm.final_error,
                            task_payload=orm.task_payload,
                            status=orm.status,
                            operator_notes=orm.operator_notes,
                            created_at=orm.created_at,
                            resolved_at=orm.resolved_at,
                        )
                    )
                return entries

    async def get_dlq_stats(self) -> Dict[str, int]:
        """Get DLQ status counts from warm tier (Postgres)."""
        with trace_span("postgres.get_dlq_stats"):
            async with self._async_session() as session:
                # Group by status to compute stats
                from sqlalchemy import func

                query = select(DLQEntryORM.status, func.count(DLQEntryORM.id)).group_by(
                    DLQEntryORM.status
                )
                result = await session.execute(query)
                stats = {"pending": 0, "requeued": 0, "discarded": 0}
                for status, count in result.all():
                    if status == "pending_review":
                        stats["pending"] = count
                    elif status == "requeued":
                        stats["requeued"] = count
                    elif status == "discarded":
                        stats["discarded"] = count
                return stats

    async def upsert_corpus_finding(self, finding_data: Dict[str, Any]) -> None:
        """Upsert aggregated finding into Postgres corpus."""
        async with self._async_session() as session:
            stmt = (
                insert(FindingCorpusORM)
                .values(
                    id=str(uuid.uuid4()),
                    original_finding_id=finding_data.get("id"),
                    category=finding_data.get("category"),
                    severity=finding_data.get("severity", "medium"),
                    outcome="accepted",
                    payload=finding_data,
                    engagement_id=finding_data.get("engagement_id"),
                    created_at=datetime.utcnow(),
                    finalized_at=datetime.utcnow(),
                )
                .on_conflict_do_update(
                    index_elements=["original_finding_id"],
                    set_={"payload": finding_data, "finalized_at": datetime.utcnow()},
                )
            )
            await session.execute(stmt)
            await session.commit()

    # ============== TASKS ==============

    async def settle_local_task_terminal_atomic(
        self, task: Task, outcome: str, result: Dict[str, Any],
    ) -> bool:
        """One terminal winner for an already running locally owned Task.

        A stale callback cannot transition another worker's running claim,
        bypass revocation, or trigger downstream chains unless this receipt
        committed. UNKNOWN/dispatching and terminal states are never replayed.
        """
        from ai_osop.memory.supervision_store import SupervisionStore
        from ai_osop.safety.approval_binding import task_payload_sha256

        if outcome not in {"completed", "failed"} or not isinstance(task, Task):
            raise ValueError("Unsupported terminal receipt")
        if not task.assigned_agent_id or not isinstance(result, dict):
            raise PermissionError("Terminal receipt requires an owner and result")
        async with self._async_session() as db:
            async with db.begin():
                engagement = (await db.execute(
                    select(SessionStateORM).where(
                        SessionStateORM.session_id == task.engagement_id,
                    ).with_for_update()
                )).scalar_one_or_none()
                if engagement is None:
                    raise PermissionError("Terminal engagement not found")
                row = (await db.execute(
                    select(TaskORM).where(
                        TaskORM.id == task.id,
                        TaskORM.engagement_id == task.engagement_id,
                    ).with_for_update()
                )).scalar_one_or_none()
                if row is None or row.status != "running":
                    return False
                if (
                    row.assigned_agent_id != task.assigned_agent_id
                    or row.type != task.type or row.agent_type != task.agent_type.value
                    or row.flow_id != task.flow_id or row.subtask_id != task.subtask_id
                    or row.parent_task_id != task.parent_task_id
                    or not isinstance(row.payload, dict)
                    or task_payload_sha256(row.payload) != task_payload_sha256(task.payload)
                ):
                    return False
                # A valid execution may complete after revocation. Preserve a
                # terminal receipt for forensics but do not represent revoked
                # authorization as a current permission for NEW downstream work.
                row.status = outcome
                row.result = result
                row.completed_at = datetime.utcnow()
                await SupervisionStore._append_event(
                    db, task.engagement_id, task.id,
                    "task.local_terminal", "scheduler",
                    {"task_id": task.id, "outcome": outcome},
                    idempotency_key="local-task-terminal:" + task.id,
                )
        return True

    async def admit_signed_replay_observation_pair(
        self, parent: Task, observations: List[Task], *, existing_only: bool = False
    ) -> List[str]:
        """Atomically register both human-gated replay observations in PostgreSQL.

        A source-only committed Task is NOT a successful paired admission. The
        engagement row serializes two replicas and signed revocation; there is
        deliberately no Redis, graph or remote tool call inside the transaction.
        Existing incomplete *legacy* pairs require explicit reconciliation,
        never a blind admission/replay of their missing peer.
        """
        from ai_osop.core.signed_replay_comparison import (
            observation_subtask_id,
            observation_task_id,
        )
        from ai_osop.memory.authorization_store import guard_sql
        from ai_osop.memory.supervision_store import SupervisionStore
        from ai_osop.safety.approval_binding import matches_pinned_payload
        from ai_osop.safety.scope import ScopeEnforcer, validate_payload_targets

        if (
            not isinstance(parent, Task)
            or len(observations) != 2
            or not parent.flow_id
            or not parent.parent_task_id
            or parent.type != "replay_for_diff_auth"
            or parent.status not in ({"running", "completed"} if existing_only else {"running"})
            or any(not isinstance(child, Task) for child in observations)
        ):
            raise PermissionError("Signed replay pair is not well formed")
        version = parent.payload.get("_authorization_version")
        revision = parent.payload.get("_flow_revision")
        workflow = parent.payload.get("workflow_id")
        source_label = parent.payload.get("source_user_label")
        target_label = parent.payload.get("target_user_label")
        if (
            type(version) is not int
            or version < 1
            or type(revision) is not int
            or revision < 0
            or not isinstance(workflow, str)
            or not isinstance(source_label, str)
            or not isinstance(target_label, str)
            or source_label == target_label
            or parent.payload.get("operator_approved") is not True
            or not isinstance(parent.payload.get("approval_id"), str)
        ):
            raise PermissionError("Signed replay parent does not bind approved identities")

        source, target = observations
        for child, role, label in (
            (source, "source", source_label),
            (target, "target", target_label),
        ):
            payload = child.payload
            if (
                not isinstance(payload, dict)
                or child.id
                != observation_task_id(
                    parent.engagement_id,
                    parent.id,
                    parent.flow_id,
                    workflow,
                    payload.get("step_id"),
                    label,
                    version,
                )
                or child.engagement_id != parent.engagement_id
                or child.parent_task_id != parent.id
                or child.flow_id != parent.flow_id
                or child.subtask_id not in (
                    {observation_subtask_id(child.id), None}
                    if existing_only
                    else {observation_subtask_id(child.id)}
                )
                or child.type != "navigate"
                or child.agent_type.value != "workflow"
                or child.status != "pending"
                or child.approval_required is not True
                or child.max_retries != 0
                or child.retry_count != 0
                or child.dependencies != [parent.id]
                or child.result is not None
                or child.assigned_agent_id is not None
                or payload.get("_comparison_role") != role
                or payload.get("user_label") != label
                or payload.get("target_user_label") != target_label
                or payload.get("source_user_label") != source_label
                or payload.get("workflow_id") != workflow
                or payload.get("method") != "GET"
                or payload.get("_authorization_version") != version
                or payload.get("_flow_revision") != revision
                or payload.get("capture_semantics") is not True
                or "operator_approved" in payload
                or "approval_id" in payload
            ):
                raise PermissionError(
                    "Signed replay observation has conflicting immutable identity"
                )
        if (
            source.id == target.id
            or source.payload.get("step_id") != target.payload.get("step_id")
            or source.payload.get("url") != target.payload.get("url")
            or not isinstance(source.payload.get("url"), str)
            or (source.subtask_id is None) != (target.subtask_id is None)
        ):
            raise PermissionError("Signed replay observations must bind one shared GET")

        async with self._async_session() as db, db.begin():
            engagement = (
                await db.execute(
                    select(SessionStateORM)
                    .where(SessionStateORM.session_id == parent.engagement_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if engagement is None or engagement.phase in {"halted", "completed"}:
                raise PermissionError("Replay engagement is not active")
            current = await guard_sql(db, parent.engagement_id, expected_version=version)
            if current.version != version:
                raise PermissionError("Replay signer revision changed")
            flow = (
                await db.execute(
                    select(ExecutionFlowORM)
                    .where(
                        ExecutionFlowORM.id == parent.flow_id,
                        ExecutionFlowORM.engagement_id == parent.engagement_id,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            durable_parent = (
                await db.execute(
                    select(TaskORM)
                    .where(
                        TaskORM.id == parent.id,
                        TaskORM.engagement_id == parent.engagement_id,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            original = (
                await db.execute(
                    select(TaskORM)
                    .where(
                        TaskORM.id == parent.parent_task_id,
                        TaskORM.engagement_id == parent.engagement_id,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            approval = (
                await db.execute(
                    select(ApprovalRequestORM)
                    .where(
                        ApprovalRequestORM.id == parent.payload["approval_id"],
                        ApprovalRequestORM.engagement_id == parent.engagement_id,
                        ApprovalRequestORM.task_id == parent.id,
                        ApprovalRequestORM.status == "approved",
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if (
                flow is None
                or flow.status not in {"pending", "running"}
                or flow.revision != revision
                or durable_parent is None
                or durable_parent.status
                not in ({"running", "completed"} if existing_only else {"running"})
                or durable_parent.type != parent.type
                or durable_parent.flow_id != parent.flow_id
                or durable_parent.parent_task_id != parent.parent_task_id
                or durable_parent.payload != parent.payload
                or not durable_parent.approval_required
                or approval is None
                or not matches_pinned_payload(approval.evidence, parent.payload)
                or original is None
                or original.status != "completed"
                or original.type != "map_workflow"
                or original.flow_id not in (None, parent.flow_id)
                or not isinstance(original.payload, dict)
                or original.payload.get("_authorization_version") != version
                or original.payload.get("user_label") != source_label
                or not isinstance(original.result, dict)
                or original.result.get("workflow_id") != workflow
                or original.result.get("status") not in {"success", "workflow_recorded"}
            ):
                raise PermissionError("Replay parent, Flow, original or human grant changed")
            from ai_osop.core.models import ScopeDefinition

            scope = ScopeEnforcer(ScopeDefinition.model_validate(engagement.scope))
            scope.validate_time_window()
            validate_payload_targets(scope, {"url": source.payload["url"]}, require_target=True)
            validate_payload_targets(
                scope, {"url": original.payload.get("url")}, require_target=True
            )

            existing = (
                (
                    await db.execute(
                        select(TaskORM)
                        .where(TaskORM.id.in_([source.id, target.id]))
                        .with_for_update()
                    )
                )
                .scalars()
                .all()
            )
            if existing:
                if len(existing) != 2:
                    raise PermissionError(
                        "Partially admitted legacy replay pair needs operator review"
                    )
                by_id = {record.id: record for record in existing}
                for child in observations:
                    row = by_id.get(child.id)
                    if (
                        row is None
                        or row.type != child.type
                        or row.agent_type != child.agent_type.value
                        or row.engagement_id != child.engagement_id
                        or row.flow_id != child.flow_id
                        or row.subtask_id != child.subtask_id
                        or row.parent_task_id != child.parent_task_id
                        or row.dependencies != child.dependencies
                        or row.payload != child.payload
                        and not (
                            isinstance(row.payload, dict)
                            and row.payload.get("operator_approved") is True
                            and {
                                k: v
                                for k, v in row.payload.items()
                                if k not in {"approval_id", "operator_approved"}
                            }
                            == child.payload
                        )
                        or row.approval_required is not True
                        or row.max_retries != 0
                    ):
                        raise PermissionError("Existing replay pair identity has changed")
                return []

            if existing_only:
                raise PermissionError("Replay pair outbox references missing TaskORM children")

            for child in observations:
                # The Flow->Task->Subtask->Action provenance is committed in
                # the same PostgreSQL transaction as BOTH TaskORM children.
                # Never create an orphan subtask before child admission.
                db.add(
                    ExecutionSubtaskORM(
                        id=child.subtask_id,
                        engagement_id=child.engagement_id,
                        flow_id=child.flow_id,
                        task_id=parent.id,
                        title="Signed replay " + child.payload["_comparison_role"] + " observation",
                        description="Read-only, individually approved cross-identity GET observation",
                        task_type="navigate",
                        agent_type=child.agent_type.value,
                        approval_required=True,
                        order=0 if child.payload["_comparison_role"] == "source" else 1,
                        dependencies=[],
                        status="dispatched",
                        refinement_count=0,
                        result_summary=None,
                        execution_task_id=child.id,
                        created_at=child.created_at,
                        updated_at=child.created_at,
                    )
                )
                db.add(
                    TaskORM(
                        id=child.id,
                        type=child.type,
                        priority=child.priority,
                        agent_type=child.agent_type.value,
                        payload=child.payload,
                        dependencies=child.dependencies,
                        max_retries=child.max_retries,
                        timeout_seconds=child.timeout_seconds,
                        scope_check=child.scope_check,
                        approval_required=True,
                        status="pending",
                        result=None,
                        retry_count=0,
                        created_at=child.created_at,
                        started_at=None,
                        completed_at=None,
                        engagement_id=child.engagement_id,
                        assigned_agent_id=None,
                        flow_id=child.flow_id,
                        subtask_id=child.subtask_id,
                        parent_task_id=child.parent_task_id,
                    )
                )
            await db.flush()
            await SupervisionStore._append_event(
                db,
                parent.engagement_id,
                parent.id,
                "replay.pair_admitted",
                "scheduler",
                {
                    "source_task_id": source.id,
                    "target_task_id": target.id,
                    "workflow_id": workflow,
                    "step_id": source.payload["step_id"],
                },
                idempotency_key="replay-pair-admitted:" + source.id + ":" + target.id,
            )
        return [source.id, target.id]

    async def store_task(self, task: Task) -> None:
        """Store a snapshot only if the durable task can make this transition.

        PostgreSQL evaluates the identity, immutable payload, ownership and
        source-state predicates under the conflicting row's UPSERT lock. The
        generic writer never creates a new signed approval, starts a claimed
        task, settles a Temporal dispatch, or resolves an UNKNOWN outcome.
        Signed dispatch/approval and planner transitions have dedicated ledger
        methods; unsigned legacy manual scheduler tasks keep their old path.
        """
        if not isinstance(task, Task) or not isinstance(task.payload, dict):
            raise ValueError("Expected a valid task snapshot")
        signed = type(task.payload.get("_authorization_version")) is int
        preapproved = signed and task.approval_required and (
            task.payload.get("operator_approved") is True
            or task.payload.get("approval_id") is not None
        )
        terminal = {"completed", "failed", "cancelled", "dispatch_unknown"}
        if task.status not in {
            "pending", "planned", "awaiting_approval", "running", "scheduled",
            "dispatching", *terminal,
        }:
            raise PermissionError("Unsupported generic task status")
        if (signed and task.status not in {"pending", "planned"}) or preapproved:
            # An existing signed record can still be settled below via its
            # owner. An INSERT must never forge an executing/approved task.
            allow_insert = False
        else:
            allow_insert = True

        # This equality is a PostgreSQL JSONB comparison of parsed JSON values;
        # JSON lacks a usable equality operator. Even nested target/options,
        # signed authorization version and approval grant must match exactly.
        identity = and_(
            TaskORM.engagement_id == task.engagement_id,
            TaskORM.type == task.type,
            TaskORM.agent_type == task.agent_type.value,
            TaskORM.priority == task.priority,
            TaskORM.max_retries == task.max_retries,
            TaskORM.timeout_seconds == task.timeout_seconds,
            TaskORM.scope_check == task.scope_check,
            TaskORM.approval_required == task.approval_required,
            TaskORM.created_at == task.created_at,
            TaskORM.flow_id.is_not_distinct_from(task.flow_id),
            TaskORM.subtask_id.is_not_distinct_from(task.subtask_id),
            TaskORM.parent_task_id.is_not_distinct_from(task.parent_task_id),
            cast(TaskORM.payload, JSONB) == cast(task.payload, JSONB),
            cast(TaskORM.dependencies, JSONB) == cast(task.dependencies, JSONB),
            TaskORM.retry_count <= task.retry_count,
        )
        same_owner = and_(
            TaskORM.assigned_agent_id.isnot(None),
            TaskORM.assigned_agent_id == task.assigned_agent_id,
        )
        if task.status in {"pending", "planned"}:
            permitted = TaskORM.status.in_(["pending", "planned"])
        elif task.status == "awaiting_approval":
            permitted = and_(
                ~cast(TaskORM.payload, JSONB).has_key("_authorization_version"),
                TaskORM.approval_required.is_(True),
                TaskORM.status.in_(["pending", "awaiting_approval"]),
            )
        elif task.status == "running":
            permitted = or_(
                and_(TaskORM.status == "running", same_owner),
                and_(
                    ~cast(TaskORM.payload, JSONB).has_key("_authorization_version"),
                    TaskORM.status.in_(["pending", "awaiting_approval"]),
                ),
            )
        elif task.status in terminal:
            permitted = or_(
                and_(TaskORM.status == "running", same_owner),
                and_(
                    ~cast(TaskORM.payload, JSONB).has_key("_authorization_version"),
                    TaskORM.status.in_(["pending", "awaiting_approval"]),
                    task.status in {"failed", "cancelled"},
                ),
            )
        else:
            # Temporal scheduled/dispatching may only be committed using
            # claim_temporal_dispatch + settle_temporal_dispatch.
            permitted = TaskORM.status == "__no_generic_temporal_transition__"
        mutable_state = and_(identity, permitted)
        with trace_span(
            "postgres.store_task",
            attributes={"ai_osop.task_id": task.id, "ai_osop.engagement_id": task.engagement_id},
        ):
            # Commit the durable tier first. Redis outages must not lose the
            # record needed for recovery on the next process startup.
            async with self._async_session() as session:
                stmt = (
                    insert(TaskORM)
                    .values(
                        id=task.id,
                        type=task.type,
                        priority=task.priority,
                        agent_type=task.agent_type.value,
                        payload=task.payload,
                        dependencies=task.dependencies,
                        max_retries=task.max_retries,
                        timeout_seconds=task.timeout_seconds,
                        scope_check=task.scope_check,
                        approval_required=task.approval_required,
                        status=task.status,
                        result=task.result,
                        retry_count=task.retry_count,
                        created_at=task.created_at,
                        started_at=task.started_at,
                        completed_at=task.completed_at,
                        engagement_id=task.engagement_id,
                        assigned_agent_id=task.assigned_agent_id,
                        flow_id=task.flow_id,
                        subtask_id=task.subtask_id,
                        parent_task_id=task.parent_task_id,
                    )
                    .on_conflict_do_update(
                        index_elements=["id"],
                        set_={
                            "status": task.status,
                            "result": task.result,
                            # Approval resolution changes these fields after
                            # insertion; Temporal workers must load the latest
                            # approved payload from the durable database.
                            "payload": task.payload,
                            "dependencies": task.dependencies,
                            "approval_required": task.approval_required,
                            "retry_count": task.retry_count,
                            # A local claim owns the original start timestamp.
                            # A second snapshot must not change its provenance.
                            "started_at": case(
                                (and_(
                                    TaskORM.status.in_(["pending", "awaiting_approval"]),
                                    ~cast(TaskORM.payload, JSONB).has_key("_authorization_version"),
                                 ),
                                 task.started_at),
                                else_=TaskORM.started_at,
                            ),
                            "completed_at": task.completed_at,
                            "assigned_agent_id": case(
                                (and_(
                                    TaskORM.status.in_(["pending", "awaiting_approval"]),
                                    ~cast(TaskORM.payload, JSONB).has_key("_authorization_version"),
                                 ),
                                 task.assigned_agent_id),
                                else_=TaskORM.assigned_agent_id,
                            ),
                            "flow_id": task.flow_id,
                            "subtask_id": task.subtask_id,
                            "parent_task_id": task.parent_task_id,
                        },
                        # The UPSERT's row conflict lock provides the CAS even
                        # when two replicas submit concurrent stale snapshots.
                        where=mutable_state,
                    )
                )
                if not allow_insert:
                    # Signed execution/terminal records must have been
                    # admitted already. INSERT...ON CONFLICT otherwise creates
                    # a fake claimed Task when no record exists.
                    stmt = update(TaskORM).where(
                        TaskORM.id == task.id, mutable_state,
                    ).values(
                        status=task.status, result=task.result,
                        retry_count=task.retry_count,
                        completed_at=task.completed_at,
                    )
                persisted = await session.execute(stmt)
                await session.commit()
            if persisted.rowcount == 0:
                # Also skip writing a stale Redis shadow over a more recent
                # authoritative PostgreSQL terminal record.
                logger.warning(
                    "stale_task_transition_rejected", task_id=task.id
                )
                return
            try:
                await self.store_hot(f"task:{task.id}", task.model_dump(), ttl=86400 * 7)
            except Exception:
                logger.warning("redis_task_cache_write_failed", task_id=task.id)

    async def load_task(self, task_id: str) -> Optional[Task]:
        """Load task from hot tier, fallback to warm."""
        try:
            data = await self.retrieve_hot(f"task:{task_id}")
        except Exception:
            logger.warning("redis_task_cache_read_failed", task_id=task_id)
            data = None
        if data:
            return Task(**data)
        return await self.load_task_authoritative(task_id)

    async def load_task_authoritative(self, task_id: str) -> Optional[Task]:
        """Read PostgreSQL directly for scheduling, safety and recovery.

        Redis is an optimization and can lag across replicas. It must never
        authorize Temporal dispatch, cancellation or a terminal replay.
        """
        async with self._async_session() as session:
            result = await session.execute(select(TaskORM).where(TaskORM.id == task_id))
            orm = result.scalar_one_or_none()
            if orm:
                from ai_osop.core.config import AgentType

                return Task(
                    id=orm.id,
                    type=orm.type,
                    priority=orm.priority,
                    agent_type=AgentType(orm.agent_type),
                    payload=orm.payload,
                    dependencies=orm.dependencies,
                    max_retries=orm.max_retries,
                    timeout_seconds=orm.timeout_seconds,
                    scope_check=orm.scope_check,
                    approval_required=orm.approval_required,
                    status=orm.status,
                    result=orm.result,
                    retry_count=orm.retry_count,
                    created_at=orm.created_at,
                    started_at=orm.started_at,
                    completed_at=orm.completed_at,
                    engagement_id=orm.engagement_id,
                    assigned_agent_id=orm.assigned_agent_id,
                    flow_id=orm.flow_id,
                    subtask_id=orm.subtask_id,
                    parent_task_id=orm.parent_task_id,
                )
        return None

    async def list_recoverable_signed_chain_parents(
        self, *, limit: int = 500, after_id: Optional[str] = None
    ) -> List[Dict[str, str]]:
        """Find completed authenticated-chain parents with no admitted SQL child.

        Neo4j is a derived projection and may lack the parent altogether after
        a worker crash. Include older children whose parent_task_id was never
        populated but whose dependencies already refer to this task: these
        must NOT be silently duplicated by modern deterministic recovery.
        Returned rows are only hints; callers re-read TaskORM and current ROE.
        """
        from sqlalchemy.orm import aliased

        bounded = max(1, min(int(limit), 500))
        if after_id is not None and (
            not isinstance(after_id, str)
            or not re.fullmatch(r"task-[A-Za-z0-9._-]{1,59}", after_id)
        ):
            raise ValueError("Invalid signed recovery cursor")
        child = aliased(TaskORM)
        admitted_child = (
            select(child.id)
            .where(
                child.engagement_id == TaskORM.engagement_id,
                or_(
                    child.parent_task_id == TaskORM.id,
                    cast(child.dependencies, JSONB).contains(
                        func.jsonb_build_array(TaskORM.id)
                    ),
                ),
            )
            .exists()
        )
        conditions = [
            TaskORM.status == "completed",
            TaskORM.type.in_([
                "map_workflow",
                "capture_authenticated_surface",
                "extract_har_api_inventory",
            ]),
            ~admitted_child,
        ]
        if after_id is not None:
            conditions.append(TaskORM.id > after_id)
        stmt = (
            select(TaskORM.id, TaskORM.type, TaskORM.engagement_id)
            .where(*conditions)
            # Keyset pagination cannot use a completed_at sort followed by
            # an ID-only cursor. Order by the immutable primary key instead;
            # every bounded page advances even if the first 500 parents are
            # permanently ineligible for a successor.
            .order_by(TaskORM.id)
            .limit(bounded)
        )
        async with self._async_session() as db:
            rows = (await db.execute(stmt)).all()
        return [
            {"id": row.id, "type": row.type, "engagement_id": row.engagement_id}
            for row in rows
        ]

    async def load_all_active_tasks(self) -> List[Task]:
        """Load all non-completed tasks from warm tier for recovery."""
        from ai_osop.core.config import AgentType

        async with self._async_session() as session:
            result = await session.execute(
                select(TaskORM).where(TaskORM.status.notin_(["completed", "failed", "cancelled"]))
            )
            tasks = []
            for orm in result.scalars():
                tasks.append(
                    Task(
                        id=orm.id,
                        type=orm.type,
                        priority=orm.priority,
                        agent_type=AgentType(orm.agent_type),
                        payload=orm.payload,
                        dependencies=orm.dependencies,
                        max_retries=orm.max_retries,
                        timeout_seconds=orm.timeout_seconds,
                        scope_check=orm.scope_check,
                        approval_required=orm.approval_required,
                        status=orm.status,
                        result=orm.result,
                        retry_count=orm.retry_count,
                        created_at=orm.created_at,
                        started_at=orm.started_at,
                        completed_at=orm.completed_at,
                        engagement_id=orm.engagement_id,
                        assigned_agent_id=orm.assigned_agent_id,
                        flow_id=orm.flow_id,
                        subtask_id=orm.subtask_id,
                        parent_task_id=orm.parent_task_id,
                    )
                )
            return tasks

    async def list_flow_tasks(self, flow_id: str, limit: int = 100) -> List[Task]:
        """Retrieve durable top-level objectives after API/worker restarts."""
        from ai_osop.core.config import AgentType

        async with self._async_session() as session:
            result = await session.execute(
                select(TaskORM)
                .where(TaskORM.flow_id == flow_id, TaskORM.parent_task_id.is_(None))
                .order_by(TaskORM.created_at.asc())
                .limit(max(1, min(limit, 100)))
            )
            return [
                Task(
                    id=row.id,
                    type=row.type,
                    priority=row.priority,
                    agent_type=AgentType(row.agent_type),
                    payload=row.payload or {},
                    dependencies=row.dependencies or [],
                    max_retries=row.max_retries,
                    timeout_seconds=row.timeout_seconds,
                    scope_check=row.scope_check,
                    approval_required=row.approval_required,
                    status=row.status,
                    result=row.result,
                    retry_count=row.retry_count,
                    created_at=row.created_at,
                    started_at=row.started_at,
                    completed_at=row.completed_at,
                    engagement_id=row.engagement_id,
                    assigned_agent_id=row.assigned_agent_id,
                    flow_id=row.flow_id,
                    subtask_id=row.subtask_id,
                    parent_task_id=row.parent_task_id,
                )
                for row in result.scalars()
            ]

    # ============== DURABLE FLOW / SUBTASK / ACTION LINEAGE ==============

    async def is_task_approved(self, task_id: str, engagement_id: str, approval_id: str) -> bool:
        """Verify durable approval *and* immutable nested task payload binding."""
        from ai_osop.safety.approval_binding import matches_pinned_payload
        async with self._async_session() as session:
            result = await session.execute(
                select(ApprovalRequestORM, TaskORM).join(
                    TaskORM,
                    (TaskORM.id == ApprovalRequestORM.task_id)
                    & (TaskORM.engagement_id == ApprovalRequestORM.engagement_id),
                ).where(
                    ApprovalRequestORM.id == approval_id,
                    ApprovalRequestORM.task_id == task_id,
                    ApprovalRequestORM.engagement_id == engagement_id,
                    ApprovalRequestORM.status == "approved",
                )
            )
            row = result.one_or_none()
            return (
                row is not None and row[1].approval_required is True
                and isinstance(row[1].payload, dict)
                and row[1].payload.get("approval_id") == approval_id
                and row[1].payload.get("operator_approved") is True
                and matches_pinned_payload(row[0].evidence, row[1].payload)
            )

    async def store_flow(self, flow: FlowRecord) -> None:
        """Idempotently persist an engagement-owned flow record."""
        async with self._async_session() as session:
            stmt = (
                insert(ExecutionFlowORM)
                .values(**flow.model_dump())
                .on_conflict_do_update(
                    index_elements=["id"],
                    set_={
                        "status": flow.status,
                        "revision": flow.revision,
                        "updated_at": flow.updated_at,
                    },
                )
            )
            await session.execute(stmt)
            await session.commit()

    async def create_flow_if_absent(self, flow: FlowRecord) -> bool:
        """Insert a new flow only; never overwrite an existing operator decision."""
        async with self._async_session() as session:
            result = await session.execute(
                insert(ExecutionFlowORM)
                .values(**flow.model_dump())
                .on_conflict_do_nothing(index_elements=["id"])
                .returning(ExecutionFlowORM.id)
            )
            created = result.scalar_one_or_none() == flow.id
            await session.commit()
            return created

    async def create_flow_objective(
        self, flow: FlowRecord, engagement: SessionState, objective: Task
    ) -> Optional[FlowRecord]:
        """Atomically persist a planned objective under current ROE and Flow CAS.

        Lock engagement before Flow, matching planner commit/engagement updates.
        The flow revision bump and objective INSERT commit together; a competing
        pause/cancel/plan revision prevents creating stale orphan objectives.
        No Redis writes occur inside this database transaction.
        """
        from ai_osop.core.exceptions import OutOfScopeError, ScopeValidationError
        from ai_osop.safety.scope import ScopeEnforcer

        if (
            flow.status not in {"pending", "running"}
            or flow.revision < 0
            or engagement.session_id != flow.engagement_id
            or objective.type != "flow_objective"
            or objective.status != "planned"
            or objective.flow_id != flow.id
            or objective.engagement_id != flow.engagement_id
            or objective.parent_task_id is not None
            or objective.subtask_id is not None
        ):
            raise ValueError("Invalid Flow objective or engagement binding")

        async with self._async_session() as session:
            session_result = await session.execute(
                select(SessionStateORM)
                .where(SessionStateORM.session_id == engagement.session_id)
                .with_for_update()
            )
            durable = session_result.scalar_one_or_none()
            if durable is None or durable.phase != engagement.phase or durable.phase in {
                "halted", "completed"
            }:
                return None
            from ai_osop.memory.authorization_store import guard_sql
            from sqlalchemy.ext.asyncio import AsyncSession

            if isinstance(session, AsyncSession):
                await guard_sql(session, engagement.session_id)
            scope = ScopeDefinition.model_validate(durable.scope)
            if (
                scope.model_dump(mode="json") != engagement.scope.model_dump(mode="json")
                or durable.roe != engagement.roe
                or not scope.authorization_ref
                or not (scope.domains or scope.ips)
            ):
                return None
            try:
                ScopeEnforcer(scope).validate_time_window()
            except (OutOfScopeError, ScopeValidationError):
                return None

            flow_result = await session.execute(
                update(ExecutionFlowORM)
                .where(
                    ExecutionFlowORM.id == flow.id,
                    ExecutionFlowORM.engagement_id == flow.engagement_id,
                    ExecutionFlowORM.revision == flow.revision,
                    ExecutionFlowORM.status == flow.status,
                    ExecutionFlowORM.status.in_(["pending", "running"]),
                )
                .values(revision=ExecutionFlowORM.revision + 1, updated_at=datetime.utcnow())
                .returning(*ExecutionFlowORM.__table__.columns)
            )
            row = flow_result.mappings().one_or_none()
            if row is None:
                return None
            await session.execute(
                insert(TaskORM).values(
                    id=objective.id,
                    type=objective.type,
                    priority=objective.priority,
                    agent_type=objective.agent_type.value,
                    payload=objective.payload,
                    dependencies=objective.dependencies,
                    max_retries=objective.max_retries,
                    timeout_seconds=objective.timeout_seconds,
                    scope_check=objective.scope_check,
                    approval_required=objective.approval_required,
                    status=objective.status,
                    result=objective.result,
                    retry_count=objective.retry_count,
                    created_at=objective.created_at,
                    started_at=objective.started_at,
                    completed_at=objective.completed_at,
                    engagement_id=objective.engagement_id,
                    assigned_agent_id=objective.assigned_agent_id,
                    flow_id=objective.flow_id,
                    subtask_id=objective.subtask_id,
                    parent_task_id=objective.parent_task_id,
                )
            )
            await session.commit()
            return FlowRecord(**dict(row))

    async def transition_flow_status(
        self,
        flow_id: str,
        engagement_id: str,
        expected_revision: int,
        allowed_statuses: List[str],
        new_status: str,
    ) -> Optional[FlowRecord]:
        """Atomically transition a flow, rejecting stale replicas and states.

        The status predicate and revision comparison are evaluated in the same
        PostgreSQL UPDATE statement. Concurrent updates serialize on the row
        lock; a losing request returns None without changing either field.
        Keep store_flow's existing upsert behavior for non-control writers.
        """
        if expected_revision < 0 or not allowed_statuses or not new_status:
            raise ValueError("A valid revision, source states and target state are required")
        if new_status in allowed_statuses:
            raise ValueError("A transition must change the flow status")
        async with self._async_session() as session:
            statement = (
                update(ExecutionFlowORM)
                .where(
                    ExecutionFlowORM.id == flow_id,
                    ExecutionFlowORM.engagement_id == engagement_id,
                    ExecutionFlowORM.revision == expected_revision,
                    ExecutionFlowORM.status.in_(allowed_statuses),
                )
                .values(
                    status=new_status,
                    revision=ExecutionFlowORM.revision + 1,
                    updated_at=datetime.utcnow(),
                )
                .returning(*ExecutionFlowORM.__table__.columns)
            )
            if new_status in {"paused", "cancelled"}:
                # Combined with claim_subtask's Flow revision bump, this
                # prevents a late pause/cancel from treating an already
                # claimed step as unsubmitted work.
                active_steps = (
                    select(ExecutionSubtaskORM.id)
                    .where(
                        ExecutionSubtaskORM.flow_id == flow_id,
                        ExecutionSubtaskORM.engagement_id == engagement_id,
                        ExecutionSubtaskORM.status.notin_(
                            ["pending", "completed", "failed", "cancelled"]
                        ),
                    )
                    .exists()
                )
                unresolved_tasks = (
                    select(ExecutionSubtaskORM.id)
                    .outerjoin(TaskORM, TaskORM.id == ExecutionSubtaskORM.execution_task_id)
                    .where(
                        ExecutionSubtaskORM.flow_id == flow_id,
                        ExecutionSubtaskORM.engagement_id == engagement_id,
                        ExecutionSubtaskORM.execution_task_id.is_not(None),
                        (
                            TaskORM.id.is_(None)
                            | TaskORM.status.notin_(["completed", "failed", "cancelled"])
                        ),
                    )
                    .exists()
                )
                statement = statement.where(~active_steps, ~unresolved_tasks)
            result = await session.execute(statement)
            row = result.mappings().one_or_none()
            await session.commit()
            if row is None:
                return None
            return FlowRecord(**dict(row))

    async def commit_flow_refinement(
        self,
        flow: FlowRecord,
        engagement: SessionState,
        expected_subtask_ids: List[str],
        additions: List[SubtaskRecord],
        source: Optional[SubtaskRecord] = None,
        revised_step: Optional[SubtaskRecord] = None,
        activate_flow: bool = True,
    ) -> Optional[FlowRecord]:
        """Atomically apply a planner/operator revision and affected steps.

        Locks the persisted engagement before the flow revision CAS, following
        the same ordering as engagement halt. A concurrent pause/cancel or a
        second planner cannot commit the same revision. Missing/changed state
        returns None with no commit; database errors propagate and roll back.
        No external tools or LLMs run inside this database transaction.
        """
        from ai_osop.core.exceptions import OutOfScopeError, ScopeValidationError
        from ai_osop.safety.scope import ScopeEnforcer

        if not additions and source is None and revised_step is None:
            raise ValueError("Planner commit requires a change")
        if revised_step is not None and (source is not None or additions):
            raise ValueError("Edit one pending step or refine a completed source")
        if (
            flow.revision < 0
            or flow.status not in {"pending", "running"}
            or engagement.session_id != flow.engagement_id
            or len(expected_subtask_ids) != len(set(expected_subtask_ids))
            or len(expected_subtask_ids) + len(additions) > 15
        ):
            raise ValueError("Invalid planner revision, ownership, or step budget")
        if any(
            step.flow_id != flow.id
            or step.engagement_id != flow.engagement_id
            or step.status != "pending"
            or step.order < len(expected_subtask_ids)
            for step in additions
        ):
            raise ValueError("New steps must belong to this flow and be pending")
        if source is not None and (
            source.flow_id != flow.id
            or source.engagement_id != flow.engagement_id
            or source.status != "completed"
            or source.refinement_count >= 3
            or source.id not in expected_subtask_ids
            or not source.execution_task_id
        ):
            raise ValueError("Invalid refinement source")
        if revised_step is not None and (
            revised_step.flow_id != flow.id
            or revised_step.engagement_id != flow.engagement_id
            or revised_step.status != "pending"
            or revised_step.id not in expected_subtask_ids
        ):
            raise ValueError("Invalid pending step revision")

        async with self._async_session() as session:
            # Hold the session row lock through commit so a concurrent halt or
            # scope change using persist_session_state cannot change the ROE
            # between verification and inserting the planned work.
            session_result = await session.execute(
                select(SessionStateORM)
                .where(SessionStateORM.session_id == flow.engagement_id)
                .with_for_update()
            )
            current = session_result.scalar_one_or_none()
            if current is None or current.phase != engagement.phase or current.phase in {
                "halted", "completed"
            }:
                return None
            from ai_osop.memory.authorization_store import guard_sql
            from sqlalchemy.ext.asyncio import AsyncSession

            if isinstance(session, AsyncSession):
                await guard_sql(session, flow.engagement_id)
            scope = ScopeDefinition.model_validate(current.scope)
            if (
                scope.model_dump(mode="json") != engagement.scope.model_dump(mode="json")
                or current.roe != engagement.roe
                or not scope.authorization_ref
                or not (scope.domains or scope.ips)
            ):
                return None
            try:
                ScopeEnforcer(scope).validate_time_window()
            except (OutOfScopeError, ScopeValidationError):
                return None

            # CAS the flow first: row-level PostgreSQL locking serializes
            # competing operator state transitions and planner revisions.
            revision_result = await session.execute(
                update(ExecutionFlowORM)
                .where(
                    ExecutionFlowORM.id == flow.id,
                    ExecutionFlowORM.engagement_id == flow.engagement_id,
                    ExecutionFlowORM.revision == flow.revision,
                    ExecutionFlowORM.status == flow.status,
                )
                .values(
                    revision=ExecutionFlowORM.revision + 1,
                    status=(
                        "running"
                        if activate_flow and flow.status == "pending"
                        else flow.status
                    ),
                    updated_at=datetime.utcnow(),
                )
                .returning(*ExecutionFlowORM.__table__.columns)
            )
            row = revision_result.mappings().one_or_none()
            if row is None:
                return None

            # Detect previously dispatched, inserted or removed plan steps.
            existing_result = await session.execute(
                select(ExecutionSubtaskORM.id).where(ExecutionSubtaskORM.flow_id == flow.id)
            )
            if set(existing_result.scalars()) != set(expected_subtask_ids):
                return None  # uncommitted CAS is rolled back on session exit

            if source is not None:
                # Lock the confirming task row to prevent a retry/recovery
                # process from changing its outcome while the refiner writes
                # follow-up steps based on that execution.
                execution_result = await session.execute(
                    select(TaskORM.id)
                    .where(
                        TaskORM.id == source.execution_task_id,
                        TaskORM.engagement_id == flow.engagement_id,
                        TaskORM.flow_id == flow.id,
                        TaskORM.subtask_id == source.id,
                        TaskORM.status == "completed",
                    )
                    .with_for_update(read=True)
                )
                if execution_result.scalar_one_or_none() != source.execution_task_id:
                    return None
                source_result = await session.execute(
                    update(ExecutionSubtaskORM)
                    .where(
                        ExecutionSubtaskORM.id == source.id,
                        ExecutionSubtaskORM.flow_id == flow.id,
                        ExecutionSubtaskORM.engagement_id == flow.engagement_id,
                        ExecutionSubtaskORM.status == "completed",
                        ExecutionSubtaskORM.refinement_count == source.refinement_count,
                        ExecutionSubtaskORM.execution_task_id == source.execution_task_id,
                    )
                    .values(
                        refinement_count=source.refinement_count + 1,
                        updated_at=datetime.utcnow(),
                    )
                    .returning(ExecutionSubtaskORM.id)
                )
                if source_result.scalar_one_or_none() != source.id:
                    return None

            if revised_step is not None:
                # A scheduler may claim the step concurrently without touching
                # the Flow row. Its status predicate prevents editing a step
                # already accepted for external execution.
                edited = await session.execute(
                    update(ExecutionSubtaskORM)
                    .where(
                        ExecutionSubtaskORM.id == revised_step.id,
                        ExecutionSubtaskORM.flow_id == flow.id,
                        ExecutionSubtaskORM.engagement_id == flow.engagement_id,
                        ExecutionSubtaskORM.task_id == revised_step.task_id,
                        ExecutionSubtaskORM.status == "pending",
                    )
                    .values(
                        title=revised_step.title,
                        description=revised_step.description,
                        updated_at=datetime.utcnow(),
                    )
                    .returning(ExecutionSubtaskORM.id)
                )
                if edited.scalar_one_or_none() != revised_step.id:
                    return None

            for step in additions:
                values = step.model_dump()
                values["agent_type"] = step.agent_type.value
                # Plain INSERT intentionally raises on ID collisions; that
                # aborts the whole transaction rather than silently dropping
                # a dependency or reporting a partial plan as committed.
                await session.execute(insert(ExecutionSubtaskORM).values(**values))
            await session.commit()
            return FlowRecord(**dict(row))

    async def load_flow(self, flow_id: str) -> Optional[FlowRecord]:
        async with self._async_session() as session:
            result = await session.execute(
                select(ExecutionFlowORM).where(ExecutionFlowORM.id == flow_id)
            )
            row = result.scalar_one_or_none()
            return (
                FlowRecord(**{key: getattr(row, key) for key in FlowRecord.model_fields})
                if row is not None
                else None
            )

    async def list_flows(self, engagement_id: str, limit: int = 100) -> List[FlowRecord]:
        async with self._async_session() as session:
            result = await session.execute(
                select(ExecutionFlowORM)
                .where(ExecutionFlowORM.engagement_id == engagement_id)
                .order_by(ExecutionFlowORM.created_at.desc())
                .limit(max(1, min(limit, 100)))
            )
            return [
                FlowRecord(**{key: getattr(row, key) for key in FlowRecord.model_fields})
                for row in result.scalars()
            ]

    async def store_subtask(self, subtask: SubtaskRecord) -> None:
        """Write a subtask without undoing a committed execution reservation.

        A stale planner, callback or operator response cannot clear an already
        linked execution_task_id or reset a claimed step to pending. Stronger
        Flow-CAS dispatch paths write the step and Task in one transaction.
        """
        allowed_from = {
            "pending": ["pending"],
            "dispatched": ["pending", "dispatched"],
            "running": ["dispatched", "running"],
            "dispatch_unknown": ["pending", "dispatched", "running", "dispatch_unknown"],
            "completed": ["pending", "dispatched", "running", "dispatch_unknown", "completed"],
            "failed": ["pending", "dispatched", "running", "dispatch_unknown", "failed"],
            "cancelled": ["pending", "dispatched", "running", "dispatch_unknown", "cancelled"],
        }
        if subtask.status not in allowed_from:
            raise MemoryException("Subtask transition state is unrecognized")
        async with self._async_session() as session:
            stmt = (
                insert(ExecutionSubtaskORM)
                .values(**subtask.model_dump())
                .on_conflict_do_update(
                    index_elements=["id"],
                    set_={
                        "title": subtask.title,
                        "description": subtask.description,
                        "task_type": subtask.task_type,
                        "agent_type": subtask.agent_type.value,
                        "approval_required": subtask.approval_required,
                        "order": subtask.order,
                        "dependencies": subtask.dependencies,
                        "status": subtask.status,
                        "refinement_count": subtask.refinement_count,
                        "result_summary": subtask.result_summary,
                        "execution_task_id": subtask.execution_task_id,
                        "updated_at": subtask.updated_at,
                    },
                    where=and_(
                        ExecutionSubtaskORM.engagement_id == subtask.engagement_id,
                        ExecutionSubtaskORM.flow_id == subtask.flow_id,
                        ExecutionSubtaskORM.task_id == subtask.task_id,
                        ExecutionSubtaskORM.status.in_(allowed_from[subtask.status]),
                        or_(
                            ExecutionSubtaskORM.execution_task_id.is_(None),
                            ExecutionSubtaskORM.execution_task_id == subtask.execution_task_id,
                        ),
                        or_(
                            ExecutionSubtaskORM.status == "pending",
                            and_(
                                ExecutionSubtaskORM.task_type == subtask.task_type,
                                ExecutionSubtaskORM.agent_type == subtask.agent_type.value,
                                ExecutionSubtaskORM.approval_required == subtask.approval_required,
                            ),
                        ),
                    ),
                )
            )
            persisted = await session.execute(stmt)
            if persisted.rowcount == 0:
                raise MemoryException("Subtask has changed; stale write refused")
            await session.commit()

    async def list_subtasks(
        self, flow_id: str, task_id: Optional[str] = None, limit: int = 100
    ) -> List[SubtaskRecord]:
        async with self._async_session() as session:
            stmt = select(ExecutionSubtaskORM).where(ExecutionSubtaskORM.flow_id == flow_id)
            if task_id is not None:
                stmt = stmt.where(ExecutionSubtaskORM.task_id == task_id)
            result = await session.execute(
                stmt.order_by(ExecutionSubtaskORM.order, ExecutionSubtaskORM.created_at).limit(
                    max(1, min(limit, 100))
                )
            )
            return [
                SubtaskRecord(**{key: getattr(row, key) for key in SubtaskRecord.model_fields})
                for row in result.scalars()
            ]

    async def claim_subtask(
        self,
        subtask_id: str,
        engagement_id: str,
        *,
        flow: Optional[FlowRecord] = None,
        engagement: Optional[SessionState] = None,
        subtask: Optional[SubtaskRecord] = None,
        payload: Optional[Dict[str, Any]] = None,
        execution_task: Optional[Task] = None,
    ) -> bool:
        """Claim Flow work with engagement+Flow locks, revising Flow atomically.

        New Flow dispatch callers must supply all four snapshots. The legacy
        two-argument call is retained for compatibility but excludes persisted
        Flow subtasks, so it cannot bypass Flow/ROE/window checks.

        Engagement lock -> Flow lock -> subtask claim -> Flow revision bump
        are in ONE PostgreSQL transaction. When execution_task is supplied,
        its immutable Task row, the subtask lineage, and a dispatch-intent
        event/outbox are committed in that SAME transaction. Queue delivery
        happens only afterwards and can be recovered from the durable row.
        """
        from ai_osop.core.config import AgentType
        from ai_osop.core.exceptions import OutOfScopeError, ScopeValidationError
        from ai_osop.safety.scope import (
            ScopeEnforcer, action_requires_approval, validate_payload_targets,
        )

        snapshots = (flow, engagement, subtask, payload)
        if all(item is None for item in snapshots):
            if execution_task is not None:
                raise ValueError("Execution task requires signed Flow snapshots")
            async with self._async_session() as session:
                from ai_osop.memory.authorization_store import guard_sql
                from sqlalchemy.ext.asyncio import AsyncSession

                if isinstance(session, AsyncSession):
                    await guard_sql(session, engagement_id)
                result = await session.execute(
                    update(ExecutionSubtaskORM)
                    .where(
                        ExecutionSubtaskORM.id == subtask_id,
                        ExecutionSubtaskORM.engagement_id == engagement_id,
                        ExecutionSubtaskORM.flow_id.is_(None),
                        ExecutionSubtaskORM.status == "pending",
                    )
                    .values(status="dispatched", updated_at=datetime.utcnow())
                )
                await session.commit()
                return bool(result.rowcount == 1)
        if any(item is None for item in snapshots):
            raise ValueError("Flow claims require Flow, engagement, subtask and payload")
        if (
            flow.engagement_id != engagement_id
            or engagement.session_id != engagement_id
            or subtask.engagement_id != engagement_id
            or subtask.flow_id != flow.id
            or subtask.id != subtask_id
            or flow.revision < 0
            or flow.status not in {"pending", "running"}
            or subtask.status != "pending"
        ):
            return False

        if execution_task is not None:
            if (
                not isinstance(execution_task, Task)
                or execution_task.engagement_id != engagement_id
                or execution_task.flow_id != flow.id
                or execution_task.subtask_id != subtask_id
                or execution_task.parent_task_id != subtask.task_id
                or execution_task.type != subtask.task_type
                or execution_task.agent_type != subtask.agent_type
                or execution_task.status != "pending"
                or not isinstance(execution_task.payload, dict)
                or execution_task.payload != payload
                or any(key in payload for key in (
                    "operator_approved", "approval_id", "_authorization_version"
                ))
                or len(execution_task.id) > 64
            ):
                return False

        async with self._async_session() as session:
            locked_engagement = await session.execute(
                select(SessionStateORM)
                .where(SessionStateORM.session_id == engagement_id)
                .with_for_update()
            )
            current = locked_engagement.scalar_one_or_none()
            if current is None or current.phase != engagement.phase or current.phase in {
                "halted", "completed"
            }:
                return False
            from ai_osop.memory.authorization_store import guard_sql
            from sqlalchemy.ext.asyncio import AsyncSession

            signed = await guard_sql(session, engagement_id) if isinstance(session, AsyncSession) else None
            scope = ScopeDefinition.model_validate(current.scope)
            if (
                scope.model_dump(mode="json") != engagement.scope.model_dump(mode="json")
                or current.roe != engagement.roe
                or not scope.authorization_ref
                or not (scope.domains or scope.ips)
            ):
                return False
            try:
                enforcer = ScopeEnforcer(scope)
                enforcer.validate_time_window()
                validate_payload_targets(
                    enforcer,
                    payload,
                    require_target=subtask.agent_type in {
                        AgentType.RECON, AgentType.VULN_ANALYSIS,
                    },
                )
            except (ScopeValidationError, OutOfScopeError):
                return False

            if execution_task is not None:
                if signed is None or type(signed.version) is not int:
                    # Never persist a new executable task under a mock or
                    # unverifiable authorization in the production admission.
                    return False
                if not execution_task.scope_check or not execution_task.approval_required and (
                    subtask.approval_required
                    or subtask.agent_type == AgentType.EXPLOIT_VALIDATION
                    or action_requires_approval(subtask.task_type, scope)
                ):
                    return False
                # Reject stale/unconfirmed dependency snapshots while holding
                # the Flow lock. The execution DAG cannot be substituted after
                # the operator has submitted the dispatch request.
                expected_dependencies = []
                if subtask.dependencies:
                    result = await session.execute(
                        select(ExecutionSubtaskORM).where(
                            ExecutionSubtaskORM.id.in_(subtask.dependencies),
                            ExecutionSubtaskORM.flow_id == flow.id,
                            ExecutionSubtaskORM.task_id == subtask.task_id,
                            ExecutionSubtaskORM.engagement_id == engagement_id,
                        ).with_for_update()
                    )
                    parents = {row.id: row for row in result.scalars()}
                    if any(
                        parent not in parents
                        or parents[parent].status != "completed"
                        or not parents[parent].execution_task_id
                        for parent in subtask.dependencies
                    ):
                        return False
                    expected_dependencies = [
                        parents[parent].execution_task_id for parent in subtask.dependencies
                    ]
                if execution_task.dependencies != expected_dependencies:
                    return False
                execution_task.payload["_authorization_version"] = signed.version

            flow_result = await session.execute(
                select(ExecutionFlowORM)
                .where(
                    ExecutionFlowORM.id == flow.id,
                    ExecutionFlowORM.engagement_id == engagement_id,
                )
                .with_for_update()
            )
            current_flow = flow_result.scalar_one_or_none()
            if (
                current_flow is None
                or current_flow.revision != flow.revision
                or current_flow.status != flow.status
                or current_flow.status not in {"pending", "running"}
            ):
                return False

            claim = await session.execute(
                update(ExecutionSubtaskORM)
                .where(
                    ExecutionSubtaskORM.id == subtask_id,
                    ExecutionSubtaskORM.engagement_id == engagement_id,
                    ExecutionSubtaskORM.flow_id == flow.id,
                    ExecutionSubtaskORM.task_id == subtask.task_id,
                    ExecutionSubtaskORM.task_type == subtask.task_type,
                    ExecutionSubtaskORM.agent_type == subtask.agent_type.value,
                    ExecutionSubtaskORM.approval_required == subtask.approval_required,
                    ExecutionSubtaskORM.execution_task_id.is_(None),
                    ExecutionSubtaskORM.status == "pending",
                )
                .values(
                    status="dispatched", updated_at=datetime.utcnow(),
                    **({"execution_task_id": execution_task.id} if execution_task else {}),
                )
                .returning(ExecutionSubtaskORM.id)
            )
            if claim.scalar_one_or_none() != subtask_id:
                return False
            revision = await session.execute(
                update(ExecutionFlowORM)
                .where(
                    ExecutionFlowORM.id == flow.id,
                    ExecutionFlowORM.engagement_id == engagement_id,
                    ExecutionFlowORM.status == flow.status,
                    ExecutionFlowORM.revision == flow.revision,
                )
                .values(
                    revision=ExecutionFlowORM.revision + 1,
                    updated_at=datetime.utcnow(),
                )
                .returning(ExecutionFlowORM.id)
            )
            if revision.scalar_one_or_none() != flow.id:
                return False
            if execution_task is not None:
                from ai_osop.memory.supervision_store import SupervisionStore

                await session.execute(
                    insert(TaskORM).values(
                        id=execution_task.id, type=execution_task.type,
                        priority=execution_task.priority,
                        agent_type=execution_task.agent_type.value,
                        payload=execution_task.payload,
                        dependencies=execution_task.dependencies,
                        max_retries=execution_task.max_retries,
                        timeout_seconds=execution_task.timeout_seconds,
                        scope_check=True,
                        approval_required=execution_task.approval_required,
                        status="pending", result=None, retry_count=0,
                        created_at=execution_task.created_at,
                        started_at=None, completed_at=None,
                        engagement_id=engagement_id, assigned_agent_id=None,
                        flow_id=flow.id, subtask_id=subtask_id,
                        parent_task_id=subtask.task_id,
                    )
                )
                await SupervisionStore._append_event(
                    session, engagement_id, execution_task.id,
                    "flow.subtask_dispatch_intent", "operator",
                    {
                        "status": "pending", "flow_id": flow.id,
                        "subtask_id": subtask_id, "task_id": execution_task.id,
                        "signed_version": signed.version,
                        "approval_required": execution_task.approval_required,
                    },
                    idempotency_key="flow-subtask-intent:" + subtask_id,
                )
            await session.commit()
            return True

    async def record_action(self, action: ExecutionActionRecord) -> None:
        """Persist one redacted action receipt with idempotent call identity.

        Only explicitly trusted scalar provenance fields survive. Never persist
        arguments, responses, headers, bearer credentials or exception strings.
        """
        allowed = {
            "server_id",
            "agent_id",
            "request_id",
            "trace_id",
            "correlation_id",
            "error_class",
            "retry_count",
            "provider",
            "model",
            "input_tokens",
            "output_tokens",
            "total_tokens",
            "cost_usd",
        }
        safe_metadata = {
            key: value[:128] if isinstance(value, str) else value
            for key, value in action.safe_metadata.items()
            if (
                key in allowed
                or (
                    action.tool_name == "signed_diff_auth_compare"
                    and key
                    in {
                        "comparison_sha256",
                        "source_task_id",
                        "source_observation_task_id",
                        "target_observation_task_id",
                    }
                )
            )
            and (
                (isinstance(value, str) and len(value) <= 256)
                or isinstance(value, (int, float, bool))
            )
        }
        data = action.model_dump()
        data["safe_metadata"] = safe_metadata
        async with self._async_session() as session:
            async with session.begin():
                if action.tool_name == "signed_diff_auth_compare":
                    # This terminal comparison is an immutable evidence lead,
                    # never independent proof of a vulnerability. Bind its
                    # insert + notification to the SAME signed ROE/Flow lock,
                    # so revocation cannot commit between the last check and
                    # the authoritative action record.
                    from ai_osop.memory.authorization_store import guard_sql
                    from ai_osop.memory.supervision_store import SupervisionStore

                    digest = safe_metadata.get("comparison_sha256")
                    ids = [
                        safe_metadata.get(key)
                        for key in (
                            "source_task_id",
                            "source_observation_task_id",
                            "target_observation_task_id",
                        )
                    ]
                    if (
                        action.outcome
                        not in {"candidate_review", "expected_denial", "inconclusive"}
                        or set(safe_metadata)
                        != {
                            "comparison_sha256",
                            "source_task_id",
                            "source_observation_task_id",
                            "target_observation_task_id",
                        }
                        or not isinstance(digest, str)
                        or re.fullmatch(r"[a-f0-9]{64}", digest) is None
                        or any(
                            not isinstance(identifier, str)
                            or re.fullmatch(r"task-[A-Za-z0-9._-]{1,59}", identifier) is None
                            for identifier in ids
                        )
                        or len(set(ids)) != 3
                        or not action.task_id
                        or not action.flow_id
                    ):
                        raise PermissionError("Invalid signed comparison action provenance")
                    session_row = (
                        await session.execute(
                            select(SessionStateORM)
                            .where(
                                SessionStateORM.session_id == action.engagement_id,
                            )
                            .with_for_update()
                        )
                    ).scalar_one_or_none()
                    parent = (
                        await session.execute(
                            select(TaskORM)
                            .where(
                                TaskORM.id == action.task_id,
                                TaskORM.engagement_id == action.engagement_id,
                            )
                            .with_for_update()
                        )
                    ).scalar_one_or_none()
                    if (
                        session_row is None
                        or session_row.phase in {"halted", "completed"}
                        or parent is None
                        or parent.type != "replay_for_diff_auth"
                        or parent.flow_id != action.flow_id
                        or parent.parent_task_id != ids[0]
                        or not isinstance(parent.payload, dict)
                        or parent.payload.get("operator_approved") is not True
                        or not isinstance(parent.payload.get("approval_id"), str)
                    ):
                        raise PermissionError("Signed replay comparison parent changed")
                    human = (
                        await session.execute(
                            select(ApprovalRequestORM)
                            .where(
                                ApprovalRequestORM.id == parent.payload["approval_id"],
                                ApprovalRequestORM.engagement_id == action.engagement_id,
                                ApprovalRequestORM.task_id == parent.id,
                                ApprovalRequestORM.status == "approved",
                            )
                            .with_for_update()
                        )
                    ).scalar_one_or_none()
                    from ai_osop.safety.approval_binding import matches_pinned_payload

                    if human is None or not matches_pinned_payload(
                        human.evidence,
                        parent.payload,
                    ):
                        raise PermissionError("Replay parent human approval has changed")
                    version = parent.payload.get("_authorization_version")
                    revision = parent.payload.get("_flow_revision")
                    if type(version) is not int or type(revision) is not int:
                        raise PermissionError("Signed replay comparison version missing")
                    await guard_sql(session, action.engagement_id, expected_version=version)
                    flow = (
                        await session.execute(
                            select(ExecutionFlowORM)
                            .where(
                                ExecutionFlowORM.id == action.flow_id,
                                ExecutionFlowORM.engagement_id == action.engagement_id,
                            )
                            .with_for_update()
                        )
                    ).scalar_one_or_none()
                    if (
                        flow is None
                        or flow.status not in {"pending", "running"}
                        or flow.revision != revision
                    ):
                        raise PermissionError("Signed replay comparison Flow changed")
                    observations = (
                        (
                            await session.execute(
                                select(TaskORM)
                                .where(
                                    TaskORM.id.in_(ids[1:]),
                                    TaskORM.engagement_id == action.engagement_id,
                                )
                                .with_for_update()
                            )
                        )
                        .scalars()
                        .all()
                    )
                    if (
                        len(observations) != 2
                        or {row.id for row in observations} != set(ids[1:])
                        or any(
                            row.status != "completed"
                            or row.parent_task_id != parent.id
                            or row.flow_id != flow.id
                            or row.type != "navigate"
                            or not row.approval_required
                            or not isinstance(row.payload, dict)
                            or row.payload.get("_authorization_version") != version
                            or row.payload.get("operator_approved") is not True
                            or not isinstance(row.payload.get("approval_id"), str)
                            for row in observations
                        )
                    ):
                        raise PermissionError("Signed replay comparison children changed")
                    by_observation_id = {row.id: row for row in observations}
                    source_row, target_row = (
                        by_observation_id[ids[1]],
                        by_observation_id[ids[2]],
                    )
                    if (
                        action.subtask_id != target_row.subtask_id
                        or (source_row.subtask_id is None)
                        != (target_row.subtask_id is None)
                    ):
                        raise PermissionError("Signed replay comparison subtask lineage changed")
                    if target_row.subtask_id is not None:
                        from ai_osop.core.signed_replay_comparison import (
                            observation_subtask_id,
                        )

                        if (
                            source_row.subtask_id != observation_subtask_id(source_row.id)
                            or target_row.subtask_id != observation_subtask_id(target_row.id)
                        ):
                            raise PermissionError("Signed replay observation subtask identity changed")
                        substasks = (
                            (
                                await session.execute(
                                    select(ExecutionSubtaskORM)
                                    .where(
                                        ExecutionSubtaskORM.id.in_(
                                            [source_row.subtask_id, target_row.subtask_id]
                                        ),
                                        ExecutionSubtaskORM.engagement_id == action.engagement_id,
                                        ExecutionSubtaskORM.flow_id == flow.id,
                                    )
                                    .with_for_update()
                                )
                            )
                            .scalars()
                            .all()
                        )
                        bound = {row.id: row for row in substasks}
                        if len(bound) != 2 or any(
                            sid not in bound
                            or bound[sid].task_id != parent.id
                            or bound[sid].execution_task_id != child.id
                            or bound[sid].task_type != "navigate"
                            or bound[sid].agent_type != "workflow"
                            or bound[sid].approval_required is not True
                            for child, sid in (
                                (source_row, source_row.subtask_id),
                                (target_row, target_row.subtask_id),
                            )
                        ):
                            raise PermissionError("Signed replay action has no durable subtask provenance")
                    for child in observations:
                        human = (
                            await session.execute(
                                select(ApprovalRequestORM)
                                .where(
                                    ApprovalRequestORM.id == child.payload["approval_id"],
                                    ApprovalRequestORM.engagement_id == action.engagement_id,
                                    ApprovalRequestORM.task_id == child.id,
                                    ApprovalRequestORM.status == "approved",
                                )
                                .with_for_update()
                            )
                        ).scalar_one_or_none()
                        if human is None or not matches_pinned_payload(
                            human.evidence,
                            child.payload,
                        ):
                            raise PermissionError("Replay observation human approval has changed")

                    # Recompute the non-promotable comparison from the very
                    # PostgreSQL snapshots held under the same transaction.
                    # Caller-supplied digest/outcome must never become an
                    # independently trusted review lead by assertion alone.
                    original = (
                        await session.execute(
                            select(TaskORM)
                            .where(
                                TaskORM.id == ids[0],
                                TaskORM.engagement_id == action.engagement_id,
                            )
                            .with_for_update()
                        )
                    ).scalar_one_or_none()
                    if (
                        original is None
                        or original.type != "map_workflow"
                        or original.status != "completed"
                        or original.flow_id not in {None, flow.id}
                        or not isinstance(original.payload, dict)
                        or original.payload.get("_authorization_version") != version
                        or original.payload.get("user_label")
                        != parent.payload.get("source_user_label")
                        or not isinstance(original.result, dict)
                        or original.result.get("workflow_id") != parent.payload.get("workflow_id")
                        or original.result.get("status") not in {"success", "workflow_recorded"}
                    ):
                        raise PermissionError(
                            "Replay comparison original source is not authoritative"
                        )
                    from ai_osop.core.config import AgentType
                    from ai_osop.core.signed_replay_comparison import (
                        classify_signed_observation_pair,
                    )

                    by_id = {row.id: row for row in observations}

                    def observed_snapshot(row: TaskORM) -> Task:
                        return Task(
                            id=row.id,
                            type=row.type,
                            agent_type=AgentType(row.agent_type),
                            engagement_id=row.engagement_id,
                            flow_id=row.flow_id,
                            parent_task_id=row.parent_task_id,
                            subtask_id=row.subtask_id,
                            status=row.status,
                            payload=row.payload,
                            result=row.result,
                            dependencies=row.dependencies,
                            max_retries=row.max_retries,
                            approval_required=row.approval_required,
                        )

                    decision = classify_signed_observation_pair(
                        observed_snapshot(by_id[ids[1]]),
                        observed_snapshot(by_id[ids[2]]),
                        engagement_id=action.engagement_id,
                        parent_id=parent.id,
                        flow_id=flow.id,
                        workflow_id=parent.payload.get("workflow_id"),
                        step_id=by_id[ids[1]].payload.get("step_id"),
                        source_identity=parent.payload.get("source_user_label"),
                        target_identity=parent.payload.get("target_user_label"),
                        version=version,
                        flow_revision=revision,
                        original_source_task_id=original.id,
                    )
                    expected_outcome = {
                        "candidate_needs_independent_review": "candidate_review",
                        "expected_denial_observed": "expected_denial",
                    }.get(decision.get("status"), "inconclusive")
                    expected_action_id = (
                        "action-"
                        + hashlib.sha256(
                            (action.engagement_id + ":" + parent.id + ":" + digest).encode()
                        ).hexdigest()[:48]
                    )
                    if (
                        not decision.get("source_observed")
                        or not decision.get("target_observed")
                        or decision.get("comparison_sha256") != digest
                        or expected_outcome != action.outcome
                        or expected_action_id != action.id
                    ):
                        raise PermissionError(
                            "Signed comparison disagrees with immutable source data"
                        )

                stmt = (
                    insert(ExecutionActionORM)
                    .values(**data)
                    .on_conflict_do_nothing(index_elements=["id"])
                    .returning(ExecutionActionORM.id)
                )
                inserted = (await session.execute(stmt)).scalar_one_or_none()
                if inserted is None and action.tool_name == "signed_diff_auth_compare":
                    prior = (
                        await session.execute(
                            select(ExecutionActionORM)
                            .where(
                                ExecutionActionORM.id == action.id,
                            )
                            .with_for_update()
                        )
                    ).scalar_one_or_none()
                    if (
                        prior is None
                        or prior.engagement_id != action.engagement_id
                        or prior.flow_id != action.flow_id
                        or prior.task_id != action.task_id
                        or prior.subtask_id != action.subtask_id
                        or prior.tool_name != action.tool_name
                        or prior.outcome != action.outcome
                        or prior.safe_metadata != safe_metadata
                    ):
                        raise PermissionError("Conflicting immutable signed comparison receipt")
                if inserted is not None and action.tool_name == "signed_diff_auth_compare":
                    await SupervisionStore._append_event(
                        session,
                        action.engagement_id,
                        action.task_id,
                        "signed_diff.comparison_recorded",
                        "signed_comparator",
                        {
                            "action_id": action.id,
                            "status": action.outcome,
                            "flow_id": action.flow_id,
                        },
                        idempotency_key="signed-diff-comparison:" + action.id,
                    )

    async def record_action_adapter(self, payload: Dict[str, Any]) -> None:
        """Durable sink for sanitized asynchronous MCP and LLM action receipts."""
        engagement_id = payload.get("engagement_id")
        if (
            not isinstance(engagement_id, str)
            or not engagement_id
            or engagement_id == "api-bootstrap"
        ):
            # Unattributed tool use cannot safely be attached to an engagement.
            return
        record = ExecutionActionRecord(
            **{
                key: value
                for key, value in payload.items()
                if key in ExecutionActionRecord.model_fields
            }
        )
        await self.record_action(record)

    async def consume_mcp_tool_budget(
        self,
        engagement_id: str,
        tool_name: str,
        agent_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> bool:
        """Atomically enforce ROE tool budgets across processes via Redis.

        Optional ROE keys:
          tool_call_budget_total: total permitted calls in a rolling window
          tool_call_budget_per_tool: permitted calls per agent/tool pair
          tool_call_window_seconds: window TTL, default 3600

        The counters increment only when *both* limits allow the request. A
        Redis outage with enabled limits fails closed rather than over-budget
        scanning continuing against the user's authorized target.
        """
        if engagement_id == "api-bootstrap":
            return True
        if not engagement_id:
            return False
        session = await self.load_session_state(engagement_id)
        if session is None or session.phase in {"halted", "completed"}:
            return False
        try:
            await self.assert_signed_authorization(engagement_id)
        except Exception:
            # This is the shared MCP quota/admission boundary. A missing,
            # revoked, expired or tampered authorization never spends quota
            # or reaches a provider.
            return False
        if not session.scope.authorization_ref or not (
            session.scope.domains or session.scope.ips
        ):
            return False
        # This callback is the common boundary for direct, registry and
        # background MCP calls. Even an engagement with *unlimited* numeric
        # quotas must stop once its signed ROE testing window closes.
        from ai_osop.core.exceptions import OutOfScopeError, ScopeValidationError
        from ai_osop.safety.scope import ScopeEnforcer

        try:
            ScopeEnforcer(session.scope).validate_time_window()
        except (OutOfScopeError, ScopeValidationError):
            return False
        roe = session.roe or {}
        total_raw = roe.get("tool_call_budget_total")
        per_tool_raw = roe.get("tool_call_budget_per_tool")
        if total_raw is None and per_tool_raw is None:
            return True

        try:
            total = int(total_raw) if total_raw is not None else 1_000_000_000
            per_tool = int(per_tool_raw) if per_tool_raw is not None else 1_000_000_000
            window = int(roe.get("tool_call_window_seconds", 3600))
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid ROE tool budget configuration") from exc
        if not (0 <= total <= 1_000_000_000 and 0 <= per_tool <= 1_000_000_000):
            raise ValueError("ROE tool budgets must be nonnegative")
        if not 60 <= window <= 86400:
            raise ValueError("ROE tool window must be 60–86400 seconds")
        eng_key = hashlib.sha256(engagement_id.encode("utf-8")).hexdigest()[:24]
        tool_key = hashlib.sha256(
            f"{agent_id or 'agent-unspecified'}:{tool_name}".encode("utf-8")
        ).hexdigest()[:24]
        if request_id is not None and (
            not isinstance(request_id, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", request_id)
        ):
            raise ValueError("Invalid MCP quota request identity")
        receipt_key = (
            f"osop:tool-budget:{eng_key}:request:"
            + hashlib.sha256(f"{tool_name}:{request_id}".encode()).hexdigest()
            if request_id is not None else None
        )
        redis_conn = await self._ensure_redis()
        atomic_counter = """
if #KEYS == 3 and redis.call('EXISTS', KEYS[3]) == 1 then
    return 1
end
local overall = tonumber(redis.call('GET', KEYS[1]) or '0')
local matching = tonumber(redis.call('GET', KEYS[2]) or '0')
if overall >= tonumber(ARGV[1]) or matching >= tonumber(ARGV[2]) then
    return 0
end
local total = redis.call('INCR', KEYS[1])
local tool = redis.call('INCR', KEYS[2])
if total == 1 then redis.call('EXPIRE', KEYS[1], ARGV[3]) end
if tool == 1 then redis.call('EXPIRE', KEYS[2], ARGV[3]) end
if #KEYS == 3 then
    redis.call('SET', KEYS[3], '1', 'EX', ARGV[3])
end
return 1
"""
        allowed = await redis_conn.eval(
            atomic_counter,
            3 if receipt_key else 2,
            f"osop:tool-budget:{eng_key}:total",
            f"osop:tool-budget:{eng_key}:{tool_key}",
            *([receipt_key] if receipt_key else []),
            total,
            per_tool,
            window,
        )
        return bool(allowed)

    async def list_actions(
        self,
        engagement_id: str,
        task_id: Optional[str] = None,
        limit: int = 100,
        flow_id: Optional[str] = None,
    ) -> List[ExecutionActionRecord]:
        async with self._async_session() as session:
            stmt = select(ExecutionActionORM).where(
                ExecutionActionORM.engagement_id == engagement_id
            )
            if task_id is not None:
                stmt = stmt.where(ExecutionActionORM.task_id == task_id)
            if flow_id is not None:
                stmt = stmt.where(ExecutionActionORM.flow_id == flow_id)
            result = await session.execute(
                stmt.order_by(ExecutionActionORM.created_at.desc()).limit(max(1, min(limit, 100)))
            )
            return [
                ExecutionActionRecord(
                    **{key: getattr(row, key) for key in ExecutionActionRecord.model_fields}
                )
                for row in result.scalars()
            ]

    # ============== CHECKPOINTS ==============

    async def create_checkpoint(self, session_id: str, metadata: Dict[str, Any]) -> str:
        """Create a session checkpoint for recovery."""
        checkpoint_id = f"chk-{session_id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

        # Get current state
        state = await self.get_session_state(session_id)
        if not state:
            raise MemoryException(f"Session {session_id} not found")

        # Store checkpoint
        checkpoint_data = {
            "checkpoint_id": checkpoint_id,
            "session_id": session_id,
            "state": state.model_dump(),
            "metadata": metadata,
            "created_at": datetime.utcnow().isoformat(),
        }

        await self.store_hot(f"checkpoint:{checkpoint_id}", checkpoint_data, ttl=604800)  # 7 days

        # Update session with checkpoint reference
        state.checkpoint_id = checkpoint_id
        await self.store_session_state(state)

        return checkpoint_id

    async def restore_checkpoint(self, checkpoint_id: str) -> SessionState:
        """Select a saved checkpoint without replaying stale scope or ROE.

        Snapshots are contextual history, never fresh testing authorization.
        The current PostgreSQL engagement remains authoritative for phase,
        ownership, signed ROE and target scope. Lock that row to serialize
        with policy updates and emergency halts.
        """
        data = await self.retrieve_hot(f"checkpoint:{checkpoint_id}")
        if not isinstance(data, dict) or data.get("checkpoint_id") != checkpoint_id:
            raise MemoryException(f"Checkpoint {checkpoint_id} not found or expired")
        try:
            saved = SessionState.model_validate(data["state"])
        except (KeyError, ValueError, TypeError) as exc:
            raise MemoryException("Checkpoint snapshot is invalid") from exc
        if data.get("session_id") != saved.session_id:
            raise MemoryException("Checkpoint engagement identity mismatch")
        async with self._async_session() as session:
            result = await session.execute(
                select(SessionStateORM)
                .where(SessionStateORM.session_id == saved.session_id)
                .with_for_update()
            )
            current = result.scalar_one_or_none()
            if current is None or current.phase in {"halted", "completed"}:
                raise MemoryException("Cannot restore an inactive or missing engagement")
            from ai_osop.memory.authorization_store import guard_sql
            from sqlalchemy.ext.asyncio import AsyncSession

            if isinstance(session, AsyncSession):
                await guard_sql(session, saved.session_id)
            scope = ScopeDefinition.model_validate(current.scope)
            if (
                scope.engagement_id != saved.session_id
                or not scope.authorization_ref
                or not (scope.domains or scope.ips)
                or scope.model_dump(mode="json") != saved.scope.model_dump(mode="json")
                or current.roe != saved.roe
                or current.phase != saved.phase
            ):
                raise MemoryException("Checkpoint authorization or lifecycle is stale")
            from ai_osop.safety.scope import ScopeEnforcer

            ScopeEnforcer(scope).validate_time_window()
            current.checkpoint_id = checkpoint_id
            await session.commit()
        fresh = await self.load_session_state(saved.session_id)
        if fresh is None:
            raise MemoryException("Checkpoint restore committed but engagement unavailable")
        return fresh

    @staticmethod
    def _evidence_from_row(orm: EvidenceArtifactORM) -> EvidenceArtifact:
        return _checked_evidence_artifact(EvidenceArtifact(**{
            key: getattr(orm, key) for key in EvidenceArtifact.model_fields
        }))

    async def record_evidence_artifact(
        self, artifact: EvidenceArtifact, *, source_task_id: str,
    ) -> str:
        """Store only an unverified artifact bound to a CURRENT signed Task.

        No model/graph/HTTP observation is promoted to target proof. The
        signed engagement, real Task owner, approved human grant (if required),
        Flow, and source URL are checked under the same SQL transaction as
        the insert. A missing DB/ambiguous COMMIT/readback always raises.
        """
        from ai_osop.memory.authorization_store import guard_sql
        from ai_osop.memory.supervision_store import SupervisionStore
        from ai_osop.safety.approval_binding import matches_pinned_payload

        _checked_evidence_artifact(artifact)
        if (
            not self._async_session
            or not isinstance(source_task_id, str)
            or source_task_id != artifact.replay_recipe["source_task_id"]
        ):
            raise MemoryException("PostgreSQL signed artifact source unavailable")
        async with self._async_session() as session:
            async with session.begin():
                # The 0023 table alone is NOT immutable. Refuse evidence
                # creation on databases missing the 0024 write-once trigger.
                migration_ready = (await session.execute(text(
                    "SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE "
                    "tgrelid = to_regclass('evidence_artifacts') AND "
                    "tgname = 'trg_evidence_artifacts_immutable' AND NOT tgisinternal)"
                ))).scalar_one()
                if migration_ready is not True:
                    raise MemoryException("Evidence artifact write-once migration 0024 unavailable")
                engagement, _ = await SupervisionStore._guard(
                    session, artifact.engagement_id, require_window=True,
                )
                signed = await guard_sql(session, artifact.engagement_id)
                task = (await session.execute(select(TaskORM).where(
                    TaskORM.id == source_task_id,
                    TaskORM.engagement_id == artifact.engagement_id,
                ).with_for_update(read=True))).scalar_one_or_none()
                if (
                    task is None
                    or task.id != source_task_id
                    or task.engagement_id != artifact.engagement_id
                    or task.status not in {"running", "completed"}
                    or not isinstance(task.payload, dict)
                    or type(task.payload.get("_authorization_version")) is not int
                    or task.payload["_authorization_version"] != signed.version
                    or not isinstance(task.payload.get("url"), str)
                    or hashlib.sha256(task.payload["url"].encode("utf-8")).hexdigest()
                    != artifact.replay_recipe["original_url_sha256"]
                    or task.payload.get("method", "GET").upper() != artifact.http_method
                ):
                    raise MemoryException("Evidence source is not the current signed Task")
                if task.flow_id:
                    flow = (await session.execute(select(ExecutionFlowORM).where(
                        ExecutionFlowORM.id == task.flow_id,
                        ExecutionFlowORM.engagement_id == artifact.engagement_id,
                    ).with_for_update(read=True))).scalar_one_or_none()
                    if (
                        flow is None or flow.status not in {"pending", "running"}
                        or ("_flow_revision" in task.payload
                            and (type(task.payload["_flow_revision"]) is not int
                                 or task.payload["_flow_revision"] != flow.revision))
                    ):
                        raise MemoryException("Evidence source Flow is stale or closed")
                    if task.subtask_id:
                        step = (await session.execute(select(ExecutionSubtaskORM).where(
                            ExecutionSubtaskORM.id == task.subtask_id,
                            ExecutionSubtaskORM.flow_id == task.flow_id,
                            ExecutionSubtaskORM.engagement_id == artifact.engagement_id,
                        ).with_for_update(read=True))).scalar_one_or_none()
                        if (
                            step is None or step.execution_task_id != task.id
                            or step.task_id != task.parent_task_id
                            or step.status not in {"dispatched", "running", "completed"}
                        ):
                            raise MemoryException("Evidence source Task/subtask lineage unavailable")
                elif task.subtask_id:
                    raise MemoryException("Evidence source subtask lacks Flow")
                if task.approval_required:
                    grant = task.payload.get("approval_id")
                    approval = (await session.execute(select(ApprovalRequestORM).where(
                        ApprovalRequestORM.id == grant,
                        ApprovalRequestORM.engagement_id == artifact.engagement_id,
                        ApprovalRequestORM.task_id == task.id,
                        ApprovalRequestORM.status == "approved",
                    ).with_for_update(read=True))).scalar_one_or_none() if isinstance(grant, str) else None
                    if (
                        approval is None or not approval.operator_id
                        or approval.responded_at is None
                        or artifact.approval_id != grant
                        or task.payload.get("operator_approved") is not True
                        or not matches_pinned_payload(approval.evidence, task.payload)
                    ):
                        raise MemoryException("Evidence source approval was not signed and pinned")
                elif artifact.approval_id is not None:
                    raise MemoryException("Evidence artifact cannot claim a foreign approval")
                from ai_osop.safety.scope import ScopeEnforcer, validate_payload_targets

                scope = ScopeDefinition.model_validate(engagement.scope)
                validate_payload_targets(ScopeEnforcer(scope), {"url": task.payload["url"]}, require_target=True)
                session.add(EvidenceArtifactORM(**artifact.model_dump()))

        # A successful INSERT call/COMMIT acknowledgement alone is not enough
        # to hand back an artifact ID. Read it under the exact tenant fence.
        current = await self.get_evidence_artifact(
            artifact.id, engagement_id=artifact.engagement_id,
        )
        if current is None or current != artifact:
            raise MemoryException("Evidence artifact durable readback is UNKNOWN")
        return artifact.id

    async def get_evidence_artifact(
        self, artifact_id: str, *, engagement_id: str,
    ) -> Optional[EvidenceArtifact]:
        """Owner/tenant-fenced readback; never search across all engagements."""
        if (
            not self._async_session
            or not isinstance(artifact_id, str)
            or not re.fullmatch(r"ev-[A-Za-z0-9._-]{1,61}", artifact_id)
            or not isinstance(engagement_id, str)
            or not _EVIDENCE_ID.fullmatch(engagement_id)
        ):
            raise MemoryException("Tenant-scoped evidence store/identity unavailable")
        from ai_osop.memory.authorization_store import guard_sql

        async with self._async_session() as session:
            await guard_sql(session, engagement_id)
            result = await session.execute(select(EvidenceArtifactORM).where(
                EvidenceArtifactORM.id == artifact_id,
                EvidenceArtifactORM.engagement_id == engagement_id,
            ))
            orm = result.scalar_one_or_none()
            if orm is not None and (
                orm.id != artifact_id or orm.engagement_id != engagement_id
            ):
                raise MemoryException("Evidence artifact tenant readback identity mismatch")
            return self._evidence_from_row(orm) if orm is not None else None

    async def list_finding_evidence(
        self, engagement_id: str, finding_id: str
    ) -> List[EvidenceArtifact]:
        """List all immutable evidence artifacts associated with a finding."""
        if (
            not self._async_session or not isinstance(engagement_id, str)
            or not _EVIDENCE_ID.fullmatch(engagement_id)
            or not isinstance(finding_id, str)
            or not _EVIDENCE_ID.fullmatch(finding_id)
        ):
            raise MemoryException("Tenant-scoped evidence collection unavailable")
        from ai_osop.memory.authorization_store import guard_sql

        async with self._async_session() as session:
            await guard_sql(session, engagement_id)
            stmt = select(EvidenceArtifactORM).where(
                and_(
                    EvidenceArtifactORM.engagement_id == engagement_id,
                    EvidenceArtifactORM.finding_id == finding_id,
                )
            ).order_by(EvidenceArtifactORM.captured_at.desc()).limit(100)
            result = await session.execute(stmt)
            orms = result.scalars().all()
            if any(row.engagement_id != engagement_id or row.finding_id != finding_id for row in orms):
                raise MemoryException("Evidence collection included foreign tenant or finding")
            return [self._evidence_from_row(orm) for orm in orms]

    async def close(self) -> None:
        if self._redis:
            await self._redis.close()
        if self._pg_engine:
            await self._pg_engine.dispose()
