"""
Session Memory Layer
Multi-tier storage: Redis (hot) + PostgreSQL (warm) + S3 (cold).
Manages session state, agent working memory, and checkpoints.
"""

import hashlib
import json
import pickle
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import redis.asyncio as redis
from sqlalchemy import JSON, Boolean, Column, DateTime, Integer, String, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker

from ai_osop.core.config import settings
from ai_osop.core.exceptions import MemoryException
from ai_osop.core.models import ApprovalRequest, AuditEvent, ScopeDefinition, SessionState, Task
from ai_osop.core.telemetry import RequestContext
from ai_osop.core.tracing import trace_span
from ai_osop.core.observability import record_redis_latency, record_postgres_latency
from ai_osop.reliability.retry import retry_with_backoff

import time
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
        String(16), index=True
    )  # pending, running, completed, failed, cancelled, awaiting_approval
    result = Column(JSON, nullable=True)
    retry_count = Column(Integer)
    created_at = Column(DateTime)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    engagement_id = Column(String(64), index=True)
    assigned_agent_id = Column(String(64), nullable=True)


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
    retry_count = Column(Integer, nullable=True)
    created_at = Column(DateTime)
    updated_at = Column(DateTime, nullable=True)

class FindingCorpusORM(Base):
    __tablename__ = "finding_corpus"

    id = Column(String(64), primary_key=True)
    original_finding_id = Column(String(64), index=True)
    category = Column(String(64), index=True)
    severity = Column(String(16))
    outcome = Column(String(32), index=True) # accepted, duplicate, etc.
    payload = Column(JSON)
    engagement_id = Column(String(64), index=True)
    created_at = Column(DateTime)
    finalized_at = Column(DateTime)


class _TimedPostgresSession:
    """Wraps an async session context manager to record Postgres latency."""
    def __init__(self, session, operation_name: str = "transaction"):
        self._session = session
        self._operation_name = operation_name
        self._start = None

    async def __aenter__(self):
        self._start = time.perf_counter()
        return await self._session.__aenter__()

    async def __aexit__(self, *args):
        result = await self._session.__aexit__(*args)
        if self._start is not None:
            record_postgres_latency(self._operation_name, time.perf_counter() - self._start)
        return result


class _TimedPostgresSessionMaker:
    """Wraps sessionmaker to return timed sessions."""
    def __init__(self, sessionmaker, operation_name: str = "transaction"):
        self._sm = sessionmaker
        self._operation_name = operation_name

    def __call__(self, *args, **kwargs):
        return _TimedPostgresSession(self._sm(*args, **kwargs), self._operation_name)


def _wrap_redis_for_metrics(redis_client):
    """Monkey-patch common Redis async methods to record latency metrics."""
    import time as _time
    methods = [
        "get", "set", "rpush", "lrange", "keys", "lrem", "delete", "ping",
        "setnx", "eval", "hset", "hgetall", "hincrby", "publish", "zadd",
        "zrange", "zrem", "hget", "hdel", "sadd", "sismember", "smembers",
    ]
    write_methods = {"set", "rpush", "lrem", "delete", "setnx", "hset", "hincrby",
                     "publish", "zadd", "zrem", "hdel", "sadd"}
    for method_name in methods:
        original = getattr(redis_client, method_name, None)
        if original is None:
            continue
        async def _timed_wrapper(*args, __original=original, __name=method_name, **kwargs):
            start = _time.perf_counter()
            result = await __original(*args, **kwargs)
            op_type = "write" if __name in write_methods else "read"
            record_redis_latency(op_type, _time.perf_counter() - start)
            return result
        setattr(redis_client, method_name, _timed_wrapper)
    return redis_client


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
            self._redis = _wrap_redis_for_metrics(self._redis)
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
            self._async_session = _TimedPostgresSessionMaker(
                sessionmaker(
                    self._pg_engine, class_=AsyncSession, expire_on_commit=False
                )
            )
            # Verify connection by creating tables
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
            self._redis = _wrap_redis_for_metrics(self._redis)
            return self._redis
        try:
            await self._redis.ping()
            return self._redis
        except Exception:
            logger.warning("Redis connection lost, reconnecting...")
            self._redis = redis.from_url(
                settings.redis_uri, decode_responses=True, max_connections=50
            )
            self._redis = _wrap_redis_for_metrics(self._redis)
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

    async def acquire_lock(self, lock_key: str, lock_value: str = "locked", ttl_seconds: int = 30, ttl: Optional[int] = None) -> bool:
        """Acquire a distributed Redis lock."""
        actual_ttl = ttl if ttl is not None else ttl_seconds
        r = await self._ensure_redis()
        with trace_span("redis.acquire_lock", attributes={"ai_osop.redis.key": lock_key}):
            result = await r.set(lock_key, lock_value, nx=True, ex=actual_ttl)
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
        """Persist session state to PostgreSQL."""
        async with self._async_session() as session:
            stmt = (
                insert(SessionStateORM)
                .values(
                    session_id=state.session_id,
                    scope=state.scope.model_dump(),
                    roe=state.roe,
                    phase=state.phase,
                    agents=state.agents,
                    checkpoint_id=state.checkpoint_id,
                    audit_log_position=state.audit_log_position,
                    created_by=state.created_by,
                    created_at=state.created_at,
                    updated_at=state.updated_at,
                )
                .on_conflict_do_update(
                    index_elements=["session_id"],
                    set_={
                        "scope": state.scope.model_dump(),
                        "phase": state.phase,
                        "agents": state.agents,
                        "checkpoint_id": state.checkpoint_id,
                        "audit_log_position": state.audit_log_position,
                        "updated_at": datetime.utcnow(),
                    },
                )
            )
            await session.execute(stmt)
            await session.commit()

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

            # Load the key - in production this would fetch from Vault using the path
            # Fallback for dev/testing if not configured
            secret_key = getattr(settings, "audit_secret_key", b"default-insecure-audit-key")
            if isinstance(secret_key, str):
                secret_key = secret_key.encode()

            # Get the hash of the last event for the chain
            last_hash = None
            async with self._async_session() as session:
                # We get the most recent event for this engagement to continue the chain
                last_event = await session.execute(
                    select(AuditLogORM.integrity_hash)
                    .where(AuditLogORM.engagement_id == event.engagement_id)
                    .order_by(AuditLogORM.timestamp.desc())
                    .limit(1)
                )
                last_hash = last_event.scalar_one_or_none()

            # Calculate integrity hash using HMAC with a secret key
            # We match the chain format expected by scope.py
            event_data = (
                f"{event.event_id}:{event.timestamp.isoformat()}:{event.actor_id}:{event.event_type}"
            )
            if last_hash:
                event_data = f"{last_hash}:{event_data}"

            integrity_hash = hmac.new(secret_key, event_data.encode(), hashlib.sha256).hexdigest()
            event.integrity_hash = integrity_hash

            async with self._async_session() as session:
                stmt = insert(AuditLogORM).values(
                    event_id=event.event_id,
                    timestamp=event.timestamp,
                    event_type=event.event_type,
                    severity=event.severity,
                    actor_type=event.actor_type,
                    actor_id=event.actor_id,
                    action=event.action,
                    result=event.result,
                    context=event.context,
                    integrity_hash=integrity_hash,
                    engagement_id=event.engagement_id,
                )
                await session.execute(stmt)
                await session.commit()

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
        """Persist approval request to hot + warm tier with tracing."""
        with trace_span(
            "postgres.store_approval",
            attributes={
                "ai_osop.approval_id": request.id,
                "ai_osop.engagement_id": request.engagement_id,
                "ai_osop.status": request.status,
            },
        ):
            # Hot tier (Redis)
            await self.store_hot(f"approval:{request.id}", request.model_dump(), ttl=86400 * 7)
            # Warm tier (Postgres)
            async with self._async_session() as session:
                stmt = (
                    insert(ApprovalRequestORM)
                    .values(
                        id=request.id,
                        task_id=request.task_id,
                        agent_id=request.agent_id,
                        action_type=request.action_type,
                        target=request.target,
                        payload_summary=request.payload_summary,
                        risk_assessment=request.risk_assessment,
                        evidence=request.evidence,
                        status=request.status,
                        operator_id=request.operator_id,
                        operator_notes=request.operator_notes,
                        requested_at=request.requested_at,
                        responded_at=request.responded_at,
                        engagement_id=request.engagement_id,
                    )
                    .on_conflict_do_update(
                        index_elements=["id"],
                        set_={
                            "status": request.status,
                            "operator_id": request.operator_id,
                            "operator_notes": request.operator_notes,
                            "responded_at": request.responded_at,
                        },
                    )
                )
                await session.execute(stmt)
                await session.commit()

    async def load_approval_request(self, request_id: str) -> Optional[ApprovalRequest]:
        """Load approval request from hot tier, fallback to warm."""
        # Try hot first
        data = await self.retrieve_hot(f"approval:{request_id}")
        if data:
            return ApprovalRequest(**data)
        # Fallback to warm
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
        with trace_span("postgres.store_dlq_entry", attributes={"ai_osop.dlq_id": entry.id, "ai_osop.engagement_id": entry.engagement_id}):
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
                        retry_count=entry.retry_count,
                        created_at=entry.created_at,
                        updated_at=entry.updated_at,
                    )
                    .on_conflict_do_update(
                        index_elements=["id"],
                        set_={
                            "status": entry.status,
                            "operator_notes": entry.operator_notes,
                            "retry_count": entry.retry_count,
                            "updated_at": entry.updated_at,
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
                result = await session.execute(select(DLQEntryORM).where(DLQEntryORM.id == entry_id))
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
                        retry_count=orm.retry_count,
                        created_at=orm.created_at,
                        updated_at=orm.updated_at,
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
                            retry_count=orm.retry_count,
                            created_at=orm.created_at,
                            updated_at=orm.updated_at,
                        )
                    )
                return entries

    async def get_dlq_stats(self) -> Dict[str, int]:
        """Get DLQ status counts from warm tier (Postgres)."""
        with trace_span("postgres.get_dlq_stats"):
            async with self._async_session() as session:
                # Group by status to compute stats
                from sqlalchemy import func
                query = select(DLQEntryORM.status, func.count(DLQEntryORM.id)).group_by(DLQEntryORM.status)
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

    async def store_task(self, task: Task) -> None:
        """Persist task to hot + warm tier."""
        with trace_span("postgres.store_task", attributes={"ai_osop.task_id": task.id, "ai_osop.engagement_id": task.engagement_id}):
            # Hot tier (Redis)
            await self.store_hot(f"task:{task.id}", task.model_dump(), ttl=86400 * 7)
            # Warm tier (Postgres)
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
                    )
                    .on_conflict_do_update(
                        index_elements=["id"],
                        set_={
                            "status": task.status,
                            "result": task.result,
                            "retry_count": task.retry_count,
                            "started_at": task.started_at,
                            "completed_at": task.completed_at,
                            "assigned_agent_id": task.assigned_agent_id,
                        },
                    )
                )
                await session.execute(stmt)
                await session.commit()

    async def load_task(self, task_id: str) -> Optional[Task]:
        """Load task from hot tier, fallback to warm."""
        data = await self.retrieve_hot(f"task:{task_id}")
        if data:
            return Task(**data)
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
                )
        return None

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
                    )
                )
            return tasks

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
        """Restore session from checkpoint."""
        data = await self.retrieve_hot(f"checkpoint:{checkpoint_id}")
        if not data:
            raise MemoryException(f"Checkpoint {checkpoint_id} not found or expired")

        state = SessionState(**data["state"])
        await self.store_session_state(state)
        return state


    async def list_all_sessions(self) -> List[str]:
        r = await self._ensure_redis()
        return await r.keys("session:*")


    async def list_all_tasks(self) -> List[str]:
        r = await self._ensure_redis()
        return await r.keys("task:*")

    async def close(self) -> None:
        if self._redis:
            await self._redis.close()
        if self._pg_engine:
            await self._pg_engine.dispose()


    async def update_agent_heartbeat(self, agent_id: str, data: Dict[str, Any]) -> None:
        """Update agent heartbeat with ownership and state."""
        if "last_seen" not in data:
            data["last_seen"] = datetime.utcnow().isoformat()
        await self.store_hot(f"agent:heartbeat:{agent_id}", data, ttl=60)

    async def get_agent_heartbeat(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve agent heartbeat."""
        return await self.retrieve_hot(f"agent:heartbeat:{agent_id}")


    async def update_agent_heartbeat(self, agent_id: str, data: Dict[str, Any]) -> None:
        """Update agent heartbeat with ownership and state."""
        if "last_seen" not in data:
            data["last_seen"] = datetime.utcnow().isoformat()
        await self.store_hot(f"agent:heartbeat:{agent_id}", data, ttl=60)

    async def get_agent_heartbeat(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve agent heartbeat."""
        return await self.retrieve_hot(f"agent:heartbeat:{agent_id}")

    async def get_all_agents(self) -> Dict[str, Any]:
        r = await self._ensure_redis()
        keys = await r.keys("agent:*")
        agents = {}
        for key in keys:
            if not key.startswith("agent:heartbeat:"):
                data = await self.retrieve_hot(key)
                agents[key.replace("agent:", "")] = data
        return agents

    async def find_tasks_by_agent(self, agent_id: str) -> List[Any]:
        r = await self._ensure_redis()
        task_keys = await r.keys("task:*")
        tasks = []
        for key in task_keys:
            task = await self.retrieve_hot(key)
            if task.get("assigned_agent_id") == agent_id:
                tasks.append(task)
        return tasks


    async def update_agent_status(self, agent_id: str, status: str) -> None:
        """Update agent status in Redis."""
        key = f"agent:{agent_id}"
        data = await self.retrieve_hot(key)
        if data:
            data["status"] = status
            await self.store_hot(key, data)
        else:
            await self.store_hot(key, {"status": status})

    async def release_lock_simple(self, key: str) -> None:
        """Release a lock without ownership check (simple delete)."""
        r = await self._ensure_redis()
        await r.delete(f"lock:{key}")
