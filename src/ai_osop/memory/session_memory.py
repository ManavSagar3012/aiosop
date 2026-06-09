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
from sqlalchemy import JSON, Column, DateTime, String, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from ai_osop.core.config import settings
from ai_osop.core.exceptions import MemoryException
from ai_osop.core.models import AuditEvent, ScopeDefinition, SessionState

Base = declarative_base()


class SessionStateORM(Base):
    __tablename__ = "session_states"

    session_id = Column(String(64), primary_key=True)
    scope = Column(JSON)
    roe = Column(JSON)
    phase = Column(String(32))
    agents = Column(JSON)
    checkpoint_id = Column(String(64))
    audit_log_position = Column(String(64))
    created_at = Column(DateTime)
    updated_at = Column(DateTime)


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
        """Initialize all storage connections."""
        # Redis
        self._redis = redis.from_url(settings.redis_uri, decode_responses=True, max_connections=50)

        # PostgreSQL
        self._pg_engine = create_async_engine(
            settings.postgres_uri, pool_size=20, max_overflow=10, echo=False
        )
        self._async_session = sessionmaker(
            self._pg_engine, class_=AsyncSession, expire_on_commit=False
        )

        # Create tables
        async with self._pg_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    # ============== HOT TIER (Redis) ==============

    async def store_hot(self, key: str, value: Any, ttl: int = 3600) -> None:
        """Store in Redis with TTL."""
        serialized = json.dumps(value, default=str)
        await self._redis.setex(key, ttl, serialized)

    async def retrieve_hot(self, key: str) -> Optional[Any]:
        """Retrieve from Redis."""
        data = await self._redis.get(key)
        if data:
            return json.loads(data)
        return None

    async def delete_hot(self, key: str) -> None:
        await self._redis.delete(key)

    async def store_session_state(self, state: SessionState) -> None:
        """Store active session state in Redis."""
        key = f"session:{state.session_id}"
        await self.store_hot(key, state.dict(), ttl=86400)

    async def get_session_state(self, session_id: str) -> Optional[SessionState]:
        """Retrieve active session state from Redis."""
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
        await self._redis.publish(channel, json.dumps(event, default=str))

    async def subscribe_events(self, channel: str):
        """Subscribe to Redis pub/sub channel."""
        pubsub = self._redis.pubsub()
        await pubsub.subscribe(channel)
        return pubsub

    async def push_task_queue(self, queue_name: str, task: Dict[str, Any]) -> None:
        """Push task to priority queue."""
        priority = task.get("priority", 5)
        await self._redis.zadd(f"queue:{queue_name}", {json.dumps(task, default=str): priority})

    async def pop_task_queue(self, queue_name: str) -> Optional[Dict[str, Any]]:
        """Pop highest priority task from queue."""
        result = await self._redis.zpopmax(f"queue:{queue_name}")
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
                    scope=state.scope.dict(),
                    roe=state.roe,
                    phase=state.phase,
                    agents=state.agents,
                    checkpoint_id=state.checkpoint_id,
                    audit_log_position=state.audit_log_position,
                    created_at=state.created_at,
                    updated_at=state.updated_at,
                )
                .on_conflict_do_update(
                    index_elements=["session_id"],
                    set_={
                        "scope": state.scope.dict(),
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
                    created_at=orm.created_at,
                    updated_at=orm.updated_at,
                )
            return None

    async def write_audit_event(self, event: AuditEvent) -> None:
        """Write cryptographically signed audit event."""
        import hmac
        # Calculate integrity hash using HMAC with a secret key
        # In a real production system, this key should come from a secure KMS
        secret_key = getattr(settings, "audit_secret_key", "default-insecure-audit-key").encode()
        event_data = (
            f"{event.event_id}:{event.timestamp.isoformat()}:{event.actor_id}:{event.event_type}:"
            f"{json.dumps(event.action, sort_keys=True)}:{json.dumps(event.result, sort_keys=True)}"
        )
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
            "state": state.dict(),
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

    async def close(self) -> None:
        if self._redis:
            await self._redis.close()
        if self._pg_engine:
            await self._pg_engine.dispose()
