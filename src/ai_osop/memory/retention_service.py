"""Retention Service — automated cleanup of old data across all storage tiers.

Runs as a background task (started by Orchestrator) that periodically:
1. Archives then deletes old Neo4j nodes (completed engagements, endpoints)
2. Deletes old Postgres rows (completed tasks, expired sessions, resolved approvals)
3. Sets TTL on Redis hot-state keys

Configuration via Settings (retention_* fields).
"""

import asyncio
from datetime import datetime, timedelta
from typing import Optional

import structlog

from ai_osop.core.config import settings
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.memory.session_memory import SessionMemory

logger = structlog.get_logger("ai_osop.retention")


class RetentionService:
    """Automated data retention across Neo4j, Postgres, and Redis."""

    def __init__(
        self,
        graph_memory: GraphMemory,
        session_memory: SessionMemory,
    ):
        self.graph_memory = graph_memory
        self.session_memory = session_memory
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._interval_hours = 24

    async def start(self) -> None:
        """Start the background retention loop."""
        if not settings.retention_enabled:
            logger.info("retention_disabled")
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("retention_service_started", interval_hours=self._interval_hours)

    async def stop(self) -> None:
        """Stop the background retention loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("retention_service_stopped")

    async def _loop(self) -> None:
        while self._running:
            try:
                await self.run_once()
            except Exception as e:
                logger.error("retention_run_failed", error=str(e))
            await asyncio.sleep(self._interval_hours * 3600)

    async def run_once(self) -> dict:
        """Execute a single retention pass. Returns counts of what was cleaned."""
        results = {}

        # Neo4j cleanup
        try:
            neo4j_results = await self._cleanup_neo4j()
            results["neo4j"] = neo4j_results
        except Exception as e:
            logger.error("neo4j_retention_failed", error=str(e))
            results["neo4j"] = {"error": str(e)}

        # Postgres cleanup
        try:
            pg_results = await self._cleanup_postgres()
            results["postgres"] = pg_results
        except Exception as e:
            logger.error("postgres_retention_failed", error=str(e))
            results["postgres"] = {"error": str(e)}

        # Redis TTL audit (just log, Redis handles TTL via EXPIRE)
        try:
            redis_results = await self._audit_redis_ttl()
            results["redis"] = redis_results
        except Exception as e:
            logger.error("redis_retention_failed", error=str(e))
            results["redis"] = {"error": str(e)}

        logger.info("retention_pass_complete", results=results)
        return results

    async def _cleanup_neo4j(self) -> dict:
        """Archive and delete old Neo4j nodes."""
        cutoff = datetime.utcnow() - timedelta(days=settings.neo4j_retention_days)
        cutoff_iso = cutoff.isoformat()

        cypher = """
        MATCH (e:Engagement)
        WHERE e.completed_at IS NOT NULL
          AND e.completed_at < $cutoff
          AND (e.archived IS NULL OR e.archived = false)
        WITH e
        OPTIONAL MATCH (e)-[:HAS_TASK|HAS_ENDPOINT|HAS_VULNERABILITY|HAS_EXPLOIT|HAS_PAYLOAD|HAS_WORKFLOW|HAS_EVIDENCE|HAS_DIFF_AUTH_FINDING*1..5]->(n)
        SET e.archived = true, n.archived = true
        RETURN count(DISTINCT e) as engagements, count(DISTINCT n) as nodes
        """

        records = await self.graph_memory.run_read_query(
            cypher, {"cutoff": cutoff_iso}
        )
        if records:
            record = records[0]
            return {
                "archived_engagements": record.get("engagements", 0),
                "archived_nodes": record.get("nodes", 0),
                "cutoff": cutoff_iso,
            }
        return {"archived_engagements": 0, "archived_nodes": 0}

    async def _cleanup_postgres(self) -> dict:
        """Delete old Postgres rows from warm tier."""
        from sqlalchemy import delete

        from ai_osop.memory.session_memory import (
            ApprovalRequestORM,
            AuditLogORM,
            SessionStateORM,
            TaskORM,
        )
        from ai_osop.auth.session_store import UserSessionORM

        results = {}

        # Completed tasks older than retention period
        task_cutoff = datetime.utcnow() - timedelta(days=settings.postgres_task_retention_days)
        async with self.session_memory._async_session() as session:
            stmt = delete(TaskORM).where(
                TaskORM.status.in_(["completed", "failed", "cancelled"]),
                TaskORM.completed_at < task_cutoff,
            )
            result = await session.execute(stmt)
            results["tasks_deleted"] = result.rowcount

        # Expired user sessions
        session_cutoff = datetime.utcnow() - timedelta(
            days=settings.postgres_session_retention_days
        )
        stmt = delete(UserSessionORM).where(UserSessionORM.expires_at < session_cutoff)
        result = await session.execute(stmt)
        results["sessions_deleted"] = result.rowcount

        # Resolved approvals older than retention period
        approval_cutoff = datetime.utcnow() - timedelta(
            days=settings.postgres_approval_retention_days
        )
        stmt = delete(ApprovalRequestORM).where(
            ApprovalRequestORM.status != "pending",
            ApprovalRequestORM.responded_at < approval_cutoff,
        )
        result = await session.execute(stmt)
        results["approvals_deleted"] = result.rowcount

        # Old audit logs (keep longer, but still cleanup)
        audit_cutoff = datetime.utcnow() - timedelta(days=settings.audit_log_retention_days)
        stmt = delete(AuditLogORM).where(AuditLogORM.timestamp < audit_cutoff)
        result = await session.execute(stmt)
        results["audit_logs_deleted"] = result.rowcount

        # Old session states (hot tier recovery checkpoints)
        state_cutoff = datetime.utcnow() - timedelta(days=7)
        stmt = delete(SessionStateORM).where(SessionStateORM.last_accessed < state_cutoff)
        result = await session.execute(stmt)
        results["session_states_deleted"] = result.rowcount

        await session.commit()

        return results

    async def _audit_redis_ttl(self) -> dict:
        """Audit Redis keys for TTL compliance. Sets TTL on keys that lack it."""
        if not self.session_memory._redis:
            return {"error": "redis_not_connected"}

        # Scan for hot-state keys that should have TTL
        patterns = ["hot:*", "approval:*", "task:*", "session:*"]
        total_keys = 0
        keys_without_ttl = 0
        ttl_set = 0

        for pattern in patterns:
            async for key in self.session_memory._redis.scan_iter(match=pattern, count=100):
                total_keys += 1
                ttl = await self.session_memory._redis.ttl(key)
                if ttl < 0:  # -1 = no TTL, -2 = key doesn't exist
                    keys_without_ttl += 1
                    # Set TTL based on key type
                    if key.startswith(b"approval:") or key.startswith(b"task:"):
                        await self.session_memory._redis.expire(
                            key, settings.redis_hot_ttl_hours * 3600
                        )
                    else:
                        await self.session_memory._redis.expire(
                            key, settings.redis_session_ttl_hours * 3600
                        )
                    ttl_set += 1

        return {
            "total_keys_scanned": total_keys,
            "keys_without_ttl": keys_without_ttl,
            "ttl_set": ttl_set,
        }
