"""
DLQ Recovery Service for AI-OSOP Distributed Coordination Bus.

This service continuously monitors pending messages in consumer groups,
claims failed messages after a timeout, and moves them to the Dead Letter Queue (DLQ).

Features:
- Automatic detection of stuck messages in Pending Entries List (PEL)
- Configurable retry count before permanent failure
- Moves permanently failed messages to DLQ for manual inspection
- Supports multiple consumer groups simultaneously
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, Optional

import redis.asyncio as redis

from ai_osop.core.config import settings

logger = logging.getLogger(__name__)


class DLQRecoveryService:
    """
    Background service that recovers failed messages from consumer groups.

    Usage:
        service = DLQRecoveryService(redis_url="redis://localhost:6379")
        await service.start()

        # Runs in background until stop() is called
        await asyncio.sleep(3600)  # Run for an hour

        await service.stop()
    """

    def __init__(
        self,
        # FIX (redis-url-settings-2026-08-23): default was hardcoded to 6379 and
        # ignored OSOP_REDIS_URI. Resolve from settings so deployments on a
        # non-default Redis port (e.g. the compose remap to 6381) are honored.
        redis_url: Optional[str] = None,
        engagement_id: str = "default",
        max_retries: int = 3,
        min_idle_time_ms: int = 5000,  # 5 seconds
        check_interval_sec: int = 10,
    ):
        self.redis_url = redis_url or settings.redis_uri
        self.engagement_id = engagement_id
        self.stream_name = f"aiosop:{engagement_id}:events"
        self.dlq_stream = f"aiosop:{engagement_id}:dlq"
        self.max_retries = max_retries
        self.min_idle_time_ms = min_idle_time_ms
        self.check_interval_sec = check_interval_sec

        self.redis: Optional[redis.Redis] = None
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._stats = {
            "messages_recovered": 0,
            "messages_moved_to_dlq": 0,
            "consumer_groups_checked": 0,
            "last_check": None,
        }

    async def connect(self):
        """Establish Redis connection."""
        self.redis = redis.from_url(self.redis_url, decode_responses=True)
        await self.redis.ping()
        logger.info(f"DLQ Recovery Service connected to Redis")

        # Ensure DLQ stream exists
        await self.redis.xadd(self.dlq_stream, {"init": "true"})
        await self.redis.xtrim(self.dlq_stream, maxlen=10000, approximate=True)

    async def disconnect(self):
        """Close Redis connection."""
        if self.redis:
            # FIX (redis-aclose-2026-08-24): deprecated close() -> aclose().
            await self.redis.aclose()
            logger.info("DLQ Recovery Service disconnected")

    async def start(self):
        """Start the background recovery loop."""
        if self._running:
            logger.warning("DLQ Recovery Service already running")
            return

        await self.connect()
        self._running = True
        self._task = asyncio.create_task(self._recovery_loop())
        logger.info("DLQ Recovery Service started")

    async def stop(self):
        """Stop the background recovery loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self.disconnect()
        logger.info("DLQ Recovery Service stopped")

    async def _recovery_loop(self):
        """Main recovery loop - runs continuously."""
        while self._running:
            try:
                await self._check_and_recover()
                self._stats["last_check"] = datetime.utcnow().isoformat()
                await asyncio.sleep(self.check_interval_sec)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Recovery loop error: {e}")
                await asyncio.sleep(self.check_interval_sec)

    async def _check_and_recover(self):
        """Check all consumer groups and recover failed messages."""
        try:
            # Get all consumer groups for this stream
            stream_info = await self.redis.xinfo_groups(self.stream_name)

            for group_info in stream_info:
                group_name = group_info["name"]
                self._stats["consumer_groups_checked"] += 1

                # Get pending messages for this group
                pending = await self.redis.xpending_range(
                    self.stream_name,
                    group_name,
                    min="-",
                    max="+",
                    count=100,  # Process up to 100 pending messages at a time
                )

                for pending_msg in pending:
                    message_id = pending_msg["message_id"]
                    consumer = pending_msg["consumer"]
                    times_delivered = pending_msg["times_delivered"]
                    idle_time = pending_msg["time_since_delivered"]

                    # Check if message has been idle too long
                    if idle_time >= self.min_idle_time_ms:
                        await self._handle_failed_message(
                            group_name, consumer, message_id, times_delivered, idle_time
                        )

        except Exception as e:
            logger.error(f"Error checking consumer groups: {e}")

    async def _handle_failed_message(
        self, group_name: str, consumer: str, message_id: str, times_delivered: int, idle_time: int
    ):
        """Handle a failed message - retry or move to DLQ."""
        try:
            # Claim the message to our recovery consumer
            claimed = await self.redis.xclaim(
                self.stream_name,
                group_name,
                "dlq_recovery_service",
                min_idle_time=self.min_idle_time_ms,
                message_ids=[message_id],
            )

            if not claimed:
                logger.debug(f"Message {message_id} no longer exists")
                return

            # Extract message data
            _, fields = claimed[0]

            # Check if max retries exceeded
            if times_delivered >= self.max_retries:
                # Move to DLQ permanently
                await self._move_to_dlq(
                    message_id,
                    fields,
                    group_name,
                    consumer,
                    times_delivered,
                    idle_time,
                    reason=f"Max retries ({self.max_retries}) exceeded",
                )
                self._stats["messages_moved_to_dlq"] += 1

                # Acknowledge to remove from PEL
                await self.redis.xack(self.stream_name, group_name, message_id)
                logger.warning(
                    f"Moved message {message_id} to DLQ after {times_delivered} failures"
                )
            else:
                # Re-deliver by leaving it unacknowledged
                # Just log for monitoring
                logger.info(
                    f"Re-delivering message {message_id} "
                    f"(attempt {times_delivered + 1}/{self.max_retries})"
                )
                self._stats["messages_recovered"] += 1

        except Exception as e:
            logger.error(f"Error handling failed message {message_id}: {e}")

    async def _move_to_dlq(
        self,
        message_id: str,
        fields: Dict[str, str],
        original_group: str,
        original_consumer: str,
        times_delivered: int,
        idle_time: int,
        reason: str,
    ):
        """Move a failed message to the Dead Letter Queue."""
        dlq_entry = {
            "original_message_id": message_id,
            "original_stream": self.stream_name,
            "original_group": original_group,
            "original_consumer": original_consumer,
            "times_delivered": str(times_delivered),
            "idle_time_ms": str(idle_time),
            "failure_reason": reason,
            "moved_at": datetime.utcnow().isoformat(),
            "topic": fields.get("topic", "unknown"),
            "source": fields.get("source", "unknown"),
            "event_type": fields.get("type", "unknown"),
            "payload": fields.get("payload", "{}"),
        }

        await self.redis.xadd(self.dlq_stream, dlq_entry)
        logger.info(f"Message {message_id} added to DLQ: {reason}")

    def get_stats(self) -> Dict:
        """Get current recovery service statistics."""
        return self._stats.copy()


# Singleton instance
_recovery_service_instance: Optional[DLQRecoveryService] = None


def get_dlq_recovery_service(engagement_id: str = "default") -> DLQRecoveryService:
    """Get or create the global DLQ recovery service instance."""
    global _recovery_service_instance
    if _recovery_service_instance is None:
        _recovery_service_instance = DLQRecoveryService(engagement_id=engagement_id)
    return _recovery_service_instance


async def initialize_dlq_service(
    redis_url: str, engagement_id: str = "default"
) -> DLQRecoveryService:
    """Initialize and start the global DLQ recovery service."""
    global _recovery_service_instance
    _recovery_service_instance = DLQRecoveryService(
        redis_url=redis_url, engagement_id=engagement_id
    )
    await _recovery_service_instance.start()
    return _recovery_service_instance
