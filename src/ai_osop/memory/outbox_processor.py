import asyncio
import structlog
from sqlalchemy import select, update
from ai_osop.memory.session_memory import OutboxORM, SessionMemory
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.core.tracing import trace_span

logger = structlog.get_logger("ai_osop.memory.outbox_processor")

class OutboxProcessor:
    def __init__(self, session_memory: SessionMemory, graph_memory: GraphMemory, interval: int = 5):
        self.session_memory = session_memory
        self.graph_memory = graph_memory
        self.interval = interval
        self._running = False

    async def run(self):
        self._running = True
        logger.info("OutboxProcessor started")
        while self._running:
            try:
                await self.process_batch()
            except Exception as e:
                logger.error("OutboxProcessor error", error=str(e))
            await asyncio.sleep(self.interval)

    async def stop(self):
        self._running = False
        logger.info("OutboxProcessor stopped")

    async def process_batch(self):
        async with self.session_memory._async_session() as session:
            # Get unprocessed entries
            result = await session.execute(
                select(OutboxORM).where(OutboxORM.processed == False).order_by(OutboxORM.created_at).limit(100)
            )
            entries = result.scalars().all()

            for entry in entries:
                with trace_span("outbox.process_entry", attributes={"entity_id": entry.entity_id}):
                    try:
                        if entry.entity_type == "task":
                            # Reconstruct task from payload
                            from ai_osop.core.models import Task
                            task = Task(**entry.payload)
                            await self.graph_memory.upsert_task(task)
                            
                            # Mark as processed
                            await session.execute(
                                update(OutboxORM).where(OutboxORM.id == entry.id).values(processed=True)
                            )
                            await session.commit()
                            logger.info(f"Processed outbox entry {entry.id}")
                    except Exception as e:
                        logger.error(f"Failed to process outbox entry {entry.id}", error=str(e))
                        # Don't commit, will retry
                        await session.rollback()
