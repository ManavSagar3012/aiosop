import asyncio

import structlog
from sqlalchemy import select, update

from ai_osop.core.tracing import trace_span
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.memory.session_memory import OutboxORM, SessionMemory

logger = structlog.get_logger("ai_osop.memory.outbox_processor")

# Phase-1 issue #12: a perpetually-failing outbox entry previously retried
# forever (no max-attempts column, no DLQ path). 10 attempts at the default
# 5s interval = 50s of retries before the entry is marked DLQ and an alert
# is emitted — enough to ride out a transient Neo4j blip, short enough to
# surface a real bug (e.g. a malformed task payload) quickly.
MAX_ATTEMPTS = 10


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
            # Get unprocessed entries.
            # Phase-1 issue #12: skip entries already marked dlq=True so a
            # poison entry does not loop forever. An entry is retried up to
            # MAX_ATTEMPTS; once over the cap it is marked dlq=True and an
            # alert is emitted on the next tick.
            result = await session.execute(
                select(OutboxORM)
                .where(OutboxORM.processed == False, OutboxORM.dlq == False)
                .order_by(OutboxORM.created_at)
                .limit(100)
            )
            entries = result.scalars().all()

            # AIOSOP-OUTBOX-ASYNC-ORM (2026-08-03): snapshot every attribute the
            # loop touches BEFORE iterating. Both ``session.commit()`` (success
            # path) and ``session.rollback()`` (failure path) expire EVERY ORM
            # instance attached to this session — the SELECT-loaded ``entry``
            # objects are all affected by the first commit/rollback, so reading
            # ``entry.id`` on the SECOND row would trigger a synchronous
            # lazy-refresh that raises MissingGreenlet under the async engine
            # (SQLAlchemy 2.0.x, greenlet_spawn). The plain-value snapshot is
            # detached from the session and safe to read for every row.
            row_snaps = [
                (
                    entry.id,
                    entry.entity_type,
                    entry.entity_id,
                    entry.payload,
                    entry.attempt_count,
                )
                for entry in entries
            ]

            for row_id, entity_type, entity_id, payload, attempt_count in row_snaps:
                with trace_span("outbox.process_entry", attributes={"entity_id": entity_id}):
                    try:
                        if entity_type == "task":
                            # Reconstruct task from payload
                            from ai_osop.core.models import Task

                            task = Task(**payload)
                            await self.graph_memory.upsert_task(task)

                            # Mark as processed
                            await session.execute(
                                update(OutboxORM)
                                .where(OutboxORM.id == row_id)
                                .values(processed=True)
                            )
                            await session.commit()
                            logger.info(f"Processed outbox entry {row_id}")
                        elif entity_type == "vulnerability":
                            # AIOSOP-FINDINGS-OUTBOX: project a queued finding to
                            # Neo4j. _from_outbox=True so the projection cannot
                            # re-enqueue itself (infinite loop).
                            from ai_osop.core.models import Vulnerability

                            vuln = Vulnerability(**payload)
                            await self.graph_memory.add_vulnerability(vuln, _from_outbox=True)
                            await session.execute(
                                update(OutboxORM)
                                .where(OutboxORM.id == row_id)
                                .values(processed=True)
                            )
                            await session.commit()
                            logger.info(f"Projected finding outbox entry {row_id}")
                        elif entity_type == "endpoint":
                            # AIOSOP-FINDINGS-OUTBOX: project a queued endpoint to
                            # Neo4j. _from_outbox=True so projection can't re-enqueue.
                            from ai_osop.core.models import Endpoint

                            endpoint = Endpoint(**payload)
                            await self.graph_memory.add_endpoint(endpoint, _from_outbox=True)
                            await session.execute(
                                update(OutboxORM)
                                .where(OutboxORM.id == row_id)
                                .values(processed=True)
                            )
                            await session.commit()
                            logger.info(f"Projected endpoint outbox entry {row_id}")
                        elif entity_type == "asset":
                            from ai_osop.core.models import Asset

                            asset = Asset(**payload)
                            await self.graph_memory.add_asset(asset, _from_outbox=True)
                            await session.execute(
                                update(OutboxORM)
                                .where(OutboxORM.id == row_id)
                                .values(processed=True)
                            )
                            await session.commit()
                            logger.info(f"Projected asset outbox entry {row_id}")
                        elif entity_type == "attack_path":
                            # AIOSOP-ATTACK-OUTBOX: attack-path outbox entries carry
                            # a MINIMAL payload ({id, node_ids, edges, ...}) — a full
                            # AttackPath dump cannot round-trip (the model requires
                            # entry_node_id/goal_node_id/edge_ids/risk_score which the
                            # writer never persists). Re-run the same LEADS_TO Cypher
                            # the writer uses; _from_outbox=True keeps the projection
                            # from re-enqueuing (infinite loop / outbox growth).
                            await self.graph_memory.add_attack_path_from_outbox(payload)
                            await session.execute(
                                update(OutboxORM)
                                .where(OutboxORM.id == row_id)
                                .values(processed=True)
                            )
                            await session.commit()
                            logger.info(f"Projected attack_path outbox entry {row_id}")
                        else:
                            # Phase-1 issue #12: previously an unknown
                            # entity_type was silently skipped forever
                            # (never marked processed). Now it counts as an
                            # attempt so a misconfigured producer surfaces
                            # as a DLQ entry instead of looping silently.
                            raise ValueError(f"unknown outbox entity_type: {entity_type!r}")
                    except Exception as e:
                        # Phase-1 issue #12: increment attempt_count and
                        # record the error. Over MAX_ATTEMPTS, mark dlq=True
                        # so the entry is skipped on subsequent ticks and
                        # emits a single alert instead of retrying forever.
                        # ``row_id``/``attempt_count`` are plain values captured
                        # above (never ORM objects) — safe to use after the
                        # rollback, which expires session-attached instances and
                        # would otherwise raise MissingGreenlet on re-read.
                        attempt = (attempt_count or 0) + 1
                        over_cap = attempt >= MAX_ATTEMPTS
                        await session.rollback()
                        await session.execute(
                            update(OutboxORM)
                            .where(OutboxORM.id == row_id)
                            .values(
                                attempt_count=attempt,
                                last_error=str(e)[:512],
                                dlq=over_cap,
                            )
                        )
                        await session.commit()
                        if over_cap:
                            logger.error(
                                "outbox_entry_dlq_full",
                                entry_id=row_id,
                                entity_type=entity_type,
                                attempts=attempt,
                                error=str(e)[:300],
                            )
                        else:
                            logger.warning(
                                "outbox_entry_retry",
                                entry_id=row_id,
                                attempt=attempt,
                                max_attempts=MAX_ATTEMPTS,
                                error=str(e)[:300],
                            )
