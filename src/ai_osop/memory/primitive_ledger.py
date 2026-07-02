"""
Primitive Ledger — Neo4j persistence for raw security signals.

Every tool output (Nuclei, recon, diff-auth, JS analysis) is persisted as a
typed :Primitive node. Primitives are the shared substrate for the chain engine:
the Escalation Engine queries them, the Chain Composer groups them, and the
Triager Gate decides whether to promote a chain to a finding.

Key design rules
----------------
1. NEVER create a Finding directly from this layer — primitives are pre-finding.
2. MERGE on (engagement_id, primitive_type, dedup_key) so idempotent tool replays
   don't create duplicate nodes.
3. promote_to_finding() marks the primitive and writes the back-ref finding_id but
   does NOT create the Vulnerability node — that is the caller's responsibility.
"""

import json
import logging
from typing import Any, Dict, List, Optional

import structlog

from ai_osop.core.exceptions import GraphQueryError
from ai_osop.core.models import AttackChain, ChainStatus, PrimitiveLedger, PrimitiveType

logger = structlog.get_logger("ai_osop.primitive_ledger")

# ---------------------------------------------------------------------------
# Cypher templates
# ---------------------------------------------------------------------------

_MERGE_PRIMITIVE = """
MERGE (p:Primitive {
    engagement_id: $engagement_id,
    primitive_type: $primitive_type,
    dedup_key: $dedup_key
})
ON CREATE SET
    p.id              = $id,
    p.source          = $source,
    p.target          = $target,
    p.raw             = $raw,
    p.confidence      = $confidence,
    p.severity_hint   = $severity_hint,
    p.tags            = $tags,
    p.escalated_from  = $escalated_from,
    p.chain_id        = $chain_id,
    p.promoted        = false,
    p.finding_id      = null,
    p.created_at      = $created_at
ON MATCH SET
    p.confidence      = CASE WHEN $confidence > p.confidence
                             THEN $confidence ELSE p.confidence END,
    p.last_seen       = $created_at
RETURN p.id AS node_id, p.created_at AS created_at
"""

_MARK_PROMOTED = """
MATCH (p:Primitive {id: $primitive_id})
SET p.promoted  = true,
    p.finding_id = $finding_id
RETURN p.id
"""

_LINK_CHAIN = """
MATCH (p:Primitive {id: $primitive_id})
MATCH (c:Chain    {id: $chain_id})
MERGE (c)-[:INCLUDES]->(p)
SET p.chain_id = $chain_id
"""

_MERGE_CHAIN = """
MERGE (c:Chain {id: $chain_id})
ON CREATE SET
    c.engagement_id   = $engagement_id,
    c.title           = $title,
    c.description     = $description,
    c.status          = $status,
    c.confidence      = $confidence,
    c.severity        = $severity,
    c.poc_script      = $poc_script,
    c.created_at      = $created_at,
    c.updated_at      = $updated_at
ON MATCH SET
    c.status          = $status,
    c.confidence      = $confidence,
    c.poc_script      = $poc_script,
    c.updated_at      = $updated_at
RETURN c.id
"""

_QUERY_PRIMITIVES_BY_ENGAGEMENT = """
MATCH (p:Primitive {engagement_id: $engagement_id})
WHERE NOT p.promoted
RETURN p
ORDER BY p.confidence DESC
"""

_QUERY_UNESCALATED = """
MATCH (p:Primitive {engagement_id: $engagement_id})
WHERE NOT p.promoted
  AND (p.chain_id IS NULL OR p.chain_id = '')
RETURN p
ORDER BY p.confidence DESC
LIMIT $limit
"""

_SETUP_CONSTRAINTS = [
    "CREATE CONSTRAINT primitive_id IF NOT EXISTS FOR (p:Primitive) REQUIRE p.id IS UNIQUE",
    "CREATE CONSTRAINT chain_id IF NOT EXISTS FOR (c:Chain) REQUIRE c.id IS UNIQUE",
    # Compound uniqueness on the dedup triplet (supported as a node key in Neo4j 5+)
    "CREATE INDEX primitive_dedup IF NOT EXISTS FOR (p:Primitive) ON (p.engagement_id, p.primitive_type, p.dedup_key)",
    "CREATE INDEX primitive_eid   IF NOT EXISTS FOR (p:Primitive) ON (p.engagement_id)",
    "CREATE INDEX chain_eid       IF NOT EXISTS FOR (c:Chain)     ON (c.engagement_id)",
]


class PrimitiveLedgerStore:
    """Thin async persistence layer for :Primitive and :Chain nodes.

    Designed to be injected with a live ``GraphMemory._driver`` (the same
    neo4j.AsyncDriver instance used by the rest of the memory layer) so it
    shares a single connection pool. Usable standalone in tests via the
    ``driver`` constructor arg.
    """

    def __init__(self, driver: Any) -> None:
        """
        Args:
            driver: A ``neo4j.AsyncDriver`` instance (or a test double).
        """
        self._driver = driver

    async def setup_schema(self) -> None:
        """Create :Primitive and :Chain constraints/indexes (idempotent)."""
        async with self._driver.session() as session:
            for cypher in _SETUP_CONSTRAINTS:
                try:
                    await session.run(cypher)
                except Exception as e:
                    msg = str(e).lower()
                    if "equivalent" in msg or "already exists" in msg:
                        continue
                    logger.warning("ddl_failed", cypher=cypher[:80], error=str(e))

    # ------------------------------------------------------------------
    # Primitive persistence
    # ------------------------------------------------------------------

    async def upsert_primitive(self, primitive: PrimitiveLedger) -> str:
        """Persist a Primitive via MERGE (idempotent).

        Returns the canonical Neo4j node id (the primitive's id field after
        MERGE — which may differ from primitive.id if an existing node was
        matched).
        """
        try:
            async with self._driver.session() as session:
                result = await session.run(
                    _MERGE_PRIMITIVE,
                    {
                        "id": primitive.id,
                        "engagement_id": primitive.engagement_id,
                        "primitive_type": primitive.primitive_type.value,
                        "dedup_key": primitive.dedup_key,
                        "source": primitive.source,
                        "target": primitive.target,
                        "raw": json.dumps(primitive.raw),
                        "confidence": primitive.confidence,
                        "severity_hint": primitive.severity_hint,
                        "tags": primitive.tags,
                        "escalated_from": primitive.escalated_from or "",
                        "chain_id": primitive.chain_id or "",
                        "created_at": primitive.created_at.isoformat(),
                    },
                )
                record = await result.single()
                node_id = record["node_id"]
                logger.info(
                    "primitive_upserted",
                    id=node_id,
                    primitive_type=primitive.primitive_type.value,
                    engagement_id=primitive.engagement_id,
                )
                return node_id
        except Exception as exc:
            raise GraphQueryError(
                f"upsert_primitive failed: {exc}",
                context={"primitive_id": primitive.id},
            ) from exc

    async def promote_to_finding(self, primitive_id: str, finding_id: str) -> None:
        """Mark a Primitive as promoted and record the back-reference finding_id."""
        try:
            async with self._driver.session() as session:
                await session.run(
                    _MARK_PROMOTED,
                    {"primitive_id": primitive_id, "finding_id": finding_id},
                )
            logger.info(
                "primitive_promoted",
                primitive_id=primitive_id,
                finding_id=finding_id,
            )
        except Exception as exc:
            raise GraphQueryError(
                f"promote_to_finding failed: {exc}",
                context={"primitive_id": primitive_id},
            ) from exc

    async def query_unpromoted(
        self, engagement_id: str
    ) -> List[Dict[str, Any]]:
        """Return all unpromoted primitives for an engagement (raw Neo4j data)."""
        try:
            async with self._driver.session() as session:
                result = await session.run(
                    _QUERY_PRIMITIVES_BY_ENGAGEMENT,
                    {"engagement_id": engagement_id},
                )
                return [dict(record["p"]) async for record in result]
        except Exception as exc:
            raise GraphQueryError(
                f"query_unpromoted failed: {exc}",
                context={"engagement_id": engagement_id},
            ) from exc

    async def query_unescalated(
        self, engagement_id: str, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Return primitives not yet assigned to any chain, for escalation."""
        try:
            async with self._driver.session() as session:
                result = await session.run(
                    _QUERY_UNESCALATED,
                    {"engagement_id": engagement_id, "limit": limit},
                )
                return [dict(record["p"]) async for record in result]
        except Exception as exc:
            raise GraphQueryError(
                f"query_unescalated failed: {exc}",
                context={"engagement_id": engagement_id},
            ) from exc

    # ------------------------------------------------------------------
    # Chain persistence
    # ------------------------------------------------------------------

    async def upsert_chain(self, chain: AttackChain) -> str:
        """Persist or update an AttackChain node and link its primitives."""
        try:
            async with self._driver.session() as session:
                # Upsert the Chain node
                await session.run(
                    _MERGE_CHAIN,
                    {
                        "chain_id": chain.id,
                        "engagement_id": chain.engagement_id,
                        "title": chain.title,
                        "description": chain.description,
                        "status": chain.status.value,
                        "confidence": chain.confidence,
                        "severity": chain.severity,
                        "poc_script": json.dumps(chain.poc_script),
                        "created_at": chain.created_at.isoformat(),
                        "updated_at": chain.updated_at.isoformat(),
                    },
                )
                # Link each primitive to the chain
                for prim_id in chain.primitive_ids:
                    try:
                        await session.run(
                            _LINK_CHAIN,
                            {"primitive_id": prim_id, "chain_id": chain.id},
                        )
                    except Exception as link_exc:
                        logger.warning(
                            "chain_link_failed",
                            chain_id=chain.id,
                            primitive_id=prim_id,
                            error=str(link_exc),
                        )
            logger.info(
                "chain_upserted",
                chain_id=chain.id,
                status=chain.status.value,
                primitives=len(chain.primitive_ids),
            )
            return chain.id
        except Exception as exc:
            raise GraphQueryError(
                f"upsert_chain failed: {exc}",
                context={"chain_id": chain.id},
            ) from exc
