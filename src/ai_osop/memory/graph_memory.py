"""
Graph Memory Layer (Neo4j)
Attack graph construction, pathfinding, and risk propagation.
"""

import asyncio
import hashlib
import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from cachetools import TTLCache
from neo4j import AsyncDriver, AsyncGraphDatabase
from neo4j.exceptions import ServiceUnavailable

from ai_osop.core.config import settings
from ai_osop.core.models import (
    Asset,
    AttackPath,
    BusinessInvariant,
    DiffAuthFinding,
    Endpoint,
    Exploit,
    Hypothesis,
    Vulnerability,
    Workflow,
    WorkflowStep,
    WorkflowTransition,
)
from ai_osop.core.observability import record_neo4j_pool_metrics
from ai_osop.core.tracing import trace_span
from ai_osop.reliability.retry import retry_with_backoff

logger = logging.getLogger(__name__)
logging.getLogger("neo4j").setLevel(logging.ERROR)


class GraphMemory:
    """
    Neo4j-backed attack graph with offensive security schema.

    Schema:
    - (:Asset)-[:HAS_ENDPOINT]->(:Endpoint)
    - (:Endpoint)-[:HAS_VULNERABILITY]->(:Vulnerability)
    - (:Vulnerability)-[:EXPLOITED_BY]->(:Exploit)
    - (:Exploit)-[:USES_PAYLOAD]->(:Payload)
    - (:Vulnerability)-[:LEADS_TO]->(:Vulnerability)
    - (:Asset)-[:DEPENDS_ON]->(:Asset)
    - (:Identity)-[:CAN_ACCESS]->(:Endpoint)
    - (:Exploit)-[:ESCALATES_TO]->(:Identity)
    """

    def __init__(self):
        self._driver: Optional[AsyncDriver] = None
        self._initialized = False
        # Optional P2 learning-brain hook. When wired (app lifespan), every real
        # persisted vulnerability is also recorded into semantic findings memory,
        # so past engagements inform future ones. Left None in minimal setups/tests
        # so GraphMemory stays decoupled from embeddings/LLM.
        self.findings_knowledge: Optional[Any] = None
        # Optional chain-first hook. When wired (app lifespan), every confirmed
        # finding is also recorded as a typed primitive so the escalation/chain
        # engine can chain co-located signals. Left None so GraphMemory stays
        # decoupled from the ledger in minimal setups/tests.
        self.primitive_ledger: Optional[Any] = None
        # Optional P2b calibration engine. When wired, validate_vulnerability()
        # records accepted findings into the Beta-Binomial feedback loop.
        self.calibration_engine: Optional[Any] = None
        # Optional coordination bus. When wired (app lifespan), every persisted
        # finding publishes a 'finding.recorded' event so the reasoning loop
        # and other subscribers can react immediately. Left None so GraphMemory
        # stays decoupled from the bus in minimal setups/tests.
        self.coordination_bus: Optional[Any] = None
        # Optional AIOSOP-FINDINGS-OUTBOX sink (a SessionMemory). When wired (app
        # lifespan), a Neo4j outage during a finding write queues the finding to the
        # Postgres outbox for replay instead of losing it. Left None in minimal/test
        # setups so GraphMemory stays decoupled from Postgres (memory obs 3047).
        self.outbox_sink: Optional[Any] = None

        # AIOSOP-CACHE-001 (2026-07-22): TTLCache for get_graph_stats results.
        # Phase monitor calls this on every tick for each active engagement
        # (via _resolve_auto_next). Cache for 10s since graph stats change
        # infrequently (only when new Vulnerability/Endpoint nodes are added).
        self._graph_stats_cache: TTLCache = TTLCache(maxsize=128, ttl=10)

        # AIOSOP-NEO4J-POOL-METRICS-002 (2026-07-22): periodic pool metric export.
        # Background loop runs every 15s so Prometheus gauges reflect live pool
        # health (in-use connections, closed state) rather than a startup snapshot.
        self._pool_metrics_running = False
        self._pool_metrics_task: Optional[asyncio.Task] = None

    async def connect(self) -> None:
        """Initialize Neo4j connection with exponential backoff retry.

        Sprint 7: Survives Neo4j restarts during startup without crashing the platform.

        AIOSOP-NEO4J-POOL-METRICS-001 (2026-07-22): After a successful connection,
        export pool metrics so Prometheus immediately reflects real pool health
        rather than showing 0/False until the first periodic export tick.
        """

        async def _connect() -> None:
            self._driver = AsyncGraphDatabase.driver(
                settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password)
            )
            await self._driver.verify_connectivity()
            self._initialized = True

        await retry_with_backoff(
            _connect,
            max_retries=5,
            base_delay=1.0,
            max_delay=30.0,
            exceptions=(ServiceUnavailable, Exception),
            retry_name="neo4j.connect",
        )

        # Create indexes and constraints
        await self._setup_schema()

        # Export initial pool metrics after successful connection
        await self._export_pool_metrics()

    async def _setup_schema(self) -> None:
        """Create indexes and constraints for performance."""
        constraints = [
            "CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (a:Asset) REQUIRE a.id IS UNIQUE",
            "CREATE CONSTRAINT endpoint_id IF NOT EXISTS FOR (e:Endpoint) REQUIRE e.id IS UNIQUE",
            "CREATE CONSTRAINT vuln_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
            "CREATE CONSTRAINT exploit_id IF NOT EXISTS FOR (x:Exploit) REQUIRE x.id IS UNIQUE",
            "CREATE CONSTRAINT payload_id IF NOT EXISTS FOR (p:Payload) REQUIRE p.id IS UNIQUE",
            "CREATE CONSTRAINT diff_auth_id "
            "IF NOT EXISTS FOR (d:DiffAuthFinding) REQUIRE d.id IS UNIQUE",
            "CREATE CONSTRAINT evidence_id "
            "IF NOT EXISTS FOR (ev:Evidence) REQUIRE ev.id IS UNIQUE",
            "CREATE CONSTRAINT hypothesis_id "
            "IF NOT EXISTS FOR (h:Hypothesis) REQUIRE h.id IS UNIQUE",
            "CREATE CONSTRAINT workflow_id IF NOT EXISTS FOR (w:Workflow) REQUIRE w.id IS UNIQUE",
            "CREATE CONSTRAINT step_id IF NOT EXISTS FOR (s:Step) REQUIRE s.id IS UNIQUE",
            "CREATE CONSTRAINT task_id IF NOT EXISTS FOR (t:Task) REQUIRE t.id IS UNIQUE",
            "CREATE CONSTRAINT engagement_id "
            "IF NOT EXISTS FOR (e:Engagement) REQUIRE e.engagement_id IS UNIQUE",
            "CREATE CONSTRAINT auto_discovery_claim_eid "
            "IF NOT EXISTS FOR (c:AutoDiscoveryClaim) REQUIRE c.engagement_id IS UNIQUE",
            "CREATE CONSTRAINT taxonomy_node_id "
            "IF NOT EXISTS FOR (t:TaxonomyNode) REQUIRE t.id IS UNIQUE",
            "CREATE CONSTRAINT identity_id IF NOT EXISTS FOR (i:Identity) REQUIRE i.id IS UNIQUE",
            "CREATE CONSTRAINT credential_id "
            "IF NOT EXISTS FOR (c:Credential) REQUIRE c.id IS UNIQUE",
            "CREATE CONSTRAINT session_id IF NOT EXISTS FOR (s:Session) REQUIRE s.id IS UNIQUE",
            "CREATE CONSTRAINT role_id IF NOT EXISTS FOR (r:Role) REQUIRE r.id IS UNIQUE",
        ]

        indexes = [
            "CREATE INDEX endpoint_type_idx IF NOT EXISTS FOR (e:Endpoint) ON (e.type)",
            "CREATE INDEX endpoint_eid_idx IF NOT EXISTS FOR (e:Endpoint) ON (e.engagement_id)",
            "CREATE INDEX endpoint_url_idx IF NOT EXISTS FOR (e:Endpoint) ON (e.url)",
            "CREATE INDEX task_eid_idx IF NOT EXISTS FOR (t:Task) ON (t.engagement_id)",
            "CREATE INDEX task_status_idx IF NOT EXISTS FOR (t:Task) ON (t.status)",
            "CREATE INDEX vuln_eid_idx IF NOT EXISTS FOR (v:Vulnerability) ON (v.engagement_id)",
            "CREATE INDEX vuln_class_idx IF NOT EXISTS FOR (v:Vulnerability) ON (v.vuln_class)",
            "CREATE INDEX replay_eid_idx IF NOT EXISTS FOR (r:ReplayResult) ON (r.engagement_id)",
            "CREATE INDEX authtest_eid_idx "
            "IF NOT EXISTS FOR (a:AuthorizationTest) ON (a.engagement_id)",
            "CREATE INDEX diffauth_eid_idx "
            "IF NOT EXISTS FOR (d:DiffAuthFinding) ON (d.engagement_id)",
            "CREATE INDEX evidence_eid_idx IF NOT EXISTS FOR (e:Evidence) ON (e.engagement_id)",
            "CREATE INDEX workflow_eid_idx IF NOT EXISTS FOR (w:Workflow) ON (w.engagement_id)",
            "CREATE INDEX asset_type_value IF NOT EXISTS FOR (a:Asset) ON (a.type, a.value)",
            "CREATE INDEX vuln_type_confidence "
            "IF NOT EXISTS FOR (v:Vulnerability) ON (v.vuln_type, v.confidence)",
            "CREATE INDEX exploit_timestamp IF NOT EXISTS FOR (x:Exploit) ON (x.timestamp)",
            "CREATE INDEX diff_auth_category "
            "IF NOT EXISTS FOR (d:DiffAuthFinding) ON (d.category, d.engagement_id)",
            "CREATE INDEX hypothesis_category "
            "IF NOT EXISTS FOR (h:Hypothesis) ON (h.category, h.engagement_id)",
            "CREATE INDEX hypothesis_confidence "
            "IF NOT EXISTS FOR (h:Hypothesis) ON (h.confidence, h.engagement_id)",
        ]

        async with self._driver.session() as session:
            for cypher in constraints + indexes:
                try:
                    await session.run(cypher)
                except Exception as e:
                    msg = str(e).lower()
                    # Only swallow the benign "already exists / equivalent rule" case.
                    # Surface anything else (e.g. a uniqueness constraint that cannot
                    # be created because duplicate nodes already exist in the DB).
                    if "equivalent" in msg or "already exists" in msg:
                        continue
                    logger.warning("DDL statement failed: %s | error: %s", cypher, e)

    async def _enqueue_outbox(self, entity_type: str, entity_id: str, payload: dict) -> None:
        """Enqueue a graph write for async projection via the durable Postgres outbox.

        AIOSOP-FINDINGS-OUTBOX extends beyond vulns: assets, endpoints, attacks, and
        other graph-mutating calls all need an outbox safety net so a Neo4j outage
        no longer loses the entity with zero audit trail. Passed through the
        session's Postgres outbox and re-projected on recovery by OutboxProcessor.
        """
        _sink = getattr(self, "outbox_sink", None)
        if _sink is None:
            return
        await _sink.enqueue_outbox(entity_type, entity_id, payload)

    async def add_asset(self, asset: Asset) -> str:
        """Add or update an Asset node. Post the write path through the outbox."""
        with trace_span(
            "neo4j.add_asset",
            attributes={
                "ai_osop.asset_id": asset.id,
                "ai_osop.engagement_id": asset.engagement_id,
                "ai_osop.asset_type": asset.type,
            },
        ):
            cypher = """
            MERGE (a:Asset {id: $id})
            SET a.type = $type,
                a.value = $value,
                a.source = $source,
                a.confidence = $confidence,
                a.metadata = $metadata,
                a.first_seen = CASE
                    WHEN a.first_seen IS NULL
                    THEN $first_seen ELSE a.first_seen END,
                a.last_seen = $last_seen,
                a.engagement_id = $engagement_id
            RETURN a.id
            """

            payload = {
                "id": asset.id,
                "type": asset.type,
                "value": asset.value,
                "source": asset.source,
                "confidence": asset.confidence,
                "metadata": asset.metadata,
                "first_seen": asset.first_seen.isoformat(),
                "last_seen": asset.last_seen.isoformat(),
                "engagement_id": asset.engagement_id,
            }

            try:
                async with self._driver.session() as session:
                    result = await session.run(cypher, payload)
                    record = await result.single()
                    return record["a.id"] if record else asset.id
            except Exception as neo_err:  # noqa: BLE001 - outbox durability net below
                await self._enqueue_outbox("asset", asset.id, payload)
                logger.warning(
                    "asset_neo4j_write_failed_queued_for_replay id=%s error=%s",
                    asset.id,
                    neo_err,
                )
                raise

    async def add_endpoint(self, endpoint: Endpoint) -> str:
        """Add or update an Endpoint node. Post the write through the outbox."""
        cypher = """
        MERGE (e:Endpoint {id: $id})
        SET e.url = $url,
            e.method = $method,
            e.type = $type,
            e.status_code = $status_code,
            e.title = $title,
            e.technologies = $technologies,
            e.parameters = $parameters,
            e.auth_required = $auth_required,
            e.source = $source,
            e.confidence = $confidence,
            e.engagement_id = $engagement_id,
            e.screenshot_path = $screenshot_path,
            e.host = $host,
            e.path = $path,
            e.query_keys = $query_keys,
            e.has_body = $has_body,
            e.content_type = $content_type,
            e.body_schema_keys = $body_schema_keys,
            e.auth_class = $auth_class,
            e.request_headers_sample = $request_headers_sample,
            e.status_codes_seen = $status_codes_seen,
            e.response_size_avg = $response_size_avg,
            e.response_content_type = $response_content_type,
            e.user_label = $user_label,
            e.workflow_id = $workflow_id,
            e.first_seen = CASE WHEN e.first_seen IS NULL THEN $first_seen ELSE e.first_seen END,
            e.last_seen = $last_seen,
            e.observations = $observations
        WITH e
        OPTIONAL MATCH (a:Asset {id: $asset_id})
        FOREACH (x IN CASE WHEN a IS NOT NULL THEN [a] ELSE [] END |
            MERGE (a)-[:HAS_ENDPOINT]->(e)
        )
        WITH e
        OPTIONAL MATCH (w:Workflow {id: $workflow_id})
        FOREACH (x IN CASE WHEN w IS NOT NULL THEN [w] ELSE [] END |
            MERGE (w)-[:CALLED]->(e)
        )
        RETURN e.id AS id
        """

        payload = {
            "id": endpoint.id,
            "url": endpoint.url,
            "method": endpoint.method,
            "type": endpoint.type,
            "status_code": endpoint.status_code,
            "title": endpoint.title,
            "technologies": endpoint.technologies,
            "parameters": endpoint.parameters,
            "auth_required": endpoint.auth_required,
            "source": endpoint.source,
            "confidence": endpoint.confidence,
            "engagement_id": endpoint.engagement_id,
            "screenshot_path": endpoint.screenshot_path,
            "asset_id": endpoint.asset_id,
            "host": endpoint.host,
            "path": endpoint.path,
            "query_keys": endpoint.query_keys,
            "has_body": endpoint.has_body,
            "content_type": endpoint.content_type,
            "body_schema_keys": endpoint.body_schema_keys,
            "auth_class": endpoint.auth_class,
            "request_headers_sample": json.dumps(endpoint.request_headers_sample),
            "status_codes_seen": endpoint.status_codes_seen,
            "response_size_avg": endpoint.response_size_avg,
            "response_content_type": endpoint.response_content_type,
            "user_label": endpoint.user_label,
            "workflow_id": endpoint.workflow_id,
            "first_seen": endpoint.first_seen.isoformat(),
            "last_seen": endpoint.last_seen.isoformat(),
            "observations": endpoint.observations,
        }

        try:
            async with self._driver.session() as session:
                with trace_span(
                    "graph_memory.add_endpoint",
                    attributes={
                        "endpoint_id": endpoint.id,
                        "endpoint_type": endpoint.type,
                        "engagement_id": endpoint.engagement_id,
                    },
                ):
                    result = await session.run(cypher, payload)
                    record = await result.single()
                    # Invalidate graph stats cache since we added a new node
                    await self.invalidate_graph_stats_cache(endpoint.engagement_id)
                    return record["id"] if record else endpoint.id
        except Exception as neo_err:  # noqa: BLE001 - outbox durability net below
            await self._enqueue_outbox("endpoint", endpoint.id, payload)
            logger.warning(
                "endpoint_neo4j_write_failed_queued_for_replay id=%s error=%s",
                endpoint.id,
                neo_err,
            )
            raise

    async def _write_vulnerability_cypher(self, vuln: Any, cypher: str, params: dict) -> Any:
        """Execute the Vulnerability upsert Cypher and return the single record.

        Extracted so add_vulnerability can wrap it with the outbox durability net
        (AIOSOP-FINDINGS-OUTBOX) and so OutboxProcessor can replay a queued finding
        via add_vulnerability(_from_outbox=True) without re-enqueuing it.
        """
        async with self._driver.session() as session:
            with trace_span(
                "graph_memory.add_vulnerability",
                attributes={
                    "vuln_id": vuln.id,
                    "vuln_type": vuln.vuln_type.value,
                    "engagement_id": vuln.engagement_id,
                },
            ):
                result = await session.run(cypher, params)
                return await result.single()

    async def add_vulnerability(self, vuln: Vulnerability, _from_outbox: bool = False) -> str:
        """Add a Vulnerability and link to its Endpoint."""
        # OSOP-P0-02: refuse to persist simulated/mock findings into the real graph unless
        # explicitly allowed. Without this, fabricated findings flow into the corpus,
        # reports, and dashboard counts as if they were real observations.
        from ai_osop.core.config import settings as _settings

        if vuln.is_simulated() and not getattr(_settings, "allow_simulated_findings", False):
            logger.warning(
                "rejected_simulated_vulnerability id=%s tool_source=%s title=%s engagement=%s",
                vuln.id,
                vuln.tool_source,
                vuln.title,
                vuln.engagement_id,
            )
            return vuln.id

        # Defense in depth for Nuclei normalization: an HTTP-status-only match on
        # a Next.js/SPA response is a discovery signal, not exploit evidence.  The
        # agent flags it before calling us; repeat the downgrade at the persistence
        # boundary so an alternate producer cannot bypass that validation.
        self._apply_nuclei_spa_persistence_guard(vuln)
        dedup_key = self._vulnerability_dedup_key(vuln)

        cypher = """
        // Identity guard (AIOSOP-UPSERT-IDEMPOTENT): a caller-supplied id (e.g. the
        // upsert_verified_finding MCP tool, restart-recovery, re-import) may already
        // exist on a node with a DIFFERENT dedup_key. Setting v.id = $id on the CREATE
        // branch would then violate the unique-id constraint and abort the whole
        // upsert. Detect the clash up front and mint a fresh id instead, so a genuinely
        // new finding is still persisted rather than crashing. Dedup identity remains
        // the content-based dedup_key; the external id is non-authoritative on clash.
        OPTIONAL MATCH (idclash:Vulnerability {id: $id})
        WITH idclash
        MERGE (v:Vulnerability {dedup_key: $dedup_key})
        ON CREATE SET v.id = CASE WHEN idclash IS NULL THEN $id ELSE $fresh_id END,
            v.created_at = $created_at,
            v.duplicate_count = 0
        ON MATCH SET v.duplicate_count = coalesce(v.duplicate_count, 0) + 1
        SET v.cwe = $cwe,
            v.vuln_type = $vuln_type,
            v.severity = $severity,
            v.cvss_score = $cvss_score,
            v.title = $title,
            v.description = $description,
            v.evidence = $evidence,
            v.tool_source = $tool_source,
            v.confidence = $confidence,
            v.entry_point = $entry_point,
            v.requires_auth = $requires_auth,
            v.validated = $validated,
            v.exploitability = $exploitability,
            v.impact = $impact,
            v.endpoint_id = $endpoint_id,
            v.engagement_id = $engagement_id,
            v.last_seen = $created_at
        WITH v
        OPTIONAL MATCH (e:Endpoint {id: $endpoint_id})
        // AIOSOP-GRAPHLINK-001 (2026-07-03): fall back to HOST-based linking when
        // endpoint_id is absent/unmatched. nuclei findings carry no endpoint_id, so
        // every Vulnerability was created with endpoint_id=None -> 0 HAS_VULNERABILITY
        // edges platform-wide (898/898 orphaned), leaving the "attack graph" a set of
        // disconnected nodes. Link the vuln to an endpoint of the SAME engagement whose
        // host matches the vuln's evidence host, so the graph is actually connected and
        // attack-path/impact analysis has edges to traverse.
        OPTIONAL MATCH (eh:Endpoint {engagement_id: $engagement_id})
            WHERE e IS NULL AND $host <> '' AND (eh.host = $host OR eh.url CONTAINS $host)
        WITH v, e, collect(eh)[0] AS ehost
        FOREACH (x IN CASE WHEN e IS NOT NULL THEN [e] ELSE [] END |
            MERGE (e)-[:HAS_VULNERABILITY]->(v)
        )
        FOREACH (x IN CASE WHEN e IS NULL AND ehost IS NOT NULL THEN [ehost] ELSE [] END |
            MERGE (ehost)-[:HAS_VULNERABILITY]->(v)
        )
        // 'created' derives from duplicate_count (0 on ON CREATE, >=1 after ON MATCH),
        // NOT from v.id = $id — the id may be a freshly-minted clash-avoidance id on
        // create, and on match it is the original id, so an id comparison misreports.
        RETURN v.id AS id, v.duplicate_count = 0 AS created
        """

        # AIOSOP-GRAPHLINK-001: derive a host from the vuln's evidence (nuclei/burp put
        # the matched URL there) so the Cypher above can link by host when endpoint_id
        # is unset. Best-effort — a parse failure just means we fall back to no link.
        vuln_host = ""
        try:
            from urllib.parse import urlsplit

            for ev in vuln.evidence or []:
                if not isinstance(ev, dict):
                    continue
                candidate = ev.get("matched_at") or ev.get("url") or ev.get("host")
                if candidate:
                    raw = str(candidate)
                    netloc = urlsplit(raw if "://" in raw else "http://" + raw).netloc
                    if netloc:
                        vuln_host = netloc.split("@")[-1].split(":")[0].lower()
                        break
        except Exception:  # noqa: BLE001 - host derivation is best-effort
            vuln_host = ""

        params = {
            "id": vuln.id,
            "fresh_id": f"vuln-{uuid.uuid4().hex[:12]}",
            "dedup_key": dedup_key,
            "host": vuln_host,
            "cwe": vuln.cwe,
            "vuln_type": vuln.vuln_type.value,
            "severity": vuln.severity.value,
            "cvss_score": vuln.cvss_score,
            "title": vuln.title,
            "description": vuln.description,
            "evidence": json.dumps(vuln.evidence, default=str),
            "tool_source": vuln.tool_source,
            "confidence": vuln.confidence,
            "entry_point": vuln.entry_point,
            "requires_auth": vuln.requires_auth,
            "validated": vuln.validated,
            "exploitability": vuln.exploitability,
            "impact": vuln.impact,
            "engagement_id": vuln.engagement_id,
            "created_at": vuln.created_at.isoformat(),
            "endpoint_id": vuln.endpoint_id,
        }
        try:
            record = await self._write_vulnerability_cypher(vuln, cypher, params)
        except Exception as neo_err:  # noqa: BLE001 - durability net below
            # AIOSOP-FINDINGS-OUTBOX: a Neo4j outage during a finding write
            # previously LOST the finding (only tasks were in the outbox). Queue it
            # durably in Postgres so OutboxProcessor projects it to Neo4j on
            # recovery. _from_outbox guards the replay path so the projector cannot
            # re-enqueue (infinite loop).
            # getattr, not attribute access: some paths build GraphMemory via
            # __new__ (bypassing __init__), so the optional hook may be absent.
            _sink = getattr(self, "outbox_sink", None)
            if _sink is not None and not _from_outbox:
                try:
                    await _sink.enqueue_outbox(
                        "vulnerability", vuln.id, vuln.model_dump(mode="json")
                    )
                    logger.warning(
                        "vuln_neo4j_write_failed_queued_for_replay id=%s error=%s",
                        vuln.id,
                        neo_err,
                    )
                    return vuln.id
                except Exception as ob_err:  # noqa: BLE001 - Postgres also unavailable
                    logger.error("vuln_outbox_enqueue_failed id=%s error=%s", vuln.id, ob_err)
            raise

        # Compatibility for persisted records returned by older query mocks or a
        # rolling deployment before every worker has the new RETURN aliases.
        created = record.get("created", True)
        persisted_id = record.get("id") or record["v.id"]

        # P2 learning brain: auto-record this real finding into semantic memory.
        # Best-effort — a KB failure must never break graph persistence, and the
        # finding is already confirmed non-simulated by the guard above.
        if created and self.findings_knowledge is not None:
            try:
                await self.findings_knowledge.record_finding(vuln)
            except Exception as e:  # noqa: BLE001 - knowledge recording is best-effort
                logger.warning("findings_knowledge_record_failed id=%s error=%s", vuln.id, e)

        # Event-driven finding publication: broadcast a finding.recorded event on
        # the coordination bus so the reasoning loop (and any other subscriber)
        # can immediately generate chain hypotheses or trigger follow-up work.
        if created:
            await self._publish_finding_event(vuln, persisted_id)

        # Chain-first loop: record this confirmed finding as a typed primitive so the
        # escalation/chain engine can chain it with co-located signals. Best-effort;
        # a ledger failure must never break graph persistence.
        if created and self.primitive_ledger is not None:
            try:
                from ai_osop.core.chain_analysis import vuln_to_primitive

                await self.primitive_ledger.upsert_primitive(vuln_to_primitive(vuln))
            except Exception as e:  # noqa: BLE001 - primitive recording is best-effort
                logger.warning("primitive_ledger_record_failed id=%s error=%s", vuln.id, e)

        if not created:
            logger.info(
                "deduplicated_vulnerability incoming_id=%s existing_id=%s dedup_key=%s",
                vuln.id,
                persisted_id,
                dedup_key,
            )
        # Invalidate graph stats cache since we persisted a new (or updated) node
        await self.invalidate_graph_stats_cache(vuln.engagement_id)
        return persisted_id

    async def _publish_finding_event(self, vuln: Vulnerability, persisted_id: str) -> None:
        """Publish a 'finding.recorded' event on the coordination bus.

        Event-driven finding publication: every persisted finding triggers an
        event so the reasoning loop (and any other subscriber) can immediately
        generate chain hypotheses or trigger follow-up work. Best-effort —
        a bus failure must never break graph persistence.
        """
        if self.coordination_bus is None:
            return
        try:
            await self.coordination_bus.publish(
                "finding.recorded",
                {
                    "finding_id": persisted_id,
                    "vuln_type": (
                        vuln.vuln_type.value
                        if hasattr(vuln.vuln_type, "value")
                        else str(vuln.vuln_type)
                    ),
                    "severity": (
                        vuln.severity.value
                        if hasattr(vuln.severity, "value")
                        else str(vuln.severity)
                    ),
                    "validated": vuln.validated,
                    "engagement_id": vuln.engagement_id,
                    "endpoint": vuln.endpoint_id or "",
                    "title": vuln.title,
                },
                source="graph_memory",
            )
        except Exception as e:  # noqa: BLE001 - event publication is best-effort
            logger.warning("finding_event_publish_failed id=%s error=%s", persisted_id, e)

    @staticmethod
    def _vulnerability_dedup_key(vuln: Vulnerability) -> str:
        """Return a stable key for one concrete scanner signal in one engagement."""
        template = ""
        location = ""
        for evidence in vuln.evidence or []:
            if not isinstance(evidence, dict):
                continue
            template = str(evidence.get("template") or template)
            location = str(
                evidence.get("matched_at")
                or evidence.get("url")
                or evidence.get("host")
                or location
            )
            if template and location:
                break
        identity = {
            "engagement_id": vuln.engagement_id,
            "tool_source": vuln.tool_source,
            "template": template or vuln.title.strip().lower(),
            "location": location or vuln.endpoint_id or vuln.entry_point or "unknown",
        }
        canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _apply_nuclei_spa_persistence_guard(vuln: Vulnerability) -> None:
        """Keep status-only SPA Nuclei signals out of high-confidence finding flows."""
        if vuln.tool_source != "nuclei":
            return
        for evidence in vuln.evidence or []:
            if not isinstance(evidence, dict):
                continue
            signal = evidence.get("false_positive_signal") or {}
            if not (signal.get("status_only_match") and signal.get("spa_response")):
                continue
            vuln.confidence = min(vuln.confidence, 0.1)
            vuln.validated = False
            vuln.exploitability = "low"
            logger.warning(
                "nuclei_spa_status_only_persistence_guard vuln_id=%s engagement_id=%s",
                vuln.id,
                vuln.engagement_id,
            )
            return

    async def add_endpoints_batch(self, endpoints: List[Endpoint]) -> List[str]:
        """Persist a list of Endpoints in one UNWIND Cypher transaction (N endpoints = 1
        round-trip, not N). Mirrors add_endpoint semantics exactly. Returns list of
        persisted IDs in input order."""
        if not endpoints:
            return []

        rows = [
            {
                "id": ep.id,
                "url": ep.url,
                "method": ep.method,
                "type": ep.type,
                "status_code": ep.status_code,
                "title": ep.title,
                "technologies": ep.technologies,
                "parameters": ep.parameters,
                "auth_required": ep.auth_required,
                "source": ep.source,
                "confidence": ep.confidence,
                "engagement_id": ep.engagement_id,
                "screenshot_path": ep.screenshot_path,
                "host": ep.host,
                "path": ep.path,
                "query_keys": ep.query_keys,
                "has_body": ep.has_body,
                "content_type": ep.content_type,
                "body_schema_keys": ep.body_schema_keys,
                "auth_class": ep.auth_class,
                "request_headers_sample": json.dumps(ep.request_headers_sample),
                "status_codes_seen": ep.status_codes_seen,
                "response_size_avg": ep.response_size_avg,
                "response_content_type": ep.response_content_type,
                "user_label": ep.user_label,
                "workflow_id": ep.workflow_id,
                "first_seen": ep.first_seen.isoformat(),
                "last_seen": ep.last_seen.isoformat(),
                "observations": ep.observations,
                "asset_id": ep.asset_id,
            }
            for ep in endpoints
        ]

        cypher = """
        UNWIND $rows AS ep
        MERGE (e:Endpoint {id: ep.id})
        SET e.url = ep.url, e.method = ep.method, e.type = ep.type,
            e.status_code = ep.status_code, e.title = ep.title,
            e.technologies = ep.technologies, e.parameters = ep.parameters,
            e.auth_required = ep.auth_required, e.source = ep.source,
            e.confidence = ep.confidence, e.engagement_id = ep.engagement_id,
            e.screenshot_path = ep.screenshot_path, e.host = ep.host,
            e.path = ep.path, e.query_keys = ep.query_keys,
            e.has_body = ep.has_body, e.content_type = ep.content_type,
            e.body_schema_keys = ep.body_schema_keys, e.auth_class = ep.auth_class,
            e.request_headers_sample = ep.request_headers_sample,
            e.status_codes_seen = ep.status_codes_seen,
            e.response_size_avg = ep.response_size_avg,
            e.response_content_type = ep.response_content_type,
            e.user_label = ep.user_label, e.workflow_id = ep.workflow_id,
            e.first_seen = CASE WHEN e.first_seen IS NULL THEN ep.first_seen ELSE e.first_seen END,
            e.last_seen = ep.last_seen, e.observations = ep.observations
        WITH e, ep
        OPTIONAL MATCH (a:Asset {id: ep.asset_id})
        FOREACH (x IN CASE WHEN a IS NOT NULL THEN [a] ELSE [] END |
            MERGE (a)-[:HAS_ENDPOINT]->(e)
        )
        RETURN e.id AS id
        """

        async with self._driver.session() as session:
            result = await session.run(cypher, {"rows": rows})
            ids = [rec["id"] async for rec in result]

        # Invalidate graph stats cache after batch persist
        if ids and endpoints:
            await self.invalidate_graph_stats_cache(endpoints[0].engagement_id)
        return ids

    async def add_vulnerabilities_batch(self, vulns: List[Vulnerability]) -> List[str]:
        """Persist a list of Vulnerabilities in one UNWIND Cypher transaction. Skips
        simulated findings using the same guard as add_vulnerability. Returns list of
        persisted IDs for accepted (non-simulated) entries."""
        from ai_osop.core.config import settings as _settings

        real_vulns = [
            v
            for v in vulns
            if not v.is_simulated() or getattr(_settings, "allow_simulated_findings", False)
        ]

        for v in vulns:
            if v not in real_vulns:
                logger.warning(
                    "rejected_simulated_vulnerability id=%s tool_source=%s title=%s engagement=%s",
                    v.id,
                    v.tool_source,
                    v.title,
                    v.engagement_id,
                )

        if not real_vulns:
            return []

        # Do not submit duplicate rows from one MCP response.  Cypher still uses
        # the same key as a cross-task/retry safety net.
        unique_vulns: Dict[str, Vulnerability] = {}
        for vuln in real_vulns:
            self._apply_nuclei_spa_persistence_guard(vuln)
            dedup_key = self._vulnerability_dedup_key(vuln)
            if dedup_key in unique_vulns:
                logger.info("deduplicated_batch_vulnerability id=%s", vuln.id)
                continue
            unique_vulns[dedup_key] = vuln

        from urllib.parse import urlsplit

        rows = []
        for dedup_key, vuln in unique_vulns.items():
            vuln_host = ""
            try:
                for ev in vuln.evidence or []:
                    if not isinstance(ev, dict):
                        continue
                    candidate = ev.get("matched_at") or ev.get("url") or ev.get("host")
                    if candidate:
                        raw = str(candidate)
                        netloc = urlsplit(raw if "://" in raw else "http://" + raw).netloc
                        if netloc:
                            vuln_host = netloc.split("@")[-1].split(":")[0].lower()
                            break
            except Exception:  # noqa: BLE001
                vuln_host = ""

            rows.append(
                {
                    "id": vuln.id,
                    "dedup_key": dedup_key,
                    "host": vuln_host,
                    "cwe": vuln.cwe,
                    "vuln_type": vuln.vuln_type.value,
                    "severity": vuln.severity.value,
                    "cvss_score": vuln.cvss_score,
                    "title": vuln.title,
                    "description": vuln.description,
                    "evidence": json.dumps(vuln.evidence, default=str),
                    "tool_source": vuln.tool_source,
                    "confidence": vuln.confidence,
                    "entry_point": vuln.entry_point,
                    "requires_auth": vuln.requires_auth,
                    "validated": vuln.validated,
                    "exploitability": vuln.exploitability,
                    "impact": vuln.impact,
                    "engagement_id": vuln.engagement_id,
                    "created_at": vuln.created_at.isoformat(),
                    "endpoint_id": vuln.endpoint_id,
                }
            )

        cypher = """
        UNWIND $rows AS v
        MERGE (vn:Vulnerability {dedup_key: v.dedup_key})
        ON CREATE SET vn.id = v.id, vn.created_at = v.created_at,
            vn.duplicate_count = 0
        ON MATCH SET vn.duplicate_count = coalesce(vn.duplicate_count, 0) + 1
        SET vn.cwe = v.cwe, vn.vuln_type = v.vuln_type, vn.severity = v.severity,
            vn.cvss_score = v.cvss_score, vn.title = v.title,
            vn.description = v.description, vn.evidence = v.evidence,
            vn.tool_source = v.tool_source, vn.confidence = v.confidence,
            vn.entry_point = v.entry_point, vn.requires_auth = v.requires_auth,
            vn.validated = v.validated, vn.exploitability = v.exploitability,
            vn.impact = v.impact, vn.engagement_id = v.engagement_id,
            vn.last_seen = v.created_at
        WITH vn, v
        OPTIONAL MATCH (e:Endpoint {id: v.endpoint_id})
        OPTIONAL MATCH (eh:Endpoint {engagement_id: v.engagement_id})
            WHERE e IS NULL AND v.host <> '' AND (eh.host = v.host OR eh.url CONTAINS v.host)
        WITH vn, v, e, collect(eh)[0] AS ehost
        FOREACH (x IN CASE WHEN e IS NOT NULL THEN [e] ELSE [] END |
            MERGE (e)-[:HAS_VULNERABILITY]->(vn)
        )
        FOREACH (x IN CASE WHEN e IS NULL AND ehost IS NOT NULL THEN [ehost] ELSE [] END |
            MERGE (ehost)-[:HAS_VULNERABILITY]->(vn)
        )
        RETURN vn.id AS id, v.dedup_key AS dedup_key, vn.id = v.id AS created
        """

        async with self._driver.session() as session:
            result = await session.run(cypher, {"rows": rows})
            records = [rec async for rec in result]
            ids = [rec["id"] for rec in records]
            created_keys = {rec["dedup_key"] for rec in records if rec["created"]}

        for dedup_key, vuln in unique_vulns.items():
            if dedup_key not in created_keys:
                continue
            if self.findings_knowledge is not None:
                try:
                    await self.findings_knowledge.record_finding(vuln)
                except Exception as e:  # noqa: BLE001
                    logger.warning("findings_knowledge_record_failed id=%s error=%s", vuln.id, e)
            if self.primitive_ledger is not None:
                try:
                    from ai_osop.core.chain_analysis import vuln_to_primitive

                    await self.primitive_ledger.upsert_primitive(vuln_to_primitive(vuln))
                except Exception as e:  # noqa: BLE001
                    logger.warning("primitive_ledger_record_failed id=%s error=%s", vuln.id, e)

        # Invalidate graph stats cache after batch persist
        if ids and real_vulns:
            await self.invalidate_graph_stats_cache(real_vulns[0].engagement_id)
        return ids

    async def validate_vulnerability(self, vuln_id: str) -> None:
        """Mark a vulnerability as validated in the graph.

        Also feeds the confirmed finding into the calibration brain so future
        engagements benefit from the real accept signal (P2b feedback loop).
        Wire ``graph_memory.calibration_engine`` at startup (same pattern as
        ``findings_knowledge``) to enable cross-engagement learning.
        """
        cypher = """
        MATCH (v:Vulnerability {id: $vid})
        SET v.validated = true,
            v.last_validated = $ts,
            v.confidence = 1.0
        RETURN v.id, v.vuln_type AS vuln_type, v.engagement_id AS engagement_id
        """
        async with self._driver.session() as session:
            result = await session.run(
                cypher, {"vid": vuln_id, "ts": datetime.utcnow().isoformat()}
            )
            record = await result.single()

        # P2b calibration feedback: record this validated finding as a real
        # accept-outcome so the Beta-Binomial shrinkage engine learns from it.
        # Best-effort -- never breaks the validation itself.
        if record is not None and self.calibration_engine is not None:
            try:
                await self.calibration_engine.record_outcome(
                    finding_data={
                        "id": vuln_id,
                        "category": record.get("vuln_type", "unknown"),
                        "engagement_id": record.get("engagement_id"),
                    },
                    outcome="accepted",
                )
            except Exception as _e:  # noqa: BLE001 - calibration is advisory
                logger.debug("calibration_record_skipped vuln_id=%s reason=%s", vuln_id, _e)

    async def add_exploit(self, exploit: Exploit) -> str:
        """Add an Exploit and link to Vulnerability and Payload."""
        cypher = """
        MERGE (x:Exploit {id: $id})
        SET x.type = $type,
            x.validated = $validated,
            x.operator_approved = $operator_approved,
            x.approval_id = $approval_id,
            x.evidence_path = $evidence_path,
            x.timestamp = $timestamp,
            x.time_to_exploit = $time_to_exploit,
            x.impact_confirmed = $impact_confirmed,
            x.engagement_id = $engagement_id
        WITH x
        OPTIONAL MATCH (v:Vulnerability {id: $vuln_id})
        FOREACH (y IN CASE WHEN v IS NOT NULL THEN [v] ELSE [] END |
            MERGE (v)-[:EXPLOITED_BY]->(x)
        )
        WITH x
        OPTIONAL MATCH (p:Payload {id: $payload_id})
        FOREACH (y IN CASE WHEN p IS NOT NULL THEN [p] ELSE [] END |
            MERGE (x)-[:USES_PAYLOAD]->(p)
        )
        RETURN x.id AS id
        """

        async with self._driver.session() as session:
            result = await session.run(
                cypher,
                {
                    "id": exploit.id,
                    "type": exploit.type,
                    "validated": exploit.validated,
                    "operator_approved": exploit.operator_approved,
                    "approval_id": exploit.approval_id,
                    "evidence_path": exploit.evidence_path,
                    "timestamp": exploit.timestamp.isoformat(),
                    "time_to_exploit": exploit.time_to_exploit,
                    "impact_confirmed": exploit.impact_confirmed,
                    "engagement_id": exploit.engagement_id,
                    "vuln_id": exploit.vuln_id,
                    "payload_id": exploit.payload_id,
                },
            )
            record = await result.single()
            return record["id"] if record else exploit.id

    async def add_attack_path(self, path: AttackPath) -> str:
        """Add an attack path with its nodes and edges."""
        # Create LEADS_TO relationships between consecutive nodes
        cypher = """
        UNWIND $edges as edge
        OPTIONAL MATCH (from {id: edge.from_id})
        OPTIONAL MATCH (to {id: edge.to_id})
        FOREACH (pair IN CASE WHEN from IS NOT NULL AND to IS NOT NULL THEN [1] ELSE [] END |
            MERGE (from)-[r:LEADS_TO]->(to)
            SET r.type = edge.type,
                r.probability = edge.probability,
                r.time_estimate = edge.time_estimate,
                r.detection_risk = edge.detection_risk
        )
        """

        edges = []
        for i in range(len(path.node_ids) - 1):
            edges.append(
                {
                    "from_id": path.node_ids[i],
                    "to_id": path.node_ids[i + 1],
                    "type": "exploit_chain",
                    "probability": path.confidence,
                    "time_estimate": path.total_time_estimate // max(len(path.node_ids) - 1, 1),
                    "detection_risk": path.detection_risk,
                }
            )

        async with self._driver.session() as session:
            await session.run(cypher, {"edges": edges})

        # Unlike vulns/endpoints/assets, an attack path is a graph-shaping,
        # path-dependent record — post-write, enqueue for projection on recovery.
        # payload is encoded minimally; path_id is the write-key.
        try:
            outbox_payload = {
                "id": path.id,
                "node_ids": path.node_ids,
                "confidence": path.confidence,
                "total_time_estimate": path.total_time_estimate,
                "detection_risk": path.detection_risk,
                "edges": edges,
            }
            await self._enqueue_outbox("attack_path", path.id, outbox_payload)
        except Exception as obe:  # noqa: BLE001 - never block chain persistence
            logger.warning(
                "attack_path_outbox_enqueue_failed id=%s error=%s", path.id, str(obe)[:80]
            )

        return path.id

    async def find_attack_paths(
        self,
        entry_node_id: str,
        goal_types: List[str],
        max_depth: int = 5,
        min_confidence: float = 0.5,
        engagement_id: Optional[str] = None,
    ) -> List[AttackPath]:
        """
        Find attack paths from entry node to high-value targets.
        Uses weighted shortest path with confidence thresholds.
        """
        cypher = """
        MATCH (start)
        WHERE start.id = $entry_id
        MATCH (goal:Vulnerability)
        WHERE goal.impact IN $goal_types AND coalesce(goal.confidence, 1.0) >= $min_conf
        CALL apoc.algo.dijkstra(
            start, goal,
            'HAS_ENDPOINT>|HAS_VULNERABILITY>|LEADS_TO>',
            'probability'
        )
        YIELD path, weight
        WITH path, weight, start, goal
        WHERE length(path) <= $max_depth
        RETURN 
            [node in nodes(path) | node.id] as node_ids,
            [rel in relationships(path)
             | {type: type(rel), weight: coalesce(rel.probability, 1.0)}] as edges,
            coalesce(weight, 1.0) as confidence,
            reduce(
                time = 0, r in relationships(path)
                | time + coalesce(r.time_estimate, 60)
            ) as total_time,
            reduce(
                risk = 0.0, r in relationships(path)
                | risk + coalesce(r.detection_risk, 0.1)
            ) as total_risk,
            start.id as entry_id,
            goal.id as goal_id
        ORDER BY confidence DESC
        LIMIT 10
        """

        attrs = {}
        if engagement_id:
            attrs["engagement_id"] = engagement_id
        with trace_span(
            "graph_memory.find_attack_paths",
            attributes=attrs,
        ):
            async with self._driver.session() as session:
                result = await session.run(
                    cypher,
                    {
                        "entry_id": entry_node_id,
                        "goal_types": goal_types,
                        "min_conf": min_confidence,
                        "max_depth": max_depth,
                    },
                )

                paths = []
                async for record in result:
                    # Ensure no NaN
                    conf = (
                        record["confidence"]
                        if not isinstance(record["confidence"], float)
                        or not (record["confidence"] != record["confidence"])
                        else 0.5
                    )

                    path = AttackPath(
                        node_ids=record["node_ids"],
                        edge_ids=[f"{e['type']}-{i}" for i, e in enumerate(record["edges"])],
                        confidence=min(max(conf, 0.0), 1.0),
                        risk_score=min(max(conf * 10, 0.0), 10.0),
                        total_time_estimate=record["total_time"],
                        detection_risk=0.5,  # Default for now
                        entry_node_id=record["entry_id"],
                        goal_node_id=record["goal_id"],
                        engagement_id="",
                    )
                    paths.append(path)

                return paths

    async def get_attack_surface(self, node_id: str) -> List[Dict[str, Any]]:
        """Get all reachable nodes from a given position."""
        cypher = """
        MATCH (start)
        WHERE start.id = $node_id
        CALL apoc.path.subgraphNodes(
            start,
            {relationshipFilter: 'LEADS_TO>|HAS_VULNERABILITY>|EXPLOITED_BY>',
             maxLevel: 3}
        )
        YIELD node
        RETURN node.id as id, labels(node)[0] as type, node.confidence as confidence
        """

        async with self._driver.session() as session:
            result = await session.run(cypher, {"node_id": node_id})
            nodes = []
            async for record in result:
                nodes.append(
                    {
                        "id": record["id"],
                        "type": record["type"],
                        "confidence": record["confidence"],
                    }
                )
            return nodes

    async def propagate_risk(self, exploit_id: str, impact_score: float) -> None:
        """
        Propagate risk from a validated exploit through the graph.
        Updates downstream node risk scores.
        """
        cypher = """
        MATCH (x:Exploit {id: $exploit_id})-[:USES_PAYLOAD]->(p:Payload)
        MATCH (v:Vulnerability)-[:EXPLOITED_BY]->(x)
        SET v.risk_score = $impact_score
        WITH v
        MATCH path = (v)-[:LEADS_TO*1..5]->(downstream)
        WITH downstream, path, $impact_score as base_risk
        SET downstream.risk_score = CASE
            WHEN downstream.risk_score IS NULL
                THEN base_risk * reduce(
                    conf = 1.0,
                    r in relationships(path)
                    | conf * r.probability
                )
            ELSE downstream.risk_score + base_risk * reduce(
                conf = 1.0,
                r in relationships(path)
                | conf * r.probability
            )
        END
        """

        async with self._driver.session() as session:
            await session.run(cypher, {"exploit_id": exploit_id, "impact_score": impact_score})

    async def get_node_details(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve details for a node by ID."""
        cypher = """
        MATCH (n {id: $node_id})
        RETURN labels(n)[0] as type, properties(n) as props
        """
        async with self._driver.session() as session:
            result = await session.run(cypher, {"node_id": node_id})
            record = await result.single()
            if record:
                return {"type": record["type"], **record["props"]}
            return None

    async def get_endpoint_url_for_vulnerability(self, vuln_id: str) -> Optional[str]:
        """Resolve the URL to target when validating a vulnerability.

        Primary: the linked Endpoint node's URL.
        Fallback: the location the scanner actually recorded in the finding's
        evidence. nuclei findings store ``matched_at`` / ``url`` in evidence but
        are not linked to an Endpoint node, so without this fallback the
        exploit-validation task (and its dashboard approval) gets ``target=None``
        and fires at a null URL. (AIOSOP-EXPLOIT-TARGET-2026-06-30)
        """
        cypher = """
        MATCH (v:Vulnerability {id: $vuln_id})
        OPTIONAL MATCH (v)-[:HAS_VULNERABILITY]-(e:Endpoint)
        RETURN e.url AS url, v.evidence AS evidence
        """
        async with self._driver.session() as session:
            result = await session.run(cypher, {"vuln_id": vuln_id})
            record = await result.single()
            if not record:
                return None
            if record["url"]:
                return record["url"]
            # Fallback: pull matched_at / url out of the finding's evidence blob.
            import json as _json

            ev_raw = record["evidence"]
            try:
                ev = _json.loads(ev_raw) if isinstance(ev_raw, str) else (ev_raw or [])
            except (ValueError, TypeError):
                ev = []
            if isinstance(ev, dict):
                ev = [ev]
            for item in ev if isinstance(ev, list) else []:
                if isinstance(item, dict):
                    loc = item.get("matched_at") or item.get("url")
                    if loc:
                        return loc
            return None

    async def get_graph_stats(self, engagement_id: str) -> Dict[str, Any]:
        """Get engagement graph statistics.

        Results are cached in ``self._graph_stats_cache`` (TTL 10s) since graph
        stats change infrequently — only when new Vulnerability/Endpoint nodes
        are persisted. The cache is invalidated by :meth:`invalidate_graph_stats_cache`.
        """
        _cache = getattr(self, "_graph_stats_cache", None)
        if _cache is not None:
            cached = _cache.get(engagement_id)
            if cached is not None:
                return cached

        cypher = """
        MATCH (n)
        WHERE n.engagement_id = $engagement_id
        RETURN 
            count(DISTINCT n) as total_nodes,
            count(DISTINCT CASE WHEN n:Asset THEN n END) as assets,
            count(DISTINCT CASE WHEN n:Endpoint THEN n END) as endpoints,
            count(DISTINCT CASE WHEN n:Vulnerability THEN n END) as vulnerabilities,
            count(DISTINCT CASE WHEN n:Exploit THEN n END) as exploits
        """

        with trace_span(
            "graph_memory.get_graph_stats",
            attributes={"engagement_id": engagement_id},
        ):
            async with self._driver.session() as session:
                result = await session.run(cypher, {"engagement_id": engagement_id})
                record = await result.single()
                stats = dict(record) if record else {}
                # Cache the result so repeated phase-monitor ticks skip the query.
                _cache = getattr(self, "_graph_stats_cache", None)
                if _cache is not None:
                    _cache[engagement_id] = stats
                return stats

    async def invalidate_graph_stats_cache(self, engagement_id: str) -> None:
        """Invalidate cached graph stats for an engagement.

        Called from persistence hooks so a newly added Vulnerability or Endpoint
        is immediately visible on the next phase-monitor tick rather than waiting
        for TTL expiry.
        """
        _cache = getattr(self, "_graph_stats_cache", None)
        if _cache is not None:
            _cache.pop(engagement_id, None)

    async def _export_pool_metrics(self) -> None:
        """Export Neo4j connection pool metrics to Prometheus gauges.

        Reads from ``self._driver._pool`` internal state. The neo4j Python driver
        exposes ``in_use_connection_count`` as a public pool attribute; total
        connection count and closed status are probed from internal attributes
        with try/except guards so a driver version change never breaks the
        platform.

        Gracefully handles uninitialized driver (``_driver is None``) — all
        gauges reset to 0/False so Prometheus scrapes see a drained pool rather
        than stale last-known-good values.
        """
        if self._driver is None:
            record_neo4j_pool_metrics()
            return

        pool = getattr(self._driver, "_pool", None)
        if pool is None:
            record_neo4j_pool_metrics()
            return

        in_use = getattr(pool, "in_use_connection_count", None)
        if in_use is None:
            record_neo4j_pool_metrics()
            return
        # MAJ-4 fix (2026-07-22): some neo4j driver versions expose
        # ``in_use_connection_count`` as a METHOD, not an int. Calling int()
        # on a method raises TypeError. Resolve it: if it's callable, call it;
        # if the result is still not an int, fall back to 0.
        if callable(in_use):
            try:
                in_use = in_use()
            except Exception:  # noqa: BLE001 — pool metric probe is advisory
                in_use = 0
        if not isinstance(in_use, (int, float)):
            in_use = 0

        # Derive total from internal connection set (best-effort, private API)
        connections = getattr(pool, "connections", None)
        total = 0
        if connections is not None:
            try:
                total = len(connections)
            except Exception:  # noqa: BLE001 — pool metric probe is advisory
                pass

        # Pool is closed when _pool has a 'closed' attribute that is True, or
        # when the driver itself reports not connected.
        closed = bool(getattr(pool, "closed", False))
        ready = bool(self._initialized) and not closed

        record_neo4j_pool_metrics(
            in_use=int(in_use),
            total=max(total, int(in_use)),
            closed=closed,
            ready=ready,
        )

    async def start_pool_metrics_export(self, interval: int = 15) -> None:
        """Start a background task that exports Neo4j pool metrics every ``interval`` seconds.

        The loop runs until :meth:`stop_pool_metrics_export` is called. Calling this
        method when the loop is already running is a no-op.
        """
        if self._pool_metrics_running:
            return
        self._pool_metrics_running = True
        self._pool_metrics_task = asyncio.ensure_future(self._pool_metrics_loop(interval))

    async def stop_pool_metrics_export(self) -> None:
        """Stop the pool metric export loop and cancel any in-flight iteration."""
        self._pool_metrics_running = False
        if self._pool_metrics_task is not None and not self._pool_metrics_task.done():
            self._pool_metrics_task.cancel()
            try:
                await self._pool_metrics_task
            except asyncio.CancelledError:
                pass
            self._pool_metrics_task = None

    async def _pool_metrics_loop(self, interval: int) -> None:
        """Periodically export Neo4j pool metrics.

        Follows the same pattern as :class:`OutboxProcessor.run` — a "while running"
        loop with a guard flag that :meth:`stop_pool_metrics_export` sets to False,
        so cancellation is cooperative and never leaves stale background work.
        """
        logger.info("neo4j_pool_metrics_loop_started interval=%ds", interval)
        while self._pool_metrics_running:
            try:
                await self._export_pool_metrics()
            except Exception as e:  # noqa: BLE001 - pool metrics are advisory
                logger.warning("neo4j_pool_metrics_export_error: %s", e)
            await asyncio.sleep(interval)

    async def get_vulnerabilities_by_engagement(
        self, engagement_id: str, *aliases: str
    ) -> List[Dict[str, Any]]:
        """Fetch all Vulnerability nodes for a given engagement.

        AIOSOP-FINDINGS-KEY-2026-07-20: an engagement is addressable by two id forms
        — the SHORT operator-supplied ``engagement_id`` (juice-e2e-xxx) and the FULL
        generated ``session_id`` (eng-{timestamp}-juice-e2e-xxx). Different writers
        persist Vulnerability.engagement_id under different forms (deterministic scan
        uses scope.engagement_id; some agents use ctx.session_id), so a reader that
        matches only ONE form silently returns 0 findings even though they exist.
        Match ANY provided id form so retrieval is robust regardless of which key the
        writer used. This mirrors the dual-key match already used by the phase monitor
        (orchestrator.is_phase_complete).
        """
        ids = [i for i in (engagement_id, *aliases) if i]
        # de-dupe while preserving order
        ids = list(dict.fromkeys(ids))
        # AIOSOP-FINDINGS-ROOT-2026-07-20: resolve url/method from the linked
        # Endpoint in the same query (no N+1). head(collect(e)) keeps one row
        # per vulnerability even if the undirected HAS_VULNERABILITY match
        # would otherwise fan out across multiple endpoints.
        cypher = """
        MATCH (v:Vulnerability)
        WHERE v.engagement_id IN $ids
        OPTIONAL MATCH (v)-[:HAS_VULNERABILITY]-(e:Endpoint)
        WITH v, head(collect(e)) AS e
        RETURN v, e.url AS ep_url, e.method AS ep_method
        """
        with trace_span(
            "graph_memory.get_vulnerabilities_by_engagement",
            attributes={"engagement_id": engagement_id, "id_forms": len(ids)},
        ):
            async with self._driver.session() as session:
                result = await session.run(cypher, {"ids": ids})
                records = await result.data()
                findings = []
                for record in records:
                    finding = record["v"]
                    if record.get("ep_url") and not finding.get("url"):
                        finding["url"] = record["ep_url"]
                    if record.get("ep_method") and not finding.get("method"):
                        finding["method"] = record["ep_method"]
                    findings.append(finding)
                return findings

    async def export_findings_json(
        self, engagement_id: str, path: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Export an engagement's persisted Vulnerability findings as scorer-ready JSON.

        This is the seam between a real engagement and benchmarks/score_engagement.py.
        The Vulnerability nodes are persisted (see add_vulnerability) with exactly the
        keys the scorer duck-types on — vuln_type, endpoint_id, confidence, evidence,
        tool_source, severity, title, id — so the raw node dicts are already the right
        shape; we only sort for stable output and optionally write to disk.

        Args:
            engagement_id: engagement whose findings to export.
            path: if given, the JSON array is written here (UTF-8). The list is
                always returned regardless.

        Returns:
            A JSON-serialisable list of finding dicts, ready to pass to
            score_engagement.score_findings(...) or the CLI's --findings flag.
        """
        findings = await self.get_vulnerabilities_by_engagement(engagement_id)
        # Stable ordering: highest confidence first, then id, so diffs between runs
        # are meaningful and not reshuffled by Neo4j's return order.
        findings = sorted(
            findings,
            key=lambda f: (-float(f.get("confidence") or 0.0), str(f.get("id") or "")),
        )
        if path:
            with trace_span(
                "graph_memory.export_findings_json",
                attributes={"engagement_id": engagement_id, "count": len(findings)},
            ):
                Path(path).write_text(
                    json.dumps(findings, indent=2, default=str),
                    encoding="utf-8",
                )
            logger.info(
                "exported %d findings for engagement=%s -> %s",
                len(findings),
                engagement_id,
                path,
            )
        return findings

    async def get_all_nodes_for_engagement(
        self, engagement_id: str, *aliases: str
    ) -> List[Dict[str, Any]]:
        """Fetch all nodes for a given engagement (for attack graph viz).

        AIOSOP-GRAPHVIZ-001: also return properties so the dashboard graph can render
        node names/values/urls (KnowledgeGraphs.tsx reads properties.name/value/url).
        Additive — existing callers read id/labels and ignore the extra key.

        Matches any provided id form — same split-brain fix as
        get_vulnerabilities_by_engagement (AIOSOP-FINDINGS-KEY).
        """
        ids = list(dict.fromkeys(i for i in (engagement_id, *aliases) if i))
        cypher = """
        MATCH (n)
        WHERE n.engagement_id IN $ids
        RETURN n.id AS id, labels(n) AS labels, properties(n) AS properties
        """
        with trace_span(
            "graph_memory.get_all_nodes_for_engagement",
            attributes={"engagement_id": engagement_id, "id_forms": len(ids)},
        ):
            async with self._driver.session() as session:
                result = await session.run(cypher, {"ids": ids})
                return await result.data()

    async def get_all_edges_for_engagement(
        self, engagement_id: str, *aliases: str
    ) -> List[Dict[str, Any]]:
        """Fetch all relationships for a given engagement (for attack graph viz).

        Matches any provided id form — same split-brain fix as
        get_vulnerabilities_by_engagement (AIOSOP-FINDINGS-KEY).
        """
        ids = list(dict.fromkeys(i for i in (engagement_id, *aliases) if i))
        cypher = """
        MATCH (n)-[r]->(m)
        WHERE n.engagement_id IN $ids AND m.engagement_id IN $ids
        RETURN n.id AS source, m.id AS target, type(r) AS type
        """
        with trace_span(
            "graph_memory.get_all_edges_for_engagement",
            attributes={"engagement_id": engagement_id, "id_forms": len(ids)},
        ):
            async with self._driver.session() as session:
                result = await session.run(cypher, {"ids": ids})
                return await result.data()

    async def run_read_query(
        self, cypher: str, params: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Execute a parameterized read-only Cypher query and return records.

        This is the escape hatch for complex queries that don't have a dedicated
        method yet. All callers should prefer typed methods over raw Cypher.
        """
        params = params or {}
        with trace_span(
            "graph_memory.run_read_query",
            attributes={"cypher_preview": cypher[:100]},
        ):
            async with self._driver.session() as session:
                result = await session.run(cypher, params)
                return await result.data()

    async def run_write_query(
        self, cypher: str, params: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Execute a parameterized write Cypher query and return records if any.

        This is the escape hatch for writes that don't have a dedicated method yet.
        All callers should prefer typed methods over raw Cypher. If the query has
        a RETURN clause the records are returned; otherwise an empty list.
        """
        params = params or {}
        with trace_span(
            "graph_memory.run_write_query",
            attributes={"cypher_preview": cypher[:100]},
        ):
            async with self._driver.session() as session:
                result = await session.run(cypher, params)
                return await result.data()

    async def add_workflow(self, workflow: Workflow) -> str:
        """Persist a Workflow node."""
        cypher = """
        MERGE (w:Workflow {id: $id})
        SET w.name = $name,
            w.role = $role,
            w.engagement_id = $engagement_id,
            w.created_at = $created_at
        RETURN w.id AS id
        """
        async with self._driver.session() as session:
            result = await session.run(
                cypher,
                {
                    "id": workflow.id,
                    "name": workflow.name,
                    "role": workflow.role,
                    "engagement_id": workflow.engagement_id,
                    "created_at": workflow.created_at.isoformat(),
                },
            )
            record = await result.single()
            return record["id"]

    async def add_workflow_step(self, step: WorkflowStep) -> str:
        """Persist a WorkflowStep node and link to its parent Workflow."""
        cypher = """
        MERGE (s:Step {id: $id})
        SET s.workflow_id = $workflow_id,
            s.endpoint_id = $endpoint_id,
            s.order = $order,
            s.action_type = $action_type,
            s.engagement_id = $engagement_id,
            s.created_at = $created_at
        WITH s
        OPTIONAL MATCH (w:Workflow {id: $workflow_id})
        FOREACH (x IN CASE WHEN w IS NOT NULL THEN [w] ELSE [] END |
            MERGE (w)-[:HAS_STEP]->(s)
        )
        WITH s
        OPTIONAL MATCH (e:Endpoint {id: $endpoint_id})
        FOREACH (x IN CASE WHEN e IS NOT NULL THEN [e] ELSE [] END |
            MERGE (s)-[:TARGETS_ENDPOINT]->(e)
        )
        RETURN s.id AS id
        """
        async with self._driver.session() as session:
            result = await session.run(
                cypher,
                {
                    "id": step.id,
                    "workflow_id": step.workflow_id,
                    "endpoint_id": step.endpoint_id,
                    "order": step.order,
                    "action_type": step.action_type,
                    "engagement_id": step.engagement_id,
                    "created_at": step.created_at.isoformat(),
                },
            )
            record = await result.single()
            return record["id"]

    async def add_workflow_transition(self, transition: WorkflowTransition) -> str:
        """Persist a transition edge between two WorkflowSteps."""
        cypher = """
        MATCH (a:Step {id: $from_step_id}), (b:Step {id: $to_step_id})
        MERGE (a)-[r:TRANSITION {id: $id}]->(b)
        SET r.trigger = $trigger,
            r.engagement_id = $engagement_id
        RETURN $id AS id
        """
        async with self._driver.session() as session:
            result = await session.run(
                cypher,
                {
                    "id": transition.id,
                    "from_step_id": transition.from_step_id,
                    "to_step_id": transition.to_step_id,
                    "trigger": transition.trigger,
                    "engagement_id": transition.engagement_id,
                },
            )
            record = await result.single()
            return record["id"] if record else transition.id

    async def add_diff_auth_finding(self, finding: DiffAuthFinding) -> str:
        """Persist a DiffAuthFinding and link it to the affected Resource/Endpoint."""
        cypher = """
        MERGE (d:DiffAuthFinding {id: $id})
        SET d.category = $category,
            d.resource_id = $resource_id,
            d.test_identity_id = $test_identity_id,
            d.expected_result = $expected_result,
            d.observed_result = $observed_result,
            d.evidence_diff = $evidence_diff,
            d.confidence = $confidence,
            d.engagement_id = $engagement_id,
            d.created_at = $created_at,
            d.outcome = $outcome,
            d.outcome_notes = $outcome_notes,
            d.outcome_at = $outcome_at
        WITH d
        OPTIONAL MATCH (e:Endpoint {id: $resource_id})
        FOREACH (x IN CASE WHEN e IS NOT NULL THEN [e] ELSE [] END |
            MERGE (e)-[:HAS_DIFF_AUTH_FINDING]->(d)
        )
        WITH d
        OPTIONAL MATCH (r:Resource {id: $resource_id})
        FOREACH (x IN CASE WHEN r IS NOT NULL THEN [r] ELSE [] END |
            MERGE (r)-[:HAS_DIFF_AUTH_FINDING]->(d)
        )
        RETURN d.id AS id
        """
        async with self._driver.session() as session:
            result = await session.run(
                cypher,
                {
                    "id": finding.id,
                    "category": finding.category,
                    "resource_id": finding.resource_id,
                    "test_identity_id": finding.test_identity_id,
                    "expected_result": finding.expected_result,
                    "observed_result": finding.observed_result,
                    "evidence_diff": json.dumps(finding.evidence_diff, default=str),
                    "confidence": finding.confidence,
                    "engagement_id": finding.engagement_id,
                    "created_at": finding.created_at.isoformat(),
                    "outcome": finding.outcome,
                    "outcome_notes": finding.outcome_notes,
                    "outcome_at": finding.outcome_at.isoformat() if finding.outcome_at else None,
                },
            )
            record = await result.single()
            return record["id"]

    # ---- Phase 2: Differential Authorization persistence ----

    async def add_replay_result(self, rr: Dict[str, Any]) -> str:
        """Persist a ReplayResult and link it to its Endpoint:
        (:Endpoint)-[:HAS_REPLAY]->(:ReplayResult)."""
        cypher = """
        MERGE (rr:ReplayResult {id: $id})
        SET rr.endpoint_id = $endpoint_id, rr.identity = $identity,
            rr.status_code = $status_code, rr.response_size = $response_size,
            rr.json_keys = $json_keys, rr.sensitive_fields = $sensitive_fields,
            rr.ownership_hits = $ownership_hits, rr.content_type = $content_type,
            rr.error = $error, rr.engagement_id = $engagement_id,
            rr.created_at = $created_at
        WITH rr
        OPTIONAL MATCH (e:Endpoint {id: $endpoint_id})
        FOREACH (x IN CASE WHEN e IS NOT NULL THEN [e] ELSE [] END |
            MERGE (e)-[:HAS_REPLAY]->(rr))
        RETURN rr.id AS id
        """
        async with self._driver.session() as session:
            res = await session.run(
                cypher,
                {
                    "id": rr["id"],
                    "endpoint_id": rr["endpoint_id"],
                    "identity": rr["identity"],
                    "status_code": rr.get("status_code", 0),
                    "response_size": rr.get("response_size", 0),
                    "json_keys": rr.get("json_keys", []),
                    "sensitive_fields": rr.get("sensitive_fields", []),
                    "ownership_hits": rr.get("ownership_hits", []),
                    "content_type": rr.get("content_type", ""),
                    "error": rr.get("error", ""),
                    "engagement_id": rr["engagement_id"],
                    "created_at": datetime.utcnow().isoformat(),
                },
            )
            rec = await res.single()
            return rec["id"]

    async def add_authorization_test(self, at: Dict[str, Any]) -> str:
        """Persist an AuthorizationTest and link it to its Endpoint:
        (:Endpoint)-[:HAS_AUTH_TEST]->(:AuthorizationTest)."""
        cypher = """
        MERGE (t:AuthorizationTest {id: $id})
        SET t.endpoint_id = $endpoint_id, t.user_a = $user_a, t.user_b = $user_b,
            t.signals = $signals, t.verdict = $verdict, t.category = $category,
            t.confidence = $confidence, t.engagement_id = $engagement_id,
            t.created_at = $created_at
        WITH t
        OPTIONAL MATCH (e:Endpoint {id: $endpoint_id})
        FOREACH (x IN CASE WHEN e IS NOT NULL THEN [e] ELSE [] END |
            MERGE (e)-[:HAS_AUTH_TEST]->(t))
        RETURN t.id AS id
        """
        async with self._driver.session() as session:
            res = await session.run(
                cypher,
                {
                    "id": at["id"],
                    "endpoint_id": at["endpoint_id"],
                    "user_a": at.get("user_a", ""),
                    "user_b": at.get("user_b", ""),
                    "signals": json.dumps(at.get("signals", {}), default=str),
                    "verdict": at.get("verdict", ""),
                    "category": at.get("category", ""),
                    "confidence": at.get("confidence", 0.0),
                    "engagement_id": at["engagement_id"],
                    "created_at": datetime.utcnow().isoformat(),
                },
            )
            rec = await res.single()
            return rec["id"]

    async def add_diff_auth_finding_for_endpoint(
        self, finding: DiffAuthFinding, endpoint_id: str, test_id: str = ""
    ) -> str:
        """Persist a DiffAuthFinding linked to its Endpoint and AuthorizationTest:
        (:Endpoint)-[:HAS_DIFF_AUTH_FINDING]->(:DiffAuthFinding)<-[:PRODUCED]-(:AuthorizationTest).
        """
        cypher = """
        MERGE (d:DiffAuthFinding {id: $id})
        SET d.category = $category, d.resource_id = $resource_id,
            d.test_identity_id = $test_identity_id, d.expected_result = $expected_result,
            d.observed_result = $observed_result, d.evidence_diff = $evidence_diff,
            d.confidence = $confidence,
            d.engagement_id = $engagement_id,
            d.created_at = $created_at
        WITH d
        OPTIONAL MATCH (e:Endpoint {id: $endpoint_id})
        FOREACH (x IN CASE WHEN e IS NOT NULL THEN [e] ELSE [] END |
            MERGE (e)-[:HAS_DIFF_AUTH_FINDING]->(d))
        WITH d
        OPTIONAL MATCH (t:AuthorizationTest {id: $test_id})
        FOREACH (x IN CASE WHEN t IS NOT NULL THEN [t] ELSE [] END |
            MERGE (t)-[:PRODUCED]->(d))
        RETURN d.id AS id
        """
        async with self._driver.session() as session:
            res = await session.run(
                cypher,
                {
                    "id": finding.id,
                    "category": finding.category,
                    "resource_id": finding.resource_id,
                    "test_identity_id": finding.test_identity_id,
                    "expected_result": finding.expected_result,
                    "observed_result": finding.observed_result,
                    "evidence_diff": json.dumps(finding.evidence_diff, default=str),
                    "confidence": finding.confidence,
                    "engagement_id": finding.engagement_id,
                    "endpoint_id": endpoint_id,
                    "test_id": test_id,
                    "created_at": datetime.utcnow().isoformat(),
                },
            )
            rec = await res.single()
            return rec["id"]

    async def add_hypothesis(self, hypothesis: Hypothesis) -> str:
        """Persist a hypothesis and link it to the target node when possible."""
        cypher = """
        MERGE (h:Hypothesis {id: $id})
        SET h.title = $title,
            h.description = $description,
            h.category = $category,
            h.target_id = $target_id,
            h.confidence = $confidence,
            h.supporting_entities = $supporting_entities,
            h.evidence = $evidence,
            h.recommended_tests = $recommended_tests,
            h.recommended_skills = $recommended_skills,
            h.status = $status,
            h.engagement_id = $engagement_id,
            h.created_at = $created_at
        WITH h
        OPTIONAL MATCH (e:Endpoint {id: $target_id})
        FOREACH (x IN CASE WHEN e IS NOT NULL THEN [e] ELSE [] END |
            MERGE (e)-[:SUGGESTS]->(h)
        )
        WITH h
        OPTIONAL MATCH (a:Asset {id: $target_id})
        FOREACH (x IN CASE WHEN a IS NOT NULL THEN [a] ELSE [] END |
            MERGE (a)-[:SUGGESTS]->(h)
        )
        WITH h
        OPTIONAL MATCH (w:Workflow {id: $target_id})
        FOREACH (x IN CASE WHEN w IS NOT NULL THEN [w] ELSE [] END |
            MERGE (w)-[:SUGGESTS]->(h)
        )
        RETURN h.id AS id
        """
        async with self._driver.session() as session:
            result = await session.run(
                cypher,
                {
                    "id": hypothesis.id,
                    "title": hypothesis.title,
                    "description": hypothesis.description,
                    "category": hypothesis.category,
                    "target_id": hypothesis.target_id,
                    "confidence": hypothesis.confidence,
                    "supporting_entities": hypothesis.supporting_entities,
                    "evidence": (
                        json.dumps(hypothesis.evidence, default=str)
                        if hypothesis.evidence
                        else "[]"
                    ),
                    "recommended_tests": hypothesis.recommended_tests,
                    "recommended_skills": hypothesis.recommended_skills,
                    "status": hypothesis.status,
                    "engagement_id": hypothesis.engagement_id,
                    "created_at": hypothesis.created_at.isoformat(),
                },
            )
            record = await result.single()
            return record["id"] if record else hypothesis.id

    async def get_hypotheses_by_engagement(
        self, engagement_id: str, *aliases: str
    ) -> List[Dict[str, Any]]:
        """Fetch hypotheses for an engagement sorted by confidence.

        Matches any provided id form (session_id / scope.engagement_id) — same
        split-brain fix as get_vulnerabilities_by_engagement (AIOSOP-FINDINGS-KEY).
        Single-arg callers (e.g. phase_monitor's auto-transition gate) are
        unaffected; aliases is optional.
        """
        ids = list(dict.fromkeys(i for i in (engagement_id, *aliases) if i))
        cypher = """
        MATCH (h:Hypothesis)
        WHERE h.engagement_id IN $ids
        RETURN h
        ORDER BY h.confidence DESC, h.created_at DESC
        """
        with trace_span(
            "graph_memory.get_hypotheses_by_engagement",
            attributes={"engagement_id": engagement_id, "id_forms": len(ids)},
        ):
            async with self._driver.session() as session:
                result = await session.run(cypher, {"ids": ids})
                records = await result.data()
                return [
                    dict(record["h"]) if hasattr(record["h"], "items") else record["h"]
                    for record in records
                ]

    # ---- Reliability sprint: durable task lifecycle + dedupe + recovery ----

    async def log_skipped_scan(
        self,
        task_id: str,
        vuln_class: str,
        endpoint_url: str,
        reason: str,
        confidence: float,
        evidence: list[str],
        engagement_id: str,
    ) -> bool:
        """Log a skipped scan as a persistent graph node for capability audit trail."""
        cypher = """
        MERGE (s:SkippedScan {id: $id})
        SET s.vuln_class=$vuln_class, s.endpoint_url=$endpoint_url,
            s.reason=$reason, s.confidence=$confidence, s.evidence=$evidence,
            s.engagement_id=$engagement_id, s.timestamp=$timestamp
        RETURN s.id AS id
        """
        params = {
            "id": f"skip-{task_id}",
            "vuln_class": vuln_class,
            "endpoint_url": endpoint_url,
            "reason": reason,
            "confidence": confidence,
            "evidence": evidence,
            "engagement_id": engagement_id,
            "timestamp": datetime.utcnow().isoformat(),
        }
        try:
            async with self._driver.session() as s:
                await (await s.run(cypher, params)).consume()
            return True
        except Exception as e:
            # %-style args, not kwargs: if the logger is stdlib logging (test
            # harness, or structlog not yet configured), kwargs crash with
            # TypeError instead of returning the documented safe default False.
            logger.error("log_skipped_scan_failed task_id=%s error=%s", task_id, str(e))
            return False

    async def upsert_task(self, task: Any, result_summary: Optional[Dict[str, Any]] = None) -> bool:
        """Persist a Task's lifecycle state to Neo4j. Ground truth for the stuck-task
        reaper, restart recovery, and graph-backed dedupe (replaces in-memory only state)."""
        # AIOSOP-AUDIT-2026-06-16: persist payload + priority so restart recovery can
        # faithfully RE-DISPATCH interrupted tasks (previously payload was dropped, so
        # interrupted tasks could only be reset, never re-run). recovery_attempts is
        # preserved if already set (incremented by reset_interrupted_tasks).
        cypher = """
        MERGE (t:Task {id: $id})
        SET t.type=$type, t.status=$status, t.engagement_id=$engagement_id,
            t.agent_type=$agent_type, t.retry_count=$retry_count, t.max_retries=$max_retries,
            t.timeout_seconds=$timeout_seconds, t.created_at=$created_at, t.started_at=$started_at,
            t.completed_at=$completed_at,
            t.updated_at=$updated_at,
            t.result_summary=$result_summary,
            t.result=$result, t.error=$error,
            t.payload=$payload, t.priority=$priority,
            t.recovery_attempts=coalesce(t.recovery_attempts, 0)
        RETURN t.id AS id
        """
        params = {
            "id": task.id,
            "type": task.type,
            "status": task.status,
            "engagement_id": task.engagement_id,
            "agent_type": getattr(task.agent_type, "value", str(task.agent_type)),
            "retry_count": getattr(task, "retry_count", 0),
            "max_retries": getattr(task, "max_retries", 0),
            "timeout_seconds": getattr(task, "timeout_seconds", 300),
            "created_at": (
                task.created_at.isoformat() if getattr(task, "created_at", None) else None
            ),
            "started_at": (
                task.started_at.isoformat() if getattr(task, "started_at", None) else None
            ),
            "completed_at": (
                task.completed_at.isoformat() if getattr(task, "completed_at", None) else None
            ),
            "updated_at": datetime.utcnow().isoformat(),
            "result_summary": json.dumps(result_summary or {}, default=str),
            "payload": json.dumps(getattr(task, "payload", {}) or {}, default=str),
            "priority": getattr(task, "priority", 5),
            # ROOT-CAUSE FIX (2026-07-05): task.result is frequently a DICT (agent
            # output on completion). Neo4j properties may only be primitives/arrays,
            # so a raw dict here makes the write fail — and because the result of
            # s.run() was never consumed (see below), that failure surfaced only at
            # session close, AFTER this function had already returned True. Net effect:
            # the assignment-time write (result=None) persisted 'running', but the
            # completion write (result=dict) silently vanished, pinning EVERY task at
            # 'running' in the graph forever. Serialize result like result_summary.
            "result": (
                json.dumps(_r, default=str)
                if (_r := getattr(task, "result", None)) is not None
                else None
            ),
            "error": (str(_e) if (_e := getattr(task, "error", None)) is not None else None),
        }
        # Bounded retry so a brief Neo4j blip doesn't silently drop a lifecycle
        # transition (would make Neo4j diverge from in-memory -> zombie tasks).
        backoffs = [0.2, 0.4]
        for attempt in range(len(backoffs) + 1):
            try:
                async with self._driver.session() as s:
                    with trace_span(
                        "graph_memory.upsert_task",
                        attributes={
                            "task_id": task.id,
                            "task_type": task.type,
                            "task_status": task.status,
                            "engagement_id": task.engagement_id,
                        },
                    ):
                        # Consume the result so the write actually completes and any
                        # server-side error (e.g. bad property type) is raised HERE —
                        # inside the try/except for retry+logging — instead of being
                        # swallowed at session close after we've returned success.
                        await (await s.run(cypher, params)).consume()
                return True
            except Exception as e:
                if attempt < len(backoffs):
                    await asyncio.sleep(backoffs[attempt])
                    continue
                # All callers ignore the return value, so re-raising would change
                # behavior (and could crash lifecycle transitions); return False
                # after logging at ERROR so the dropped write stays observable.
                logger.error("upsert_task failed for task %s after retries: %s", task.id, e)
                return False

    async def task_has_spawned(self, task_id: str) -> bool:
        """True if this task already has a SPAWNED chain child (durable dedupe marker)."""
        try:
            async with self._driver.session() as s:
                res = await s.run(
                    "MATCH (t:Task {id:$id})-[:SPAWNED]->() RETURN count(*) AS c",
                    {"id": task_id},
                )
                rec = await res.single()
                return bool(rec and rec["c"] > 0)
        except Exception as e:
            logger.debug("task_has_spawned_failed", error=str(e))
            return False

    async def claim_auto_discovery(self, engagement_id: str) -> bool:
        """Atomically claim auto-discovery dispatch for an engagement. Returns True only
        for the first caller — Neo4j MERGE locks the key, so concurrent hooks (and a
        restarted process) cannot both win. Returns False if Neo4j is unreachable (safe:
        no dispatch while the graph is down)."""
        cypher = """
        MERGE (c:AutoDiscoveryClaim {engagement_id: $eid})
        ON CREATE SET c.claimed_at = $ts, c._new = true
        ON MATCH SET c._new = false
        RETURN c._new AS is_new
        """
        try:
            async with self._driver.session() as s:
                res = await s.run(
                    cypher, {"eid": engagement_id, "ts": datetime.utcnow().isoformat()}
                )
                rec = await res.single()
                return bool(rec and rec["is_new"])
        except Exception as e:
            logger.debug("claim_auto_discovery_failed", error=str(e))
            return False

    async def reset_interrupted_tasks(self) -> List[Dict[str, Any]]:
        """Mark tasks left 'running' by a dead process as 'interrupted', increment their
        recovery_attempts, and return the full props needed to RE-DISPATCH them
        (AIOSOP-AUDIT-2026-06-16). Previously only id/type/engagement_id were returned,
        so recover_state could not actually re-run the interrupted work."""
        cypher = """
        MATCH (t:Task {status:'running'})
        SET t.status='interrupted', t.updated_at=$ts,
            t.recovery_attempts=coalesce(t.recovery_attempts, 0)+1
        RETURN t.id AS id, t.type AS type, t.engagement_id AS engagement_id,
               t.agent_type AS agent_type, t.payload AS payload, t.priority AS priority,
               t.max_retries AS max_retries, t.timeout_seconds AS timeout_seconds,
               t.recovery_attempts AS recovery_attempts
        """
        out: List[Dict[str, Any]] = []
        try:
            async with self._driver.session() as s:
                res = await s.run(cypher, {"ts": datetime.utcnow().isoformat()})
                async for rec in res:
                    out.append(dict(rec))
        except Exception as e:
            logger.debug("reset_interrupted_tasks_failed", error=str(e))
        return out

    async def mark_task_status(self, task_id: str, status: str) -> None:
        """Set a Task node's status (used by recovery to fail tasks over the
        re-dispatch cap). AIOSOP-AUDIT-2026-06-16."""
        try:
            async with self._driver.session() as s:
                await s.run(
                    "MATCH (t:Task {id:$id}) SET t.status=$status, t.updated_at=$ts",
                    {
                        "id": task_id,
                        "status": status,
                        "ts": datetime.utcnow().isoformat(),
                    },
                )
        except Exception as e:
            logger.debug("mark_task_status_failed", error=str(e))

    async def find_incomplete_chains(self) -> List[Dict[str, Any]]:
        """Completed chain parents missing their next SPAWNED child — candidates to resume."""
        cypher = """
        MATCH (t:Task {status:'completed'})
        WHERE t.type IN ['map_workflow','capture_authenticated_surface']
          AND NOT (t)-[:SPAWNED]->(:Task)
        RETURN t.id AS id, t.type AS type, t.engagement_id AS engagement_id,
               t.result_summary AS result_summary
        """
        out: List[Dict[str, Any]] = []
        try:
            async with self._driver.session() as s:
                res = await s.run(cypher)
                async for rec in res:
                    out.append(dict(rec))
        except Exception as e:
            logger.debug("find_incomplete_chains_failed", error=str(e))
        return out

    async def attach_evidence_to_step(
        self,
        step_id: str,
        evidence_type: str,
        path: str,
        engagement_id: str,
        workflow_id: str = "",
        extra: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Create an Evidence node and link it to a WorkflowStep and parent Workflow.
        Returns the evidence node id. Idempotent on (step_id, path)."""
        evidence_id = f"ev-{hashlib.sha1(f'{step_id}|{path}'.encode()).hexdigest()[:16]}"
        cypher = """
        MERGE (ev:Evidence {id: $id})
        SET ev.type = $type,
            ev.path = $path,
            ev.engagement_id = $engagement_id,
            ev.workflow_id = $workflow_id,
            ev.extra = $extra,
            ev.created_at = $created_at
        WITH ev
        OPTIONAL MATCH (s:Step {id: $step_id})
        FOREACH (x IN CASE WHEN s IS NOT NULL THEN [s] ELSE [] END |
            MERGE (s)-[:HAS_EVIDENCE]->(ev)
        )
        WITH ev
        OPTIONAL MATCH (w:Workflow {id: $workflow_id})
        FOREACH (x IN CASE WHEN w IS NOT NULL THEN [w] ELSE [] END |
            MERGE (w)-[:HAS_EVIDENCE]->(ev)
        )
        RETURN ev.id AS id
        """
        async with self._driver.session() as session:
            result = await session.run(
                cypher,
                {
                    "id": evidence_id,
                    "type": evidence_type,
                    "path": path,
                    "engagement_id": engagement_id,
                    "workflow_id": workflow_id,
                    "step_id": step_id,
                    "extra": json.dumps(extra or {}, default=str),
                    "created_at": datetime.utcnow().isoformat(),
                },
            )
            record = await result.single()
            return record["id"]

    async def add_business_invariant(
        self,
        invariant: BusinessInvariant,
        engagement_id: str,
        is_violated: bool = False,
    ) -> str:
        """Persist a BusinessInvariant so it can be surfaced on the Research
        Intelligence dashboard. Idempotent on invariant id."""
        cypher = """
        MERGE (i:BusinessInvariant {id: $id})
        SET i.description = $description,
            i.target_resource_type = $target_resource_type,
            i.required_state = $required_state,
            i.violation_strategy = $violation_strategy,
            i.actor_constraints = $actor_constraints,
            i.is_violated = $is_violated,
            i.engagement_id = $engagement_id,
            i.created_at = coalesce(i.created_at, $created_at)
        RETURN i.id AS id
        """
        async with self._driver.session() as session:
            result = await session.run(
                cypher,
                {
                    "id": invariant.id,
                    "description": invariant.description,
                    "target_resource_type": invariant.target_resource_type,
                    "required_state": invariant.required_state,
                    "violation_strategy": invariant.violation_strategy,
                    "actor_constraints": invariant.actor_constraints,
                    "is_violated": is_violated,
                    "engagement_id": engagement_id or invariant.engagement_id,
                    "created_at": datetime.utcnow().isoformat(),
                },
            )
            record = await result.single()
            return record["id"]

    async def mark_invariant_violated(self, invariant_id: str) -> None:
        """Flag a previously-persisted invariant as violated."""
        cypher = "MATCH (i:BusinessInvariant {id: $id}) SET i.is_violated = true RETURN i.id"
        async with self._driver.session() as session:
            await session.run(cypher, {"id": invariant_id})

    async def add_graphql_schema(self, schema: "GraphQLSchema") -> str:
        """Persist a discovered GraphQL schema. Idempotent on endpoint+engagement."""
        cypher = """
        MERGE (s:GraphQLSchema {id: $id})
        SET s.endpoint_url = $endpoint_url,
            s.introspection_enabled = $introspection_enabled,
            s.engagement_id = $engagement_id,
            s.created_at = coalesce(s.created_at, $created_at)
        RETURN s.id AS id
        """
        async with self._driver.session() as session:
            result = await session.run(
                cypher,
                {
                    "id": schema.id,
                    "endpoint_url": schema.endpoint_url,
                    "introspection_enabled": schema.introspection_enabled,
                    "engagement_id": schema.engagement_id,
                    "created_at": datetime.utcnow().isoformat(),
                },
            )
            record = await result.single()
            return record["id"] if record else schema.id

    async def add_graphql_operation(self, op: "GraphQLOperation") -> str:
        """Persist a GraphQL operation and link it to its schema."""
        cypher = """
        MERGE (o:GraphQLOperation {id: $id})
        SET o.name = $name,
            o.type = $type,
            o.schema_id = $schema_id,
            o.is_hidden = $is_hidden,
            o.description = $description
        WITH o
        OPTIONAL MATCH (s:GraphQLSchema {id: $schema_id})
        FOREACH (x IN CASE WHEN s IS NOT NULL THEN [s] ELSE [] END |
            MERGE (s)-[:EXPOSES_OPERATION]->(o)
        )
        RETURN o.id AS id
        """
        async with self._driver.session() as session:
            result = await session.run(
                cypher,
                {
                    "id": op.id,
                    "name": op.name,
                    "type": op.type,
                    "schema_id": op.schema_id,
                    "is_hidden": op.is_hidden,
                    "description": op.description,
                },
            )
            record = await result.single()
            return record["id"] if record else op.id

    async def get_invariants(self, engagement_id: str) -> List[Dict[str, Any]]:
        """Return persisted invariants for an engagement, shaped for the UI."""
        cypher = (
            "MATCH (i:BusinessInvariant) WHERE i.engagement_id = $sid "
            "RETURN i ORDER BY i.created_at DESC"
        )
        out: List[Dict[str, Any]] = []
        async with self._driver.session() as session:
            result = await session.run(cypher, {"sid": engagement_id})
            async for record in result:
                i = dict(record["i"])
                out.append(
                    {
                        "id": i.get("id"),
                        "description": i.get("description"),
                        "target_resource_type": i.get("target_resource_type"),
                        "violation_strategy": i.get("violation_strategy"),
                        "is_violated": bool(i.get("is_violated", False)),
                    }
                )
        return out

    async def get_task_dependents(self, parent_id: str) -> List[str]:
        """Return IDs of tasks that were SPAWNED by the given parent task."""
        cypher = """
        MATCH (parent:Task {id: $pid})-[:SPAWNED]->(child:Task)
        RETURN child.id AS id
        """
        try:
            async with self._driver.session() as s:
                res = await s.run(cypher, {"pid": parent_id})
                return [rec["id"] async for rec in res]
        except Exception as e:
            logger.debug("get_task_dependents_failed", error=str(e))
            return []

    async def import_knowledge_base(self) -> None:
        """Import the static security taxonomy from SecurityKnowledgeEngine into Neo4j."""
        from ai_osop.core.knowledge_engine import get_knowledge_engine

        engine = get_knowledge_engine()
        vulnerabilities_data = engine._data.get("vulnerabilities", {})

        # 1. Create VulnClass nodes
        vulns_list: List[Dict[str, Any]] = []
        for vuln_key, mapping in vulnerabilities_data.items():
            vulns_list.append(
                {
                    "id": vuln_key,
                    "title": mapping.get("title", ""),
                    "description": mapping.get("description", ""),
                }
            )

        if vulns_list:
            await self.run_write_query(
                """
                UNWIND $vulns AS vuln
                MERGE (v:VulnClass:TaxonomyNode {id: vuln.id})
                SET v.title = vuln.title, v.description = vuln.description
                """,
                {"vulns": vulns_list},
            )

        # 2. CWE mappings
        cwe_mappings: List[Dict[str, Any]] = []
        for vuln_key, mapping in vulnerabilities_data.items():
            for cwe_id in mapping.get("cwe", []):
                cwe_mappings.append({"vuln_id": vuln_key, "cwe_id": cwe_id})

        if cwe_mappings:
            await self.run_write_query(
                """
                UNWIND $cwes AS c
                MERGE (vuln:VulnClass:TaxonomyNode {id: c.vuln_id})
                MERGE (cwe:CWE:TaxonomyNode {id: c.cwe_id})
                MERGE (vuln)-[:MAPPED_TO]->(cwe)
                """,
                {"cwes": cwe_mappings},
            )

        # 3. CAPEC mappings
        capec_mappings: List[Dict[str, Any]] = []
        for vuln_key, mapping in vulnerabilities_data.items():
            for capec_id in mapping.get("capec", []):
                capec_mappings.append({"vuln_id": vuln_key, "capec_id": capec_id})

        if capec_mappings:
            await self.run_write_query(
                """
                UNWIND $capecs AS cap
                MERGE (vuln:VulnClass:TaxonomyNode {id: cap.vuln_id})
                MERGE (capec:CAPEC:TaxonomyNode {id: cap.capec_id})
                MERGE (vuln)-[:MAPPED_TO]->(capec)
                """,
                {"capecs": capec_mappings},
            )

        # 4. MitreAttack mappings
        mitre_mappings: List[Dict[str, Any]] = []
        for vuln_key, mapping in vulnerabilities_data.items():
            for mitre_id in mapping.get("mitre_attack", []):
                mitre_mappings.append({"vuln_id": vuln_key, "mitre_id": mitre_id})

        if mitre_mappings:
            await self.run_write_query(
                """
                UNWIND $mitres AS m
                MERGE (vuln:VulnClass:TaxonomyNode {id: m.vuln_id})
                MERGE (mitre:MitreAttack:TaxonomyNode {id: m.mitre_id})
                MERGE (vuln)-[:MAPPED_TO]->(mitre)
                """,
                {"mitres": mitre_mappings},
            )

        # 5. OwaspWstg mappings
        wstg_mappings: List[Dict[str, Any]] = []
        for vuln_key, mapping in vulnerabilities_data.items():
            for wstg_id in mapping.get("owasp_wstg", []):
                wstg_mappings.append({"vuln_id": vuln_key, "wstg_id": wstg_id})

        if wstg_mappings:
            await self.run_write_query(
                """
                UNWIND $wstgs AS w
                MERGE (vuln:VulnClass:TaxonomyNode {id: w.vuln_id})
                MERGE (wstg:OwaspWstg:TaxonomyNode {id: w.wstg_id})
                MERGE (vuln)-[:MAPPED_TO]->(wstg)
                """,
                {"wstgs": wstg_mappings},
            )

        # 6. Next step recommendation mappings
        recommendation_chains: List[Dict[str, Any]] = []
        for vuln_key, next_steps in engine._data.get("recommendation_chains", {}).items():
            for ns_str in next_steps:
                recommendation_chains.append({"vuln_id": vuln_key, "next_id": ns_str})

        if recommendation_chains:
            await self.run_write_query(
                """
                UNWIND $chains AS ch
                MERGE (vuln:VulnClass:TaxonomyNode {id: ch.vuln_id})
                MERGE (next:VulnClass:TaxonomyNode {id: ch.next_id})
                MERGE (vuln)-[:NEXT_STEP]->(next)
                """,
                {"chains": recommendation_chains},
            )

        # 7. Technology mappings
        tech_mappings: List[Dict[str, Any]] = []
        for tech_name, vuln_classes in engine._data.get("technology_matrix", {}).items():
            for vuln_class in vuln_classes:
                tech_mappings.append({"tech_id": tech_name, "vuln_id": vuln_class})

        if tech_mappings:
            await self.run_write_query(
                """
                UNWIND $techs AS t
                MERGE (tech:Technology:TaxonomyNode {id: t.tech_id})
                MERGE (vuln:VulnClass:TaxonomyNode {id: t.vuln_id})
                MERGE (tech)-[:RELEVANT_VULN]->(vuln)
                """,
                {"techs": tech_mappings},
            )

    async def sync_user_session(self, session: Any) -> None:
        """Sync user session (Identity, Session, Credential, Role) to Neo4j attack graph."""
        engagement_id = session.engagement_id
        user_label = session.user_label
        captured_at = session.captured_at.isoformat() if session.captured_at else None
        expires_at = session.expires_at.isoformat() if session.expires_at else None

        # Determine type
        if session.bearer_token:
            cred_type = "bearer"
        elif session.cookies:
            cred_type = "cookie"
        else:
            cred_type = "anonymous"

        # Determine role
        role_name = "admin" if "admin" in user_label else "standard"

        # Node IDs
        identity_id = f"identity-{engagement_id}-{user_label}"
        session_id = f"session-{engagement_id}-{user_label}"
        credential_id = f"credential-{engagement_id}-{user_label}"
        role_id = f"role-{engagement_id}-{role_name}"

        cypher = """
        MERGE (i:Identity {id: $identity_id})
        SET i.user_label = $user_label,
            i.engagement_id = $engagement_id

        MERGE (s:Session {id: $session_id})
        SET s.status = $status,
            s.captured_at = $captured_at,
            s.expires_at = $expires_at,
            s.engagement_id = $engagement_id

        MERGE (c:Credential {id: $credential_id})
        SET c.type = $cred_type,
            c.captured_at = $captured_at,
            c.expires_at = $expires_at,
            c.engagement_id = $engagement_id

        MERGE (r:Role {id: $role_id})
        SET r.name = $role_name,
            r.engagement_id = $engagement_id

        MERGE (s)-[:AUTHENTICATED_AS]->(i)
        MERGE (i)-[:HAS_CREDENTIAL]->(c)
        MERGE (i)-[:HAS_ROLE]->(r)
        """

        async with self._driver.session() as db_session:
            with trace_span(
                "graph_memory.sync_user_session",
                attributes={
                    "engagement_id": engagement_id,
                    "user_label": user_label,
                },
            ):
                await db_session.run(
                    cypher,
                    {
                        "identity_id": identity_id,
                        "session_id": session_id,
                        "credential_id": credential_id,
                        "role_id": role_id,
                        "user_label": user_label,
                        "engagement_id": engagement_id,
                        "status": "active",
                        "captured_at": captured_at,
                        "expires_at": expires_at,
                        "cred_type": cred_type,
                        "role_name": role_name,
                    },
                )

    async def delete_user_session_node(self, engagement_id: str, user_label: str) -> None:
        """Mark Session as expired and DETACH DELETE the credential node."""
        session_id = f"session-{engagement_id}-{user_label}"
        credential_id = f"credential-{engagement_id}-{user_label}"

        cypher = """
        OPTIONAL MATCH (s:Session {id: $session_id})
        SET s.status = 'expired'
        WITH s
        OPTIONAL MATCH (c:Credential {id: $credential_id})
        DETACH DELETE c
        """

        async with self._driver.session() as db_session:
            with trace_span(
                "graph_memory.delete_user_session_node",
                attributes={
                    "engagement_id": engagement_id,
                    "user_label": user_label,
                },
            ):
                await db_session.run(
                    cypher,
                    {
                        "session_id": session_id,
                        "credential_id": credential_id,
                    },
                )

    async def close(self) -> None:
        if self._driver:
            await self._driver.close()

    async def find_vulnerability_chains(self, engagement_id: str) -> List[Dict[str, Any]]:
        """Find multi-hop vulnerability chains."""
        query = """
        MATCH path = (v1:Vulnerability)-[:LEADS_TO*1..5]->(v2:Vulnerability)
        WHERE v1.engagement_id = $eid
        RETURN [n in nodes(path) | n.id] AS chain,
               [n in nodes(path) | n.title] AS titles
        """
        async with self._driver.session() as session:
            result = await session.execute_read(lambda tx: tx.run(query, eid=engagement_id))
            records = await result.data()
            return records

    async def scan_next_targets(
        self,
        engagement_id: str,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Return endpoints that should be scanned next for this engagement.

        Prioritizes by:
        1. Endpoints with no vulnerability scan history (never scanned)
        2. Endpoints whose technology stack has associated vuln classes in the
           knowledge base but no matching Vulnerability node yet
        3. Endpoints reachable from a known vulnerable endpoint via graph traversal

        Returns a list of dicts with: endpoint_id, url, method, priority_score, reason
        """
        cypher = """
        MATCH (e:Endpoint {engagement_id: $engagement_id})
        OPTIONAL MATCH (e)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        WITH e, count(v) AS vuln_count
        OPTIONAL MATCH (e)<-[:HAS_ENDPOINT]-(:Asset)
            -[:HAS_ENDPOINT]->(peer:Endpoint)
            -[:HAS_VULNERABILITY]->(pv:Vulnerability)
        WITH e, vuln_count, count(DISTINCT pv) AS neighbor_vuln_count
        RETURN
            e.id AS endpoint_id,
            e.url AS url,
            e.method AS method,
            e.technologies AS technologies,
            vuln_count,
            neighbor_vuln_count,
            CASE
                WHEN vuln_count = 0 AND neighbor_vuln_count > 0 THEN 10
                WHEN vuln_count = 0 THEN 5
                ELSE 1
            END AS priority_score,
            CASE
                WHEN vuln_count = 0 AND neighbor_vuln_count > 0 THEN 'unscanned_near_vulnerable'
                WHEN vuln_count = 0 THEN 'unscanned'
                ELSE 'scanned'
            END AS reason
        ORDER BY priority_score DESC, e.url ASC
        LIMIT $limit
        """
        async with self._driver.session() as session:
            result = await session.run(cypher, {"engagement_id": engagement_id, "limit": limit})
            return [dict(rec) async for rec in result]

    async def get_related_endpoints(
        self,
        endpoint_id: str,
        max_hops: int = 2,
    ) -> List[Dict[str, Any]]:
        """Return endpoints related to the given endpoint via graph traversal.

        Traverses LEADS_TO relationships up to max_hops (default 2).
        Useful for expanding the attack surface from a known vulnerable endpoint.
        Returns list of dicts with: endpoint_id, url, method, distance.
        """
        # ponytail: Neo4j variable-length range bounds must be literals; max 3 hops is
        # sufficient for attack-surface expansion without exploding traversal cost.
        cypher = """
        MATCH path = (start:Endpoint {id: $endpoint_id})
                     -[:LEADS_TO*1..3]-(related:Endpoint)
        WHERE related.id <> $endpoint_id
        RETURN DISTINCT
            related.id AS endpoint_id,
            related.url AS url,
            related.method AS method,
            length(path) AS distance
        ORDER BY distance ASC
        LIMIT 50
        """
        async with self._driver.session() as session:
            result = await session.run(cypher, {"endpoint_id": endpoint_id})
            return [dict(rec) async for rec in result]

    async def get_co_occurring_vuln_classes(
        self,
        vuln_type: str,
        engagement_id: Optional[str] = None,
        min_co_occurrences: int = 1,
    ) -> List[Dict[str, Any]]:
        """Return vulnerability classes that co-occur with the given vuln_type.

        Looks across all engagements (or a specific one) for endpoints that have
        both the given vuln_type AND another vuln_type. Returns the co-occurring
        classes ranked by frequency. Useful for attack-chain planning.
        """
        params: Dict[str, Any] = {"vuln_type": vuln_type, "min_co": min_co_occurrences}
        where_parts = ["v2.vuln_type <> $vuln_type"]
        if engagement_id:
            where_parts.append("v1.engagement_id = $engagement_id")
            params["engagement_id"] = engagement_id
        where_clause = " AND ".join(where_parts)
        cypher = f"""
        MATCH (e:Endpoint)-[:HAS_VULNERABILITY]->(v1:Vulnerability {{vuln_type: $vuln_type}}),
              (e)-[:HAS_VULNERABILITY]->(v2:Vulnerability)
        WHERE {where_clause}
        WITH v2.vuln_type AS co_vuln_type, count(*) AS frequency
        WHERE frequency >= $min_co
        RETURN co_vuln_type, frequency
        ORDER BY frequency DESC
        LIMIT 20
        """
        async with self._driver.session() as session:
            result = await session.run(cypher, params)
            return [dict(rec) async for rec in result]

    async def get_reusable_auth_contexts(
        self,
        engagement_id: str,
        target_endpoint_id: str,
    ) -> List[Dict[str, Any]]:
        """Return user session contexts that can be reused for the target endpoint.

        Finds UserSession nodes in the same engagement whose auth scope matches
        the target endpoint's host. Returns sessions ranked by recency.
        """
        cypher = """
        MATCH (us:UserSession {engagement_id: $engagement_id})
        MATCH (e:Endpoint {id: $endpoint_id})
        WHERE us.domain = e.host
           OR e.url CONTAINS us.domain
        RETURN
            us.user_label AS user_label,
            us.domain AS domain,
            us.captured_at AS captured_at,
            us.has_bearer AS has_bearer,
            us.cookie_count AS cookie_count
        ORDER BY us.captured_at DESC
        LIMIT 10
        """
        async with self._driver.session() as session:
            result = await session.run(
                cypher,
                {"engagement_id": engagement_id, "endpoint_id": target_endpoint_id},
            )
            return [dict(rec) async for rec in result]
