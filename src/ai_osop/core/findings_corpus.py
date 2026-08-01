from typing import Any, Optional

import structlog

from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.memory.session_memory import SessionMemory

logger = structlog.get_logger("ai_osop.findings_corpus")


class FindingCorpusService:
    """
    Sprint 7: Aggregates historical finding outcomes into a centralized SQL Corpus.
    """

    def __init__(
        self,
        graph_memory: GraphMemory,
        session_memory: SessionMemory,
        bug_bounty_adapter: Optional[Any] = None,
    ):
        self.graph_memory = graph_memory
        self.session_memory = session_memory
        # Optional source of real submission outcomes (HackerOne/Bugcrowd, or the
        # deterministic simulator). Injected so the corpus can capture rejections
        # and duplicates, not just accepted findings — that is the ground truth the
        # confidence calibration loop (P2b) learns from.
        self.bug_bounty_adapter = bug_bounty_adapter

    async def aggregate_accepted_findings(self):
        """Fetch accepted findings from Neo4j and persist in Postgres Corpus."""
        cypher = """
        MATCH (d:DiffAuthFinding)
        WHERE d.outcome = 'accepted'
        RETURN d
        """
        try:
            records = await self.graph_memory.run_read_query(cypher)
            for record in records:
                finding_data = record["d"]
                try:
                    await self.session_memory.upsert_corpus_finding(finding_data)
                except Exception as e:
                    logger.error(
                        "failed_upsert_corpus_finding",
                        finding_id=finding_data.get("id"),
                        error=str(e),
                    )
        except Exception as e:
            logger.error("failed_aggregate_accepted_findings", error=str(e))
        logger.info("Finding corpus aggregation complete.")

    async def ingest_external(self, entries) -> int:
        """Ingest externally sourced corpus entries; withdrawn entries are refused.

        Withdrawal is the read-only policy escape valve for the benchmark corpus:
        once an entry is withdrawn (e.g. takedown, bad provenance), it must never
        re-enter the training/validation path.
        """
        rejected = [e for e in entries if e.get("withdrawn")]
        if rejected:
            raise ValueError(
                f"refusing {len(rejected)} withdrawn corpus entries: "
                f"{[e.get('id') for e in rejected]}"
            )
        return len(entries)

    async def ingest_outcomes(self, engagement_id: str) -> int:
        """Pull real submission outcomes and record them (with their true status).

        Closes the calibration feedback loop (P2b): every synced outcome —
        accepted, triaged, paid, duplicate, **and rejected** — is written into the
        corpus keyed by finding type, so ``get_historical_success_rate`` reflects
        genuine ground truth instead of an accepted-only view that would always
        score 1.0. Returns the number of outcomes ingested. Best-effort per record
        so one bad row never aborts the sync.
        """
        if self.bug_bounty_adapter is None:
            logger.info("ingest_outcomes skipped: no bug-bounty adapter wired.")
            return 0

        try:
            outcomes = await self.bug_bounty_adapter.sync_outcomes(engagement_id)
        except Exception as e:
            logger.error("failed_sync_outcomes", engagement_id=engagement_id, error=str(e))
            return 0

        from ai_osop.core.taxonomy import category_for_finding_type

        ingested = 0
        for record in outcomes:
            # status may be an OutcomeStatus enum or a raw string.
            status = getattr(record.status, "value", record.status)
            # Normalize the concrete finding type onto the hypothesis-category
            # vocabulary so calibration lookups (keyed by hypothesis category) can
            # actually match recorded outcomes. The raw finding_type is preserved in
            # the payload for traceability.
            finding_data = {
                "id": record.finding_id,
                "category": category_for_finding_type(record.finding_type),
                "finding_type": record.finding_type,
                "severity": record.severity,
                "engagement_id": record.engagement_id,
                "external_report_id": record.external_report_id,
                "program_payout": record.program_payout,
            }
            try:
                await self.session_memory.upsert_corpus_finding(
                    finding_data, outcome=str(status).lower()
                )
                ingested += 1
            except Exception as e:
                logger.error(
                    "failed_ingest_outcome",
                    finding_id=record.finding_id,
                    error=str(e),
                )
        logger.info("Outcome ingestion complete.", engagement_id=engagement_id, ingested=ingested)
        return ingested
