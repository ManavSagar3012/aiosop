from datetime import datetime
import uuid
import structlog
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy.dialects.postgresql import insert

logger = structlog.get_logger("ai_osop.findings_corpus")

class FindingCorpusService:
    """
    Sprint 7: Aggregates historical finding outcomes into a centralized SQL Corpus.
    """
    def __init__(self, graph_memory: GraphMemory, session_memory: SessionMemory):
        self.graph_memory = graph_memory
        self.session_memory = session_memory

    async def aggregate_accepted_findings(self):
        """Fetch accepted findings from Neo4j and persist in Postgres Corpus."""
        cypher = """
        MATCH (d:DiffAuthFinding)
        WHERE d.outcome = 'accepted'
        RETURN d
        """
        async with self.graph_memory._driver.session() as session:
            result = await session.run(cypher)
            async for record in result:
                finding_data = record["d"]
                # Persist to Postgres via SessionMemory/ORM
                await self.session_memory.upsert_corpus_finding(finding_data)
        logger.info("Finding corpus aggregation complete.")
