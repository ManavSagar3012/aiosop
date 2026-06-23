import asyncio
import structlog
from ai_osop.core.findings_corpus import FindingCorpusService
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.memory.session_memory import SessionMemory

logger = structlog.get_logger("ai_osop.aggregate_findings")

async def main():
    logger.info("Initializing Finding Corpus Aggregator...")
    graph = GraphMemory()
    try:
        await graph.connect()
    except Exception as e:
        logger.warning("Neo4j offline, skipping corpus aggregation (Simulation Mode)", error=str(e))
        return

    session_mem = SessionMemory()
    # Assume settings are loaded via environment variables
    # For a real run, ensure Postgres is available.
    
    service = FindingCorpusService(graph, session_mem)
    try:
        await service.aggregate_accepted_findings()
    except Exception as e:
        logger.error("Aggregation failed", error=str(e))
    
    await graph.close()
    logger.info("Finding Corpus Aggregation Done.")

if __name__ == "__main__":
    asyncio.run(main())
