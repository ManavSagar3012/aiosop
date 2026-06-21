import asyncio
import sys
from ai_osop.memory.graph_memory import GraphMemory

async def archive_ghosts_and_orphans():
    gm = GraphMemory()
    await gm.connect()
    
    print("=== Archiving Ghost & Orphan Nodes in Neo4j ===")
    
    queries = {
        "Workflows (Ghost)": """
            MATCH (w:Workflow)
            WHERE NOT (w)-[:HAS_STEP]->() AND (w.archived IS NULL OR w.archived = false)
            SET w.archived = true, w.cleanup_reason = "ghost_workflow"
            RETURN count(w) as count
        """,
        "Steps (Orphan)": """
            MATCH (s:Step)
            WHERE NOT ()-[:HAS_STEP]->(s) AND (s.archived IS NULL OR s.archived = false)
            SET s.archived = true, s.cleanup_reason = "orphan"
            RETURN count(s) as count
        """,
        "Evidence (Orphan)": """
            MATCH (e:Evidence)
            WHERE NOT ()-[:HAS_EVIDENCE]->(e) AND (e.archived IS NULL OR e.archived = false)
            SET e.archived = true, e.cleanup_reason = "orphan"
            RETURN count(e) as count
        """,
        "Vulnerabilities (Orphan)": """
            MATCH (v:Vulnerability)
            WHERE NOT ()-[:HAS_VULNERABILITY]->(v) AND (v.archived IS NULL OR v.archived = false)
            SET v.archived = true, v.cleanup_reason = "orphan"
            RETURN count(v) as count
        """,
        "DiffAuthFindings (Orphan)": """
            MATCH (d:DiffAuthFinding)
            WHERE NOT ()-[:HAS_DIFF_AUTH_FINDING]->(d) AND (d.archived IS NULL OR d.archived = false)
            SET d.archived = true, d.cleanup_reason = "orphan"
            RETURN count(d) as count
        """
    }
    
    async with gm._driver.session() as session:
        for name, cypher in queries.items():
            res = await session.run(cypher)
            record = await res.single()
            count = record["count"] if record else 0
            print(f"Archived {count} nodes for {name}")
            
    await gm.close()
    print("Archiving complete!")

if __name__ == "__main__":
    asyncio.run(archive_ghosts_and_orphans())
