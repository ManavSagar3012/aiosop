import asyncio
from ai_osop.memory.graph_memory import GraphMemory

async def audit_graph():
    print("PHASE 4 — GRAPH INTEGRITY AUDIT (REFINED)\\n")
    gm = GraphMemory()
    await gm.connect()
    
    queries = {
        "Workflow without Step": "MATCH (w:Workflow) WHERE NOT (w)-[:HAS_STEP]->(:Step) RETURN count(w) as count, collect(w.id) as ids",
        "Workflow without Evidence": "MATCH (w:Workflow) WHERE NOT (w)-[:HAS_EVIDENCE]->(:Evidence) AND NOT (w)-[:HAS_STEP]->(:Step)-[:HAS_EVIDENCE]->(:Evidence) RETURN count(w) as count, collect(w.id) as ids",
        "Step without Workflow": "MATCH (s:Step) WHERE NOT (:Workflow)-[:HAS_STEP]->(s) RETURN count(s) as count, collect(s.id) as ids",
        "Step without Endpoint": "MATCH (s:Step) WHERE NOT (s)-[:TARGETS_ENDPOINT]->(:Endpoint) RETURN count(s) as count, collect(s.id) as ids",
        "Evidence without Step/Workflow": "MATCH (e:Evidence) WHERE NOT (:Step)-[:HAS_EVIDENCE]->(e) AND NOT (:Workflow)-[:HAS_EVIDENCE]->(e) RETURN count(e) as count, collect(e.id) as ids",
        "Vulnerability without Endpoint": "MATCH (v:Vulnerability) WHERE NOT (:Endpoint)-[:HAS_VULNERABILITY]->(v) RETURN count(v) as count, collect(v.id) as ids",
        "DiffAuthFinding without Endpoint/Resource": "MATCH (d:DiffAuthFinding) WHERE NOT (:Endpoint)-[:HAS_DIFF_AUTH_FINDING]->(d) AND NOT (:Resource)-[:HAS_DIFF_AUTH_FINDING]->(d) RETURN count(d) as count, collect(d.id) as ids",
        "Asset without Endpoints": "MATCH (a:Asset) WHERE NOT (a)-[:HAS_ENDPOINT]->(:Endpoint) RETURN count(a) as count, collect(a.id) as ids"
    }

    async with gm._driver.session() as session:
        for name, query in queries.items():
            result = await session.run(query)
            record = await result.single()
            count = record["count"]
            ids = record["ids"]
            
            status = "VERIFIED" if count == 0 else "BROKEN"
            print(f"{name}: {status}")
            print(f"  Count: {count}")
            if count > 0:
                print(f"  IDs: {ids[:10]} {'...' if len(ids) > 10 else ''}")
            print("")

    await gm.close()

if __name__ == "__main__":
    asyncio.run(audit_graph())
