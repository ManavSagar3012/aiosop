import asyncio
from ai_osop.memory.graph_memory import GraphMemory

async def debug_graph():
    g = GraphMemory()
    await g.connect()
    try:
        session_id = "eng-20260609094410-ui-mission-1780998250623"
        print(f"DEBUG: Checking vulnerabilities for session: {session_id}")
        
        query = "MATCH (v:Vulnerability {engagement_id: $sid}) RETURN v.id as id, v.title as title"
        result = await g._driver.execute_query(query, sid=session_id)
        
        if not result.records:
            print("ERROR: No Vulnerability nodes found for this engagement.")
        else:
            for record in result.records:
                print(f"FOUND VULN: {record['id']} - {record['title']}")
                
        # Also check graph stats as the orchestrator uses this
        stats = await g.get_graph_stats(session_id)
        print(f"Graph stats: {stats}")
        
    finally:
        await g.close()

if __name__ == "__main__":
    asyncio.run(debug_graph())
