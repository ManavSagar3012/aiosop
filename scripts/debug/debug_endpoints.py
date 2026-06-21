import asyncio
from ai_osop.memory.graph_memory import GraphMemory

async def debug_graph():
    g = GraphMemory()
    await g.connect()
    try:
        session_id = "eng-20260609094410-ui-mission-1780998250623"
        print(f"DEBUG: Checking for endpoints in session: {session_id}")
        
        query = "MATCH (e:Endpoint {engagement_id: $sid}) RETURN e.id as id, e.url as url"
        result = await g._driver.execute_query(query, sid=session_id)
        
        if not result.records:
            print("ERROR: No Endpoint nodes found for this engagement.")
        else:
            for record in result.records:
                print(f"FOUND ENDPOINT: {record['id']} - {record['url']}")
                
    finally:
        await g.close()

if __name__ == "__main__":
    asyncio.run(debug_graph())
