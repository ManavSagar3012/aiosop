import asyncio
from ai_osop.memory.graph_memory import GraphMemory

async def check():
    g = GraphMemory()
    await g.connect()
    sid = "eng-20260606051831-auto-mission-1780723109"
    try:
        # Check vulnerabilities
        res_v = await g._driver.execute_query("MATCH (v:Vulnerability {engagement_id: $sid}) RETURN count(v) as count", {"sid": sid})
        # Check endpoints
        res_e = await g._driver.execute_query("MATCH (e:Endpoint {engagement_id: $sid}) RETURN count(e) as count", {"sid": sid})
        
        print(f"Engagement: {sid}")
        print(f"Endpoints Indexed: {res_e.records[0]['count']}")
        print(f"Vulnerabilities Found: {res_v.records[0]['count']}")
        
    finally:
        await g.close()

if __name__ == "__main__":
    asyncio.run(check())
