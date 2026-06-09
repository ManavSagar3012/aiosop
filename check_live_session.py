import asyncio
from ai_osop.memory.graph_memory import GraphMemory

async def check():
    g = GraphMemory()
    await g.connect()
    sid = "eng-20260606064845-full-test-1780728523"
    try:
        # Check assets
        res_a = await g._driver.execute_query("MATCH (a:Asset {engagement_id: $sid}) RETURN count(a) as count", {"sid": sid})
        # Check endpoints
        res_e = await g._driver.execute_query("MATCH (e:Endpoint {engagement_id: $sid}) RETURN count(e) as count", {"sid": sid})
        # Check vulnerabilities
        res_v = await g._driver.execute_query("MATCH (v:Vulnerability {engagement_id: $sid}) RETURN count(v) as count", {"sid": sid})
        
        print(f"Engagement: {sid}")
        print(f"Assets: {res_a.records[0]['count']}")
        print(f"Endpoints: {res_e.records[0]['count']}")
        print(f"Vulnerabilities: {res_v.records[0]['count']}")
        
    finally:
        await g.close()

if __name__ == "__main__":
    asyncio.run(check())
