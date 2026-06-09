import asyncio
from ai_osop.memory.graph_memory import GraphMemory

async def check():
    g = GraphMemory()
    await g.connect()
    sid = "eng-20260606052129-auto-mission-1780723287"
    try:
        # Check vulnerabilities and their validation status
        res = await g._driver.execute_query(
            "MATCH (v:Vulnerability {engagement_id: $sid}) RETURN v.id as id, v.validated as validated", 
            {"sid": sid}
        )
        print(f"Engagement: {sid}")
        for record in res.records:
            print(f"Vuln ID: {record['id']} | Validated: {record['validated']}")
            
    finally:
        await g.close()

if __name__ == "__main__":
    asyncio.run(check())
