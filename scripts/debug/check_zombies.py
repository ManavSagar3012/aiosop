import asyncio
from ai_osop.memory.graph_memory import GraphMemory

async def check_zombies():
    g = GraphMemory()
    await g.connect()
    aid = 'asset-uat-bugbounty.nonprod.syfe.com'
    async with g._driver.session() as s:
        res = await s.run('MATCH (n {id: $aid}) RETURN n, n.engagement_id as eid', aid=aid)
        records = await res.data()
        for r in records:
            print(f"Found zombie node: {r['n']} (Engagement: {r['eid']})")
            # Force delete
            await s.run('MATCH (n {id: $aid}) DETACH DELETE n', aid=aid)
            print("Zombie deleted.")
    await g.close()

if __name__ == "__main__":
    asyncio.run(check_zombies())
