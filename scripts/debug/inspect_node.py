import asyncio
from ai_osop.memory.graph_memory import GraphMemory

async def inspect_node():
    g = GraphMemory()
    await g.connect()
    aid = 'asset-uat-bugbounty.nonprod.syfe.com'
    async with g._driver.session() as s:
        res = await s.run('MATCH (n {id: $aid}) RETURN n, labels(n) as labels', aid=aid)
        records = await res.data()
        if not records:
            print("Node NOT FOUND by ID.")
        for r in records:
            print(f"Found node: {r['n']} (Labels: {r['labels']})")
    await g.close()

if __name__ == "__main__":
    asyncio.run(inspect_node())
