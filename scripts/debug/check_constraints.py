import asyncio
from ai_osop.memory.graph_memory import GraphMemory

async def check_constraints():
    g = GraphMemory()
    await g.connect()
    async with g._driver.session() as s:
        res = await s.run('SHOW CONSTRAINTS')
        records = await res.data()
        for r in records:
            print(r)
    await g.close()

if __name__ == "__main__":
    asyncio.run(check_constraints())
