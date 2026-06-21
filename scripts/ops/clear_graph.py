import asyncio
from ai_osop.memory.graph_memory import GraphMemory

async def clear_graph():
    g = GraphMemory()
    await g.connect()
    sid = "eng-20260613102452-syfe-final-verification"
    async with g._driver.session() as s:
        await s.run('MATCH (n) WHERE n.engagement_id = $sid DETACH DELETE n', sid=sid)
    print(f'Graph cleared for {sid}.')
    await g.close()

if __name__ == "__main__":
    asyncio.run(clear_graph())
