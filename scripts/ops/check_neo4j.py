import asyncio
from ai_osop.memory.graph_memory import GraphMemory

async def check_neo4j():
    g = GraphMemory()
    await g.connect()
    sid = "eng-20260614153815-syfe-live-mission-v1"
    stats = await g.get_graph_stats(sid)
    print(f"Stats for {sid}: {stats}")
    await g.close()

if __name__ == "__main__":
    asyncio.run(check_neo4j())
