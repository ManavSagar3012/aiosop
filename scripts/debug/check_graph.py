import asyncio
from ai_osop.memory.graph_memory import GraphMemory

async def check():
    graph_mem = GraphMemory()
    await graph_mem.connect()
    async with graph_mem._driver.session() as session:
        res = await session.run("MATCH (n) RETURN labels(n) as label, count(n) as c")
        for record in await res.data():
            print(f"{record['label']} : {record['c']}")
            
        print("\nChecking workflows:")
        res = await session.run("MATCH (w:Workflow)-[:HAS_STEP]->(s:WorkflowStep) RETURN w.id, s.id")
        for record in await res.data():
            print(f"Workflow: {record['w.id']}, Step: {record['s.id']}")
            
    await graph_mem.close()

if __name__ == '__main__':
    asyncio.run(check())
