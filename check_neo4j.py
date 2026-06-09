import asyncio
from ai_osop.memory.graph_memory import GraphMemory

async def check():
    g = GraphMemory()
    await g.connect()
    try:
        # Check total nodes
        result = await g._driver.execute_query("MATCH (n) RETURN count(n) as count")
        print(f"Total nodes: {result.records[0]['count']}")
        
        # Check first 5 nodes
        result = await g._driver.execute_query("MATCH (n) RETURN n LIMIT 5")
        for record in result.records:
            print(record['n'])
    finally:
        await g.close()

if __name__ == "__main__":
    asyncio.run(check())
