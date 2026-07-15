import asyncio
import sys
import traceback

async def test():
    print("Connecting GraphMemory...")
    from ai_osop.memory.graph_memory import GraphMemory
    gm = GraphMemory()
    await gm.connect()
    
    # Query Neo4j database using self._driver
    query = """
    MATCH (n)
    RETURN labels(n) AS labels, count(n) AS count
    """
    async with gm._driver.session() as session:
        result = await session.run(query)
        records = await result.data()
        print("Neo4j Node Counts:")
        for r in records:
            print(f"  Labels: {r['labels']}, Count: {r['count']}")
            
    # List nodes for current engagement
    query_nodes = """
    MATCH (n)
    WHERE n.engagement_id = $eid OR n.session_id = $eid
    RETURN labels(n) AS labels, properties(n) AS props
    """
    async with gm._driver.session() as session:
        result = await session.run(query_nodes, eid="eng-20260714135632-syfe-live-v3")
        records = await result.data()
        print("\nNodes for current engagement:")
        for r in records:
            print(f"  Labels: {r['labels']}")
            print(f"    Props: {r['props']}")

if __name__ == "__main__":
    try:
        asyncio.run(test())
    except Exception as e:
        traceback.print_exc()
        sys.exit(1)
