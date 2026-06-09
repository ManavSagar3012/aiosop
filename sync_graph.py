import asyncio
from ai_osop.memory.graph_memory import GraphMemory

async def sync():
    g = GraphMemory()
    await g.connect()
    
    # Target session ID from logs
    current_sid = "eng-20260606044329-eng-ginandjuice.shop-1780721009683"
    
    try:
        # Update all nodes that belong to 'ginandjuice.shop' but have a different engagement_id
        # This fixes the 'Knowledge Graph' visibility issue
        cypher = """
        MATCH (n)
        WHERE (n.value CONTAINS 'ginandjuice.shop' OR n.url CONTAINS 'ginandjuice.shop')
        AND n.engagement_id <> $sid
        SET n.engagement_id = $sid
        RETURN count(n) as updated
        """
        result = await g._driver.execute_query(cypher, {"sid": current_sid})
        print(f"Relinked {result.records[0]['updated']} nodes to current session.")
        
    finally:
        await g.close()

if __name__ == "__main__":
    asyncio.run(sync())
