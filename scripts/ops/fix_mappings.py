import asyncio
from ai_osop.memory.graph_memory import GraphMemory

async def fix_properties():
    g = GraphMemory()
    await g.connect()
    
    try:
        # Fix: For every HAS_VULNERABILITY relationship, set the endpoint_id property on the Vulnerability node
        # if it's missing.
        cypher = """
        MATCH (e:Endpoint)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        WHERE v.endpoint_id IS NULL
        SET v.endpoint_id = e.id
        RETURN count(v) as fixed
        """
        result = await g._driver.execute_query(cypher)
        print(f"Fixed {result.records[0]['fixed']} vulnerability source mappings.")
        
    finally:
        await g.close()

if __name__ == "__main__":
    asyncio.run(fix_properties())
