import asyncio
from ai_osop.memory.graph_memory import GraphMemory

async def final_clean():
    g = GraphMemory()
    await g.connect()
    
    # IDs that kept appearing in errors
    ids = ['asset-uat-bugbounty.nonprod.syfe.com', 'ep-08b11a956cc1']
    
    async with g._driver.session() as s:
        for aid in ids:
            print(f"Force deleting {aid}...")
            await s.run('MATCH (n {id: $aid}) DETACH DELETE n', aid=aid)
        
        print("Final nuke of all non-current nodes for this target...")
        await s.run("""
            MATCH (n) 
            WHERE (n:Asset OR n:Endpoint) 
            AND NOT n.engagement_id = 'eng-20260613102452-syfe-final-verification'
            AND (n.value CONTAINS 'syfe' OR n.url CONTAINS 'syfe')
            DETACH DELETE n
        """)
        
    print("Cleanup COMPLETE.")
    await g.close()

if __name__ == "__main__":
    asyncio.run(final_clean())
