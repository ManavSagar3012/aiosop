import asyncio
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy import select
from ai_osop.memory.session_memory import TaskORM

async def run():
    # Get latest session ID
    mem = SessionMemory()
    await mem.connect()
    async with mem._async_session() as session:
        res = await session.execute(
            select(TaskORM.engagement_id)
            .order_by(TaskORM.created_at.desc())
            .limit(1)
        )
        latest_sid = res.scalar()
    await mem.close()
    
    if not latest_sid:
        print("No sessions found.")
        return
        
    print(f"Latest Session ID: {latest_sid}")
    
    g = GraphMemory()
    await g.connect()
    stats = await g.get_graph_stats(latest_sid)
    print(f"Stats for {latest_sid}: {stats}")
    
    # Query all Vulnerability nodes for this session
    async with g._driver.session() as s:
        res = await s.run(
            'MATCH (v:Vulnerability {engagement_id: $sid}) RETURN v.title, v.severity, v.description, v.tool_source',
            {"sid": latest_sid}
        )
        async for rec in res:
            print(f"Finding: {rec['v.title']} | Severity: {rec['v.severity']} | Source: {rec['v.tool_source']}")
            print(f"  Description: {rec['v.description']}")
            print("-" * 50)
            
    await g.close()

if __name__ == "__main__":
    asyncio.run(run())
