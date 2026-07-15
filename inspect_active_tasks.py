import asyncio
import sys
from sqlalchemy import select
from ai_osop.memory.session_memory import SessionMemory, TaskORM

async def inspect():
    sm = SessionMemory()
    await sm.connect()
    
    engagement_id = "eng-20260715070834-syfe-live-mission-v2"
    async with sm._async_session() as session:
        # Check running tasks
        result = await session.execute(
            select(TaskORM).where(TaskORM.engagement_id == engagement_id, TaskORM.status == "running")
        )
        tasks = result.scalars().all()
        print(f"Running tasks: {len(tasks)}")
        for t in tasks:
            print(f"  Task {t.id} ({t.type}): assigned to {t.assigned_agent_id}, retry={t.retry_count}")
            
        # Check completed tasks
        result = await session.execute(
            select(TaskORM).where(TaskORM.engagement_id == engagement_id, TaskORM.status == "completed")
        )
        tasks = result.scalars().all()
        print(f"Completed tasks: {len(tasks)}")
        for t in tasks:
            print(f"  Task {t.id} ({t.type}): result={str(t.result)[:150]}")
            
    await sm.close()

if __name__ == "__main__":
    asyncio.run(inspect())
