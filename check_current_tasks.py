import asyncio
import sys
import traceback
from sqlalchemy import select
from ai_osop.memory.session_memory import SessionMemory, TaskORM

async def check():
    sm = SessionMemory()
    await sm.connect()
    
    async with sm._async_session() as session:
        result = await session.execute(
            select(TaskORM).where(TaskORM.engagement_id == "eng-20260715070834-syfe-live-mission-v2")
        )
        tasks = result.scalars().all()
        print(f"Total tasks: {len(tasks)}")
        for t in tasks:
            print(f"Task {t.id}: type={t.type} status={t.status} agent={t.assigned_agent_id}")
            if t.result:
                print(f"  Result: {str(t.result)[:200]}")
    await sm.close()

if __name__ == "__main__":
    asyncio.run(check())
