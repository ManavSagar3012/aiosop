import asyncio
import sys
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy import select
from ai_osop.memory.session_memory import TaskORM

async def run():
    mem = SessionMemory()
    await mem.connect()
    async with mem._async_session() as session:
        # Get latest session_id
        res = await session.execute(
            select(TaskORM.engagement_id)
            .order_by(TaskORM.created_at.desc())
            .limit(1)
        )
        latest_sid = res.scalar()
        print(f"Latest Session ID: {latest_sid}")

        # List all tasks for this session
        res_tasks = await session.execute(
            select(TaskORM)
            .where(TaskORM.engagement_id == latest_sid)
            .order_by(TaskORM.created_at.asc())
        )
        tasks = res_tasks.scalars().all()
        print(f"Total tasks in session: {len(tasks)}")
        for t in tasks:
            print(f"Task ID: {t.id}")
            print(f"  Type: {t.type} | Agent: {t.assigned_agent_id} | Status: {t.status}")
            print(f"  Result: {t.result}")
            print("-" * 50)
            
    await mem.close()

if __name__ == "__main__":
    asyncio.run(run())
