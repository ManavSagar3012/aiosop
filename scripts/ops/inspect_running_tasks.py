import asyncio
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy import select
from ai_osop.memory.session_memory import TaskORM

async def run():
    mem = SessionMemory()
    await mem.connect()
    async with mem._async_session() as session:
        res = await session.execute(
            select(TaskORM).where(TaskORM.status == "running")
        )
        tasks = res.scalars().all()
        print(f"Total Running Tasks: {len(tasks)}")
        for t in tasks:
            print(f"  Task ID: {t.id} | Type: {t.type} | Agent: {t.assigned_agent_id} | Session: {t.engagement_id}")
    await mem.close()

if __name__ == "__main__":
    asyncio.run(run())
