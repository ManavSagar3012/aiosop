import asyncio
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy import select
from ai_osop.memory.session_memory import TaskORM

async def run():
    mem = SessionMemory()
    await mem.connect()
    async with mem._async_session() as session:
        res = await session.execute(
            select(TaskORM)
            .where(TaskORM.status == "completed")
            .where(TaskORM.engagement_id == "eng-20260710101315-dash-mission-1783678395491")
            .order_by(TaskORM.completed_at.desc())
        )
        tasks = res.scalars().all()
        print(f"Total Completed Tasks: {len(tasks)}")
        for t in tasks:
            print(f"  Task ID: {t.id} | Type: {t.type} | Target: {t.payload.get('url')} | Completed At: {t.completed_at}")
            print(f"    Result: {t.result}")
            print("-" * 50)
    await mem.close()

if __name__ == "__main__":
    asyncio.run(run())
