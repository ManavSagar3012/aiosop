import asyncio
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy import select
from ai_osop.memory.session_memory import TaskORM

async def run():
    mem = SessionMemory()
    await mem.connect()
    async with mem._async_session() as session:
        sid = "eng-20260709151325-e2e-gj-20260709-151325"
        res = await session.execute(
            select(TaskORM)
            .where(TaskORM.engagement_id == sid)
            .where(TaskORM.status == "completed")
            .order_by(TaskORM.completed_at.desc())
        )
        tasks = res.scalars().all()
        print(f"Total Completed Tasks in Session: {len(tasks)}")
        for t in tasks[:15]:
            print(f"  Task ID: {t.id} | Type: {t.type} | Completed At: {t.completed_at}")
            print(f"    Result: {t.result}")
            print("-" * 50)
    await mem.close()

if __name__ == "__main__":
    asyncio.run(run())
