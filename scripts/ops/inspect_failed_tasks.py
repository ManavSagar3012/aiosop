import asyncio
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy import select
from ai_osop.memory.session_memory import TaskORM

async def run():
    mem = SessionMemory()
    await mem.connect()
    async with mem._async_session() as session:
        res = await session.execute(
            select(TaskORM).where(TaskORM.status == "failed").where(TaskORM.engagement_id == "eng-20260709154905-e2e-gj-20260709-154904").order_by(TaskORM.completed_at.desc())
        )
        tasks = res.scalars().all()
        print(f"Total Failed Tasks: {len(tasks)}")
        for t in tasks[:15]:
            print(f"  Task ID: {t.id} | Type: {t.type} | Completed At: {t.completed_at}")
            print(f"    Result: {t.result}")
            print("-" * 50)
    await mem.close()

if __name__ == "__main__":
    asyncio.run(run())
