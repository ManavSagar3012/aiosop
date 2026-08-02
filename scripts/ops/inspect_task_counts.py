import asyncio
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy import select, func
from ai_osop.memory.session_memory import TaskORM

async def run():
    mem = SessionMemory()
    await mem.connect()
    async with mem._async_session() as session:
        sid = "eng-20260710101315-dash-mission-1783678395491"
        res = await session.execute(
            select(TaskORM.status, func.count(TaskORM.id))
            .where(TaskORM.engagement_id == sid)
            .group_by(TaskORM.status)
        )
        stats = res.all()
        print(f"Task status breakdown for session {sid}:")
        total = 0
        for status, count in stats:
            print(f"  {status}: {count}")
            total += count
        print(f"Total Tasks: {total}")
    await mem.close()

if __name__ == "__main__":
    asyncio.run(run())
