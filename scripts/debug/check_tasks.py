import asyncio
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy import text

async def check_session_tasks():
    mem = SessionMemory()
    await mem.connect()
    session_id = "eng-20260614153815-syfe-live-mission-v1"
    async with mem._async_session() as session:
        res = await session.execute(text("SELECT id, type, status FROM tasks WHERE engagement_id=:sid"), {"sid": session_id})
        for r in res.all():
            print(f"Task {r.id}: {r.type} [{r.status}]")
    await mem.close()

if __name__ == "__main__":
    asyncio.run(check_session_tasks())
