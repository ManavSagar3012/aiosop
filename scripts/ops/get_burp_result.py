import asyncio
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy import text

async def get_task_result():
    mem = SessionMemory()
    await mem.connect()
    session_id = "eng-20260614153815-syfe-live-mission-v1"
    async with mem._async_session() as session:
        res = await session.execute(text("SELECT result FROM audit_logs WHERE event_type='task_completed' AND action::text LIKE '%burp_scan%' AND engagement_id=:sid ORDER BY timestamp DESC LIMIT 1"), {"sid": session_id})
        print(res.scalar())
    await mem.close()

if __name__ == "__main__":
    asyncio.run(get_task_result())
