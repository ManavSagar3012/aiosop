import asyncio
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy import text

async def get_all_results():
    mem = SessionMemory()
    await mem.connect()
    session_id = "eng-20260614161330-syfe-live-mission-v2"
    async with mem._async_session() as session:
        res = await session.execute(text("SELECT action, result FROM audit_logs WHERE event_type='task_completed' AND engagement_id=:sid ORDER BY timestamp ASC"), {"sid": session_id})
        for r in res.all():
            print(f"ACTION: {r.action}")
            print(f"RESULT: {r.result}")
            print("-" * 20)
    await mem.close()

if __name__ == "__main__":
    asyncio.run(get_all_results())
