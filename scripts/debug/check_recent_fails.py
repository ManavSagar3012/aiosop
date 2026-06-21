import asyncio
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy import text

async def check():
    mem = SessionMemory()
    await mem.connect()
    async with mem._async_session() as session:
        res = await session.execute(text("SELECT timestamp, event_type, action, result FROM audit_logs WHERE event_type='task_failed' ORDER BY timestamp DESC LIMIT 10"))
        for r in res.all():
            print(f"[{r.timestamp}] EVENT: {r.event_type} ACTION: {r.action} RESULT: {r.result}")
    await mem.close()

if __name__ == '__main__':
    asyncio.run(check())
