import asyncio
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy import text

async def check():
    mem = SessionMemory()
    await mem.connect()
    async with mem._async_session() as session:
        res = await session.execute(text("SELECT timestamp, event_type, action, result FROM audit_logs ORDER BY timestamp DESC LIMIT 15"))
        for r in res.all():
            if 'task' in r.event_type:
                print(f"[{r.timestamp}] EVENT: {r.event_type} ACTION: {r.action} RESULT: {r.result}")
    await mem.close()

if __name__ == '__main__':
    asyncio.run(check())
