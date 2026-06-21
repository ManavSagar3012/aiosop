import asyncio
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy import text
import json

async def check():
    mem = SessionMemory()
    await mem.connect()
    async with mem._async_session() as session:
        print("--- LATEST AUDIT LOGS ---")
        res = await session.execute(text("SELECT timestamp, event_type, action, result FROM audit_logs ORDER BY timestamp DESC LIMIT 20"))
        for r in res.all():
            if 'task' in r.event_type:
                print(f"[{r.timestamp}] {r.event_type} | {str(r.action)[:100]} | {str(r.result)[:100]}")
    await mem.close()

if __name__ == '__main__':
    asyncio.run(check())
