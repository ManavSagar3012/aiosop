import asyncio
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy import text

async def find_logs():
    mem = SessionMemory()
    await mem.connect()
    sid = "eng-20260614153815-syfe-live-mission-v1"
    async with mem._async_session() as session:
        # Check by engagement_id field first
        res = await session.execute(text("SELECT event_type, action, result FROM audit_logs WHERE engagement_id=:sid OR action::text LIKE :sid_pattern OR context::text LIKE :sid_pattern ORDER BY timestamp ASC"), {"sid": sid, "sid_pattern": f"%{sid}%"})
        for r in res.all():
            print(f"[{r.event_type}] {str(r.action)[:100]} -> {str(r.result)[:100]}")
    await mem.close()

if __name__ == "__main__":
    asyncio.run(find_logs())
