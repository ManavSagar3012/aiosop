import asyncio
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy import text
from datetime import datetime, timedelta

async def check_recent_logs():
    mem = SessionMemory()
    await mem.connect()
    five_mins_ago = datetime.utcnow() - timedelta(minutes=5)
    async with mem._async_session() as session:
        res = await session.execute(text("SELECT timestamp, event_type, engagement_id, action, result FROM audit_logs WHERE timestamp > :ts ORDER BY timestamp DESC"), {"ts": five_mins_ago})
        for r in res.all():
            print(f"[{r.timestamp}] {r.event_type} | {r.engagement_id} | {str(r.action)[:100]} -> {str(r.result)[:200]}")
    await mem.close()

if __name__ == "__main__":
    asyncio.run(check_recent_logs())
