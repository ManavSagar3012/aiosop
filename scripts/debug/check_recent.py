import asyncio
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy import text

async def get_recent():
    mem = SessionMemory()
    await mem.connect()
    async with mem._async_session() as session:
        res = await session.execute(text("SELECT action, result FROM audit_logs ORDER BY timestamp DESC LIMIT 5"))
        for r in res.all():
            print(f"ACTION: {r.action}\nRESULT: {r.result}\n---")
    await mem.close()

if __name__ == '__main__':
    asyncio.run(get_recent())