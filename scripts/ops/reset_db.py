import asyncio
from ai_osop.memory.session_memory import SessionMemory, Base

async def reset_db():
    mem = SessionMemory()
    await mem.connect()
    async with mem._pg_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    await mem.close()

if __name__ == "__main__":
    asyncio.run(reset_db())