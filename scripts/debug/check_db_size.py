import asyncio
from ai_osop.memory.session_memory import SessionMemory, AuditLogORM
from sqlalchemy import select, func

async def check_size():
    m = SessionMemory()
    await m.connect()
    async with m._async_session() as s:
        res = await s.execute(select(func.count(AuditLogORM.event_id)))
        print(f'Audit Log Total: {res.scalar()}')
    await m.close()

if __name__ == "__main__":
    asyncio.run(check_size())
