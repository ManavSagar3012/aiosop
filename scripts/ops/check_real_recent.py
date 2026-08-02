import asyncio
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy import select
from ai_osop.memory.session_memory import AuditLogORM

async def run():
    mem = SessionMemory()
    await mem.connect()
    async with mem._async_session() as session:
        res = await session.execute(
            select(AuditLogORM).order_by(AuditLogORM.timestamp.desc()).limit(50)
        )
        events = res.scalars().all()
        print(f"Total Audit Events: {len(events)}")
        for e in reversed(events):
            print(f"Event: {e.event_type} | Severity: {e.severity} | Actor: {e.actor_id} | Created: {e.timestamp}")
            print(f"  Action: {e.action}")
            print(f"  Result: {e.result}")
            print("-" * 50)
    await mem.close()

if __name__ == "__main__":
    asyncio.run(run())
