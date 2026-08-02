import asyncio
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy import select
from ai_osop.memory.session_memory import AuditLogORM

async def run():
    mem = SessionMemory()
    await mem.connect()
    async with mem._async_session() as session:
        sid = "eng-20260709110154-e2e-gj-20260709-110154"
        res = await session.execute(
            select(AuditLogORM)
            .where(AuditLogORM.engagement_id == sid)
            .where(AuditLogORM.event_type == "task_reaped")
            .order_by(AuditLogORM.timestamp.desc())
        )
        events = res.scalars().all()
        print(f"Total Reaped Tasks in Session: {len(events)}")
        for e in events:
            print(f"  Event: {e.event_id} | Timestamp: {e.timestamp}")
            print(f"    Action: {e.action}")
            print(f"    Result: {e.result}")
            print("-" * 50)
    await mem.close()

if __name__ == "__main__":
    asyncio.run(run())
