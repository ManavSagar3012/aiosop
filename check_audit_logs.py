import asyncio
import sys
from sqlalchemy import select
from ai_osop.memory.session_memory import SessionMemory, AuditLogORM

async def check():
    sm = SessionMemory()
    await sm.connect()
    
    engagement_id = "eng-20260715070834-syfe-live-mission-v2"
    async with sm._async_session() as session:
        result = await session.execute(
            select(AuditLogORM)
            .where(AuditLogORM.engagement_id == engagement_id)
            .order_by(AuditLogORM.timestamp.desc())
            .limit(30)
        )
        logs = result.scalars().all()
        print(f"Total audit logs for engagement: {len(logs)}")
        for l in logs:
            print(f"[{l.timestamp}] {l.event_type} | action: {str(l.action)[:100]} | severity: {l.severity}")
            if l.result:
                print(f"  Summary: {str(l.result)[:150]}")

if __name__ == "__main__":
    asyncio.run(check())
