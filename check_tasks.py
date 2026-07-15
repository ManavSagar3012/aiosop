import asyncio
import sys
import traceback
from sqlalchemy import select

async def test():
    print("Connecting Postgres...")
    from ai_osop.memory.session_memory import SessionMemory
    sm = SessionMemory()
    await sm.connect()
    
    # Query Postgres database using SQLAlchemy Session
    # The Task model is in core/models.py or memory/session_memory.py
    # Let's inspect session_memory.py to see where Task is mapped or what tables exist.
    from ai_osop.memory.session_memory import TaskORM
    
    async with sm._async_session() as session:
        result = await session.execute(
            select(TaskORM).where(TaskORM.engagement_id == "eng-20260714135632-syfe-live-v3")
        )
        tasks = result.scalars().all()
        print(f"Total tasks in DB for eng-20260714135632-syfe-live-v3: {len(tasks)}")
        for t in tasks:
            print(f"Task {t.id}: type={t.type} status={t.status} agent={t.assigned_agent_id}")
            if t.status in ("completed", "failed") and t.result:
                # Print first 200 characters of the result to keep output clean
                print(f"  Result: {str(t.result)[:200]}")

if __name__ == "__main__":
    try:
        asyncio.run(test())
    except Exception as e:
        traceback.print_exc()
        sys.exit(1)
