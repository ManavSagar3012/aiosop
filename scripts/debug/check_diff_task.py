import asyncio
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy import text

async def check_task_diff():
    mem = SessionMemory()
    await mem.connect()
    sid = "eng-20260614161330-syfe-live-mission-v2"
    async with mem._async_session() as session:
        # Get all task IDs scheduled
        res_scheduled = await session.execute(text("SELECT action->>'task_id' as task_id, action->>'task_type' as type FROM audit_logs WHERE event_type='task_scheduled' AND (engagement_id=:sid OR action::text LIKE :sid_pattern)"), {"sid": sid, "sid_pattern": f"%{sid}%"})
        scheduled = {r.task_id: r.type for r in res_scheduled.all() if r.task_id}
        
        # Get all task IDs completed or failed
        res_finished = await session.execute(text("SELECT action->>'task_id' as task_id, event_type FROM audit_logs WHERE event_type IN ('task_completed', 'task_failed') AND (engagement_id=:sid OR action::text LIKE :sid_pattern)"), {"sid": sid, "sid_pattern": f"%{sid}%"})
        finished = {r.task_id: r.event_type for r in res_finished.all() if r.task_id}
        
        print(f"Scheduled tasks: {len(scheduled)}")
        print(f"Finished tasks: {len(finished)}")
        for tid, etype in finished.items():
            print(f"FINISHED: {tid} [{etype}]")
                
    await mem.close()

if __name__ == "__main__":
    asyncio.run(check_task_diff())
