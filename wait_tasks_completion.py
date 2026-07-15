import asyncio
import sys
import time
from sqlalchemy import select
from ai_osop.memory.session_memory import SessionMemory, TaskORM

async def poll_tasks():
    sm = SessionMemory()
    await sm.connect()
    
    engagement_id = "eng-20260715070834-syfe-live-mission-v2"
    print(f"Monitoring engagement: {engagement_id}")
    
    while True:
        async with sm._async_session() as session:
            result = await session.execute(
                select(TaskORM).where(TaskORM.engagement_id == engagement_id)
            )
            tasks = result.scalars().all()
            
            total = len(tasks)
            completed = sum(1 for t in tasks if t.status == "completed")
            failed = sum(1 for t in tasks if t.status == "failed")
            running = sum(1 for t in tasks if t.status == "running")
            pending = sum(1 for t in tasks if t.status == "pending")
            
            print(f"[{time.strftime('%H:%M:%S')}] Total: {total} | Completed: {completed} | Failed: {failed} | Running: {running} | Pending: {pending}")
            
            # If all tasks are completed/failed, we check if the orchestrator phase has advanced or completed
            if total > 0 and running == 0 and pending == 0:
                print("All tasks finished!")
                break
                
        await asyncio.sleep(10)
        
    await sm.close()

if __name__ == "__main__":
    asyncio.run(poll_tasks())
