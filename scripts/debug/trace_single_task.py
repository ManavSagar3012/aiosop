import asyncio
import json
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy import text

async def trace_dispatched_task():
    mem = SessionMemory()
    await mem.connect()
    
    # Get latest engagement
    async with mem._async_session() as session:
        res = await session.execute(text("SELECT engagement_id FROM audit_logs ORDER BY timestamp DESC LIMIT 1"))
        eng_id = res.scalar()
        print(f"--- TRACING ENGAGEMENT: {eng_id} ---")
        
        # Get tasks that were dispatched (assigned)
        query = text("""
            SELECT timestamp, event_type, action, result 
            FROM audit_logs 
            WHERE engagement_id=:eid 
            AND action->>'task_type' IN ('navigate', 'authenticate', 'map_workflow')
            ORDER BY timestamp ASC
        """)
        tasks = await session.execute(query, {"eid": eng_id})
        
        for task in tasks:
            action = json.loads(task.action) if isinstance(task.action, str) else task.action
            print(f"[{task.timestamp}] EVENT: {task.event_type}")
            print(f"  Task: {action.get('task_id')} | Type: {action.get('task_type')} | Assigned to: {action.get('agent_id')}")
            print(f"  Result: {task.result}")
            print("-" * 20)
    await mem.close()

if __name__ == "__main__":
    asyncio.run(trace_dispatched_task())
