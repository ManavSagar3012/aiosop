import asyncio
import json
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy import text

async def audit_tasks():
    mem = SessionMemory()
    await mem.connect()
    
    # 1. Latest Engagement
    async with mem._async_session() as session:
        res = await session.execute(text("SELECT engagement_id FROM audit_logs ORDER BY timestamp DESC LIMIT 1"))
        eng_id = res.scalar()
        print(f"--- LATEST ENGAGEMENT: {eng_id} ---")
        
        # 2. Get all tasks for this engagement
        query = text("""
            SELECT timestamp, event_type, action, result 
            FROM audit_logs 
            WHERE engagement_id=:eid 
            AND action->>'task_type' IN ('navigate', 'authenticate', 'map_workflow', 'replay_for_diff_auth', 'extract_semantics', 'capture_session')
            ORDER BY timestamp ASC
        """)
        tasks = await session.execute(query, {"eid": eng_id})
        
        for task in tasks:
            action = task.action
            if isinstance(action, str):
                action = json.loads(action)
            print(f"[{task.timestamp}] EVENT: {task.event_type}")
            print(f"  Type: {action.get('task_type')}, ID: {action.get('task_id')}")
            print(f"  Result: {task.result}")
            print("-" * 20)
    await mem.close()

if __name__ == "__main__":
    asyncio.run(audit_tasks())
