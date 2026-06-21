import asyncio
import json
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy import text

async def audit():
    mem = SessionMemory()
    await mem.connect()
    
    # Get latest engagement
    async with mem._async_session() as session:
        res = await session.execute(text("SELECT engagement_id FROM audit_logs ORDER BY timestamp DESC LIMIT 1"))
        eng_id = res.scalar()
        print(f"--- AUDITING ENGAGEMENT: {eng_id} ---")
        
        # Get tasks
        query = text("""
            SELECT timestamp, event_type, action, result 
            FROM audit_logs 
            WHERE engagement_id=:eid 
            AND action->>'task_type' IN ('full_recon', 'capture_session')
            ORDER BY timestamp ASC
        """)
        tasks = await session.execute(query, {"eid": eng_id})
        
        for t in tasks:
            action = json.loads(t.action) if isinstance(t.action, str) else t.action
            print(f"[{t.timestamp}] {t.event_type} | Task: {action.get('task_id')} | Type: {action.get('task_type')}")
    await mem.close()

if __name__ == '__main__':
    asyncio.run(audit())
