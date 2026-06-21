import asyncio
import json
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.memory.graph_memory import GraphMemory
from sqlalchemy import text

async def check():
    mem = SessionMemory()
    await mem.connect()
    
    print("--- RECENT AUDIT LOGS ---")
    async with mem._async_session() as session:
        res = await session.execute(text("SELECT timestamp, event_type, action, result, severity FROM audit_logs ORDER BY timestamp DESC LIMIT 20"))
        for r in res.all():
            print(f"[{r.timestamp}] {r.event_type} ({r.severity})")
            if r.event_type == 'task.completed' and r.action and r.action.get('task_type') == 'replay_for_diff_auth':
                print(f"    RESULT: {json.dumps(r.result, indent=2)}")

    print("\n--- GRAPH DIFF FINDINGS ---")
    graph_mem = GraphMemory()
    await graph_mem.connect()
    async with graph_mem._driver.session() as g_session:
        res = await g_session.run("MATCH (d:DiffAuthFinding) RETURN d ORDER BY d.timestamp DESC LIMIT 5")
        found = False
        async for record in res:
            found = True
            d = record["d"]
            print(f"Resource: {d.get('resource_id')}")
            print(f"Category: {d.get('category')}")
            print(f"Expected: {d.get('expected_result')}")
            print(f"Observed: {d.get('observed_result')}")
            print("-----------------")
        if not found:
            print("None found.")
            
    await mem.close()
    await graph_mem.close()

if __name__ == "__main__":
    asyncio.run(check())
