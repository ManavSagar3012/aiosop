import asyncio
import os
import json
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.memory.graph_memory import GraphMemory
from sqlalchemy import text

async def audit():
    print('--- PHASE 1: WORKFLOW INVENTORY ---')
    graph_mem = GraphMemory()
    await graph_mem.connect()
    
    workflows = []
    async with graph_mem._driver.session() as g_session:
        res = await g_session.run('MATCH (w:Workflow) OPTIONAL MATCH (w)-[:HAS_STEP]->(s:WorkflowStep) RETURN w, collect(s) as steps')
        async for record in res:
            w = record['w']
            steps = record['steps']
            print(f"Workflow ID: {w['id']} | Name: {w.get('name')} | Steps: {len(steps)}")
            for step in steps:
                print(f"  Step: {step['id']} | URL: {step.get('url')} | Order: {step.get('order')}")
            workflows.append((w, steps))

    print('\n--- PHASE 2: EVIDENCE VAULT CHECK ---')
    vault_files = []
    for root, _, files in os.walk('evidence_vault'):
        for f in files:
            vault_files.append(os.path.join(root, f))
    print(f'Total files in evidence_vault: {len(vault_files)}')
    for f in vault_files:
        print(f'  {f}')

    print('\n--- PHASE 3: AUDIT LOG CHECK ---')
    mem = SessionMemory()
    await mem.connect()
    async with mem._async_session() as session:
        res = await session.execute(text("SELECT event_type, action, result FROM audit_logs WHERE event_type LIKE '%task%' ORDER BY timestamp DESC LIMIT 20"))
        for r in res.all():
            print(f"[{r.event_type}] Action: {str(r.action)[:100]} | Result: {str(r.result)[:100]}")
            
    await graph_mem.close()
    await mem.close()

if __name__ == '__main__':
    asyncio.run(audit())
