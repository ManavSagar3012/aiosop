import asyncio
import json
import traceback
import sys
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.memory.graph_memory import GraphMemory

async def audit():
    try:
        session_mem = SessionMemory()
        await session_mem.connect()
        graph_mem = GraphMemory()
        await graph_mem.connect()

        metrics = {
            'workflows_completed': 0,
            'endpoints_discovered': 0,
            'auth_tested': 0,
            'diff_comparisons': 0,
            'anomalies_detected': 0,
            'rejected_by_verifier': 0,
            'survived_replay': 0,
            'live_provenance': 0,
            'human_reproducible': 0,
            'evidence_packages': 0
        }

        async with session_mem._async_session() as session:
            from sqlalchemy import text
            res = await session.execute(text('SELECT status, validated, is_accepted FROM outcome_records'))
            records = res.all()
            for status, validated, accepted in records:
                if status in ['verified', 'paid', 'triaged']:
                    metrics['survived_replay'] += 1
                    metrics['live_provenance'] += 1
                if status in ['rejected', 'fp'] or validated == 'False':
                    metrics['rejected_by_verifier'] += 1
                if status != 'unknown':
                    metrics['anomalies_detected'] += 1

        async with graph_mem._driver.session() as g_session:
            res = await g_session.run('MATCH (e:Endpoint) RETURN count(e) as c')
            record = await res.single()
            if record:
                metrics['endpoints_discovered'] = record['c']
            
            res = await g_session.run('MATCH (w:Workflow) RETURN count(w) as c')
            record = await res.single()
            if record:
                metrics['workflows_completed'] = record['c']
            
            res = await g_session.run('MATCH (d:DiffAuthFinding) RETURN count(d) as c')
            record = await res.single()
            if record:
                metrics['diff_comparisons'] = record['c']
            
        with open('audit_metrics.json', 'w') as f:
            json.dump(metrics, f)
            
        await session_mem.close()
        await graph_mem.close()
    except Exception as e:
        with open('audit_metrics_error.txt', 'w') as f:
            traceback.print_exc(file=f)

if __name__ == "__main__":
    asyncio.run(audit())
