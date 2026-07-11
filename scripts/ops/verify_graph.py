import asyncio
import sys
from ai_osop.memory.graph_memory import GraphMemory

async def run():
    g = GraphMemory()
    await g.connect()
    
    # 1. Get stats
    print("--- GRAPH STATS ---")
    # Get all nodes count
    records = await g.run_read_query("MATCH (n) RETURN labels(n) as label, count(n) as count", {})
    for r in records:
        print(f"Label: {r['label']} | Count: {r['count']}")
        
    # 2. Get recent tasks
    print("\n--- RECENT TASKS ---")
    tasks = await g.run_read_query("MATCH (t:Task) RETURN t.id as id, t.type as type, t.status as status, t.assigned_agent_id as agent LIMIT 25", {})
    for t in tasks:
        print(f"Task: {t['id']} | Type: {t['type']} | Status: {t['status']} | Agent: {t['agent']}")
        
    # 3. Get recent endpoints
    print("\n--- RECENT ENDPOINTS ---")
    eps = await g.run_read_query("MATCH (e:APIEndpoint) RETURN e.method as method, e.url as url LIMIT 15", {})
    for e in eps:
        print(f"Endpoint: {e['method']} {e['url']}")
        
    # 4. Get recent vulnerabilities
    print("\n--- RECENT VULNERABILITIES ---")
    vulns = await g.run_read_query("MATCH (v:Vulnerability) RETURN v.title as title, v.severity as severity LIMIT 15", {})
    for v in vulns:
        print(f"Vuln: {v['title']} | Severity: {v['severity']}")

    await g.close()

if __name__ == "__main__":
    asyncio.run(run())
