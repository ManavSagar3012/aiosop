import sys, time, httpx, os
from neo4j import GraphDatabase
TOK=os.environ["OSOP_API_TOKEN"]; NEOPW=os.environ["OSOP_NEO4J_PASSWORD"]
API="http://127.0.0.1:8200"; H={"Authorization":f"Bearer {TOK}"}; JS="http://localhost:3000"
neo=GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j",NEOPW))
def log(*a): print(*a, flush=True)
em=f"auto_{int(time.time())}@bench.local"
httpx.post(f"{JS}/api/Users", json={"email":em,"password":"P@ss123!","passwordRepeat":"P@ss123!","securityQuestion":{"id":1},"securityAnswer":"x"}, timeout=15)
jtok=httpx.post(f"{JS}/rest/user/login", json={"email":em,"password":"P@ss123!"}, timeout=15).json()["authentication"]["token"]
log("got Juice Shop token len", len(jtok))
sid=f"auto-{int(time.time())}"
eid=httpx.post(f"{API}/engagements", headers=H, timeout=30, json={"engagement_id":sid,"domains":["localhost:3000"],"allowed_techniques":["passive","active"],"authorization_ref":"AUTO","roe":{"note":"x"}}).json()["session_id"]
log("engagement:", eid)
r=httpx.put(f"{API}/engagements/{eid}/sessions/user_a", headers=H, timeout=30, json={"user_label":"user_a","bearer_token":jtok,"cookies":[{"name":"token","value":jtok,"domain":"localhost","path":"/"}],"metadata":{"imported_by":"auto"}})
log(f"[import] HTTP {r.status_code}")
with neo.session() as s:
    log("Session node:", s.run("MATCH (s:Session {engagement_id:$e}) RETURN s.authenticated AS a, s.user_label AS u", e=eid).data())
seen={}; t0=time.time()
while time.time()-t0 < 160:
    tks=httpx.get(f"{API}/tasks", headers=H, params={"engagement_id":eid}, timeout=15)
    arr=tks.json() if tks.status_code==200 and isinstance(tks.json(),list) else []
    for t in arr:
        k=t.get("task_id"); st=t.get("status")
        if seen.get(k)!=st:
            seen[k]=st
            log(f"  [t+{int(time.time()-t0):>3}s] {str(t.get('task_type')):<34} {st:<10} agent={t.get('assigned_agent_id')}")
    if seen and all(v in ("completed","failed","cancelled") for v in seen.values()) and any('extract' in (t.get('task_type') or '') for t in arr):
        break
    time.sleep(4)
log("FINAL:", {k[:12]:v for k,v in seen.items()})
log("tasks_seen", len(seen), "DONE")
