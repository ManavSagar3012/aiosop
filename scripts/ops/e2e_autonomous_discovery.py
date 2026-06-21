"""
E2E runtime proof: AUTONOMOUS authenticated discovery.

Proves the pipeline runs from engagement creation + session import ALONE, with NO
operator-created map_workflow task:

    POST /engagements  +  PUT .../sessions/user_a
        -> orchestrator auto-dispatches  map_workflow         (hook: session-import)
        -> chain                          capture_authenticated_surface
        -> chain                          extract_har_api_inventory
        -> (:Workflow)-[:CALLED]->(:APIEndpoint) in Neo4j

Also proves idempotency: importing a second session does NOT create a 2nd map_workflow.

Target: OWASP Juice Shop (deliberately vulnerable, in-scope).
"""
import json
import sys
import time
from datetime import datetime

import httpx
from neo4j import GraphDatabase

API = "http://127.0.0.1:8200"
HDR = {"Authorization": "Bearer dev-token"}
NEO = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "password"))
HOST = "demo.owasp-juice.shop"

stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
SCOPE_ID = f"e2e-auto-{stamp}"
EV = {"scope_id": SCOPE_ID, "target_host": HOST, "started": datetime.utcnow().isoformat()}


def cy(q, **kw):
    with NEO.session() as s:
        return [r.data() for r in s.run(q, **kw)]


def counts(eid, tag):
    c = {
        "APIEndpoint_total": cy("MATCH (n:APIEndpoint) RETURN count(n) AS c")[0]["c"],
        "Workflow_total": cy("MATCH (n:Workflow) RETURN count(n) AS c")[0]["c"],
        "Task_total": cy("MATCH (n:Task) RETURN count(n) AS c")[0]["c"],
        "eng_APIEndpoint": cy("MATCH (w:Workflow {engagement_id:$e})-[:CALLED]->(a:APIEndpoint) "
                              "RETURN count(DISTINCT a) AS c", e=eid)[0]["c"],
        "eng_CALLED": cy("MATCH (w:Workflow {engagement_id:$e})-[:CALLED]->() RETURN count(*) AS c", e=eid)[0]["c"],
        "eng_Task": cy("MATCH (t:Task {engagement_id:$e}) RETURN count(t) AS c", e=eid)[0]["c"],
    }
    print(f"[counts:{tag}] {json.dumps(c)}")
    return c


def post(path, body):
    r = httpx.post(f"{API}{path}", headers=HDR, json=body, timeout=30)
    r.raise_for_status()
    return r.json()


def put(path, body):
    r = httpx.put(f"{API}{path}", headers=HDR, json=body, timeout=30)
    r.raise_for_status()
    return r.json()


def get(path, params=None):
    r = httpx.get(f"{API}{path}", headers=HDR, params=params, timeout=30)
    r.raise_for_status()
    return r.json()


def audit(eid, types=None):
    p = {"event_types": types} if types else None
    return get(f"/engagements/{eid}/audit-log", params=p)


def wait_task(tid, label, timeout=300):
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout:
        t = get(f"/tasks/{tid}")
        st = t["status"]
        if st != last:
            print(f"  [{label}] {tid[:12]} status={st} agent={t.get('assigned_agent_id')}")
            last = st
        if st in ("completed", "failed", "cancelled"):
            return t
        time.sleep(3)
    print(f"  [{label}] {tid[:12]} TIMEOUT (last={last})")
    return get(f"/tasks/{tid}")


def find_event(eid, created_type, timeout=120):
    """Poll audit-log until an event whose action.created_type matches appears."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        for ev in audit(eid):
            a = ev.get("action", {}) or {}
            if a.get("created_type") == created_type:
                return a.get("created_task_id")
        time.sleep(3)
    return None


def cookie():
    return [{"name": "welcomebanner_status", "value": "dismiss", "domain": HOST, "path": "/"}]


def main():
    # 1. Fresh engagement (NO map_workflow created by us).
    sess = post("/engagements", {
        "engagement_id": SCOPE_ID,
        "domains": [HOST],
        "allowed_techniques": ["passive", "active"],
        "authorization_ref": "E2E-AUTONOMOUS-DISCOVERY",
        "roe": {"note": "autonomous discovery proof"},
    })
    eid = sess["session_id"]  # orchestrator's canonical id; session_store + tasks key on this
    EV["engagement_id"] = eid
    print(f"[1] engagement created: {eid} phase={sess.get('phase')}")

    EV["counts_before"] = counts(eid, "before")

    # 2. Import session under the canonical engagement id -> fires auto-dispatch hook 2.
    us = put(f"/engagements/{eid}/sessions/user_a", {"user_label": "user_a", "cookies": cookie()})
    EV["session_imported"] = us
    print(f"[2] session imported user_a cookies={us.get('cookie_count')} expires={us.get('expires_at')}")

    # 3. Prove map_workflow was AUTO-dispatched (no operator task creation).
    print("[3] waiting for auto-dispatched map_workflow...")
    map_id = None
    t0 = time.time()
    while time.time() - t0 < 90 and not map_id:
        map_id = find_event_map_dispatch(eid)
        if map_id:
            break
        time.sleep(3)
    EV["map_workflow_task_id"] = map_id
    print(f"    map_workflow_task_id={map_id}")
    if not map_id:
        raise RuntimeError("map_workflow was NOT auto-dispatched")
    mt = wait_task(map_id, "map_workflow", timeout=300)
    EV["map_workflow"] = {"status": mt["status"], "agent": mt.get("assigned_agent_id"),
                          "workflow_id": (mt.get("result") or {}).get("workflow_id")}

    # 4. Prove the chain auto-created capture + extract.
    cap_id = find_event(eid, "capture_authenticated_surface", timeout=90)
    EV["capture_task_id"] = cap_id
    print(f"[4] capture_task_id={cap_id}")
    if cap_id:
        ct = wait_task(cap_id, "capture", timeout=300)
        EV["capture"] = {"status": ct["status"], "result": ct.get("result")}
    ext_id = find_event(eid, "extract_har_api_inventory", timeout=90)
    EV["extract_task_id"] = ext_id
    print(f"    extract_task_id={ext_id}")
    if ext_id:
        et = wait_task(ext_id, "extract", timeout=180)
        EV["extract"] = {"status": et["status"], "result": et.get("result")}

    # 5. counts AFTER + graph proof
    EV["counts_after"] = counts(eid, "after")
    rels = cy("MATCH (w:Workflow {engagement_id:$e})-[:CALLED]->(a:APIEndpoint) "
              "RETURN a.method AS method, a.host AS host, a.path AS path LIMIT 25", e=eid)
    EV["sample_api_endpoints"] = rels
    print(f"[5] Workflow->APIEndpoint ({len(rels)}):")
    for r in rels[:12]:
        print(f"      {r.get('method')} {r.get('host')}{r.get('path')}")

    spawned = cy("MATCH (p:Task {engagement_id:$e})-[:SPAWNED]->(c:Task) "
                 "RETURN p.type AS parent, c.type AS child", e=eid)
    EV["task_spawned_edges"] = spawned
    print(f"[6] SPAWNED edges: {json.dumps(spawned)}")

    # 7. evidence files
    import os
    vault = os.path.join("evidence_vault", eid)
    har = png = dom = trace = 0
    har_path = ""
    if os.path.isdir(vault):
        for root, _, files in os.walk(vault):
            for f in files:
                if f.endswith(".har"):
                    har += 1; har_path = os.path.join(root, f)
                elif f.endswith(".png"):
                    png += 1
                elif f.endswith(".html"):
                    dom += 1
                elif f.endswith(".zip"):
                    trace += 1
    EV["evidence"] = {"har": har, "har_path": har_path,
                      "har_bytes": os.path.getsize(har_path) if har_path and os.path.exists(har_path) else 0,
                      "screenshots": png, "dom_snapshots": dom, "traces": trace}
    print(f"[7] evidence: {json.dumps(EV['evidence'])}")

    # 8. audit summary
    allaudit = audit(eid)
    by_type = {}
    for ev in allaudit:
        by_type[ev.get("event_type")] = by_type.get(ev.get("event_type"), 0) + 1
    EV["audit_event_counts"] = by_type
    print(f"[8] audit events: {json.dumps(by_type)}")

    # 9. IDEMPOTENCY: import a 2nd session -> must NOT create a 2nd map_workflow.
    put(f"/engagements/{eid}/sessions/user_b", {"user_label": "user_b", "cookies": cookie()})
    time.sleep(5)
    map_dispatch_events = [e for e in audit(eid) if e.get("event_type") == "auto_map_dispatch"]
    map_tasks = cy("MATCH (t:Task {engagement_id:$e, type:'map_workflow'}) RETURN count(t) AS c", e=eid)[0]["c"]
    EV["idempotency"] = {"auto_map_dispatch_events": len(map_dispatch_events),
                         "map_workflow_task_nodes": map_tasks, "expected": 1}
    print(f"[9] idempotency: auto_map_dispatch={len(map_dispatch_events)} map_task_nodes={map_tasks} (expect 1)")

    EV["finished"] = datetime.utcnow().isoformat()
    out = f"e2e_autonomous_evidence_{stamp}.json"
    with open(out, "w") as f:
        json.dump(EV, f, indent=2, default=str)
    print(f"\n=== EVIDENCE WRITTEN: {out} ===")
    NEO.close()


def find_event_map_dispatch(eid):
    for ev in audit(eid, ["auto_map_dispatch"]):
        a = ev.get("action", {}) or {}
        if a.get("created_task_id"):
            return a["created_task_id"]
    return None


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        traceback.print_exc()
        try:
            with open(f"e2e_autonomous_evidence_{stamp}_partial.json", "w") as f:
                json.dump(EV, f, indent=2, default=str)
        except Exception:
            pass
        sys.exit(1)
