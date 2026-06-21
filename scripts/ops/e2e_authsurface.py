"""
E2E runtime proof: authenticated-surface automation chain.

Drives the LIVE API (:8200) + orchestrator so the new wiring runs for real:

    auth session  ->  map_workflow
                  ->  capture_authenticated_surface   (auto-chained by orchestrator)
                  ->  extract_har_api_inventory        (auto-chained by orchestrator)
                  ->  (:Workflow)-[:CALLED]->(:APIEndpoint) in Neo4j

Reads graph counts directly from Neo4j (bolt) before/after.
Target: OWASP Juice Shop (deliberately-vulnerable, in-scope for sec testing).
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
TARGET = "https://juice-shop.herokuapp.com/"
HOST = "juice-shop.herokuapp.com"

stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
EID = f"e2e-authsurface-{stamp}"

EV = {"engagement_id": EID, "target": TARGET, "started": datetime.utcnow().isoformat()}


def cy(q, **kw):
    with NEO.session() as s:
        return [r.data() for r in s.run(q, **kw)]


def counts(tag):
    c = {
        "APIEndpoint_total": cy("MATCH (n:APIEndpoint) RETURN count(n) AS c")[0]["c"],
        "Workflow_total": cy("MATCH (n:Workflow) RETURN count(n) AS c")[0]["c"],
        "Task_total": cy("MATCH (n:Task) RETURN count(n) AS c")[0]["c"],
        "CALLED_total": cy("MATCH ()-[r:CALLED]->() RETURN count(r) AS c")[0]["c"],
        "eng_APIEndpoint": cy(
            "MATCH (w:Workflow {engagement_id:$e})-[:CALLED]->(a:APIEndpoint) "
            "RETURN count(DISTINCT a) AS c", e=EID)[0]["c"],
        "eng_Task": cy("MATCH (t:Task {engagement_id:$e}) RETURN count(t) AS c", e=EID)[0]["c"],
    }
    print(f"[counts:{tag}] {json.dumps(c)}")
    return c


def post(path, body):
    r = httpx.post(f"{API}{path}", headers=HDR, json=body, timeout=30)
    r.raise_for_status()
    return r.json()


def get(path, params=None):
    r = httpx.get(f"{API}{path}", headers=HDR, params=params, timeout=30)
    r.raise_for_status()
    return r.json()


def wait_task(tid, label, timeout=300):
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout:
        t = get(f"/tasks/{tid}")
        st = t["status"]
        if st != last:
            print(f"  [{label}] {tid[:8]} status={st} agent={t.get('assigned_agent_id')}")
            last = st
        if st in ("completed", "failed", "cancelled"):
            return t
        time.sleep(3)
    print(f"  [{label}] {tid[:8]} TIMEOUT after {timeout}s (last={last})")
    return get(f"/tasks/{tid}")


def chain_events():
    return get(f"/engagements/{EID}/audit-log", params={"event_types": ["auto_task_chain"]})


def main():
    print(f"=== ENGAGEMENT {EID} ===")

    # 1. Fresh engagement
    sess = post("/engagements", {
        "engagement_id": EID,
        "domains": [HOST],
        "allowed_techniques": ["passive", "active"],
        "authorization_ref": "E2E-AUTHSURFACE-PROOF",
        "roe": {"note": "automated e2e proof of authenticated-surface chain"},
    })
    EV["engagement_created"] = {"id": sess.get("session_id") or sess.get("id"), "phase": sess.get("phase")}
    print(f"[1] engagement created: phase={sess.get('phase')}")

    # 2. Import user session -> makes engagement AUTHENTICATED (chain precondition)
    us = httpx.put(
        f"{API}/engagements/{EID}/sessions/user_a", headers=HDR, timeout=30,
        json={
            "user_label": "user_a",
            "cookies": [{"name": "welcomebanner_status", "value": "dismiss",
                         "domain": HOST, "path": "/"}],
            "metadata": {"persona": "User A", "purpose": "e2e"},
        },
    )
    us.raise_for_status()
    EV["session_imported"] = us.json()
    print(f"[2] session imported user_a: cookies={us.json().get('cookie_count')} expires={us.json().get('expires_at')}")

    # 3. counts BEFORE
    EV["counts_before"] = counts("before")

    # 4. dispatch map_workflow (root of the chain)
    root = post("/tasks", {
        "task_type": "map_workflow",
        "agent_type": "workflow",
        "priority": 7,
        "engagement_id": EID,
        "payload": {"url": TARGET, "user_label": "user_a", "name": "JuiceShop Auth Journey"},
    })
    root_id = root["id"]
    EV["map_workflow_task_id"] = root_id
    print(f"[4] map_workflow task created: {root_id}")

    rt = wait_task(root_id, "map_workflow", timeout=300)
    EV["map_workflow"] = {"status": rt["status"], "assigned_agent_id": rt.get("assigned_agent_id"),
                          "result_keys": list((rt.get("result") or {}).keys()),
                          "workflow_id": (rt.get("result") or {}).get("workflow_id")}
    if rt["status"] != "completed":
        EV["map_workflow"]["result"] = rt.get("result")
        print(f"[!] map_workflow did not complete: {rt.get('result')}")

    # 5. wait for orchestrator to auto-chain capture + extract
    print("[5] waiting for auto-chain (capture -> extract)...")
    capture_id = extract_id = None
    t0 = time.time()
    while time.time() - t0 < 90 and not (capture_id and extract_id):
        for ev in chain_events():
            a = ev.get("action", {})
            if a.get("created_type") == "capture_authenticated_surface":
                capture_id = a.get("created_task_id")
            if a.get("created_type") == "extract_har_api_inventory":
                extract_id = a.get("created_task_id")
        if capture_id and extract_id:
            break
        time.sleep(3)
    EV["chain_audit_events"] = chain_events()
    EV["capture_task_id"] = capture_id
    EV["extract_task_id"] = extract_id
    print(f"    capture_task_id={capture_id}  extract_task_id={extract_id}")

    if capture_id:
        ct = wait_task(capture_id, "capture", timeout=300)
        EV["capture"] = {"status": ct["status"], "assigned_agent_id": ct.get("assigned_agent_id"),
                         "result": ct.get("result")}
    # extract may only be created after capture completes (chained on capture success)
    if not extract_id and capture_id:
        t0 = time.time()
        while time.time() - t0 < 60 and not extract_id:
            for ev in chain_events():
                a = ev.get("action", {})
                if a.get("created_type") == "extract_har_api_inventory":
                    extract_id = a.get("created_task_id")
            if extract_id:
                break
            time.sleep(3)
        EV["extract_task_id"] = extract_id
        EV["chain_audit_events"] = chain_events()
        print(f"    (post-capture) extract_task_id={extract_id}")
    if extract_id:
        et = wait_task(extract_id, "extract", timeout=180)
        EV["extract"] = {"status": et["status"], "assigned_agent_id": et.get("assigned_agent_id"),
                         "result": et.get("result")}

    # 6. counts AFTER
    EV["counts_after"] = counts("after")

    # 7. graph proof: Workflow -> APIEndpoint relationships
    rels = cy(
        "MATCH (w:Workflow {engagement_id:$e})-[:CALLED]->(a:APIEndpoint) "
        "RETURN a.method AS method, a.path AS path, a.host AS host LIMIT 25", e=EID)
    EV["sample_api_endpoints"] = rels
    print(f"[7] Workflow->APIEndpoint sample ({len(rels)} shown):")
    for r in rels[:15]:
        print(f"      {r.get('method')} {r.get('host')}{r.get('path')}")

    # 8. task dependency edges (SPAWNED)
    spawned = cy(
        "MATCH (p:Task {engagement_id:$e})-[:SPAWNED]->(c:Task) "
        "RETURN p.type AS parent, c.type AS child, c.status AS child_status", e=EID)
    EV["task_spawned_edges"] = spawned
    print(f"[8] Task SPAWNED edges: {json.dumps(spawned)}")

    # 9. engagement history (audit) summary
    allaudit = get(f"/engagements/{EID}/audit-log")
    by_type = {}
    for ev in allaudit:
        by_type[ev.get("event_type")] = by_type.get(ev.get("event_type"), 0) + 1
    EV["audit_event_counts"] = by_type
    EV["audit_total"] = len(allaudit)
    print(f"[9] audit/history events total={len(allaudit)}: {json.dumps(by_type)}")

    EV["finished"] = datetime.utcnow().isoformat()
    out = f"e2e_evidence_{stamp}.json"
    with open(out, "w") as f:
        json.dump(EV, f, indent=2, default=str)
    print(f"\n=== EVIDENCE WRITTEN: {out} ===")
    NEO.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        traceback.print_exc()
        try:
            with open(f"e2e_evidence_{stamp}_partial.json", "w") as f:
                json.dump(EV, f, indent=2, default=str)
        except Exception:
            pass
        sys.exit(1)
