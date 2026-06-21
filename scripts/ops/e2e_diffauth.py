"""
E2E runtime proof: Phase 2 Differential Authorization.

Flow:
  POST /engagements  +  import user_a & user_b sessions
      -> autonomous discovery (map->capture->extract) yields APIEndpoints
  -> dispatch run_diff_auth_analysis (engagement_id, workflow_id, user_a, user_b)
      -> replay each endpoint as user_a / user_b / anonymous -> compare -> persist
         ReplayResult / AuthorizationTest / DiffAuthFinding

Target: demo.owasp-juice.shop (deliberately vulnerable; many GET endpoints are open
to anonymous -> real broken_access_control findings).
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
HOST = "brokencrystals.com"

stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
SCOPE_ID = f"e2e-diffauth-{stamp}"
EV = {"scope_id": SCOPE_ID, "target_host": HOST, "started": datetime.utcnow().isoformat()}


def cy(q, **kw):
    with NEO.session() as s:
        return [r.data() for r in s.run(q, **kw)]


def counts(eid, tag):
    c = {
        "APIEndpoint": cy("MATCH (w:Workflow {engagement_id:$e})-[:CALLED]->(a:APIEndpoint) RETURN count(DISTINCT a) AS c", e=eid)[0]["c"],
        "ReplayResult": cy("MATCH (r:ReplayResult {engagement_id:$e}) RETURN count(r) AS c", e=eid)[0]["c"],
        "AuthorizationTest": cy("MATCH (t:AuthorizationTest {engagement_id:$e}) RETURN count(t) AS c", e=eid)[0]["c"],
        "DiffAuthFinding": cy("MATCH (d:DiffAuthFinding {engagement_id:$e}) RETURN count(d) AS c", e=eid)[0]["c"],
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
    return get(f"/engagements/{eid}/audit-log", params=({"event_types": types} if types else None))


def wait_task(tid, label, timeout=400):
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
    return get(f"/tasks/{tid}")


def find_dispatch(eid, created_type=None):
    """Find an auto_map_dispatch task id, or an auto_task_chain of created_type."""
    for ev in audit(eid):
        a = ev.get("action", {}) or {}
        if created_type and a.get("created_type") == created_type:
            return a.get("created_task_id")
        if not created_type and ev.get("event_type") == "auto_map_dispatch" and a.get("created_task_id"):
            return a.get("created_task_id")
    return None


def cookie(val):
    return [{"name": "welcomebanner_status", "value": val, "domain": HOST, "path": "/"}]


def main():
    sess = post("/engagements", {
        "engagement_id": SCOPE_ID, "domains": [HOST],
        "allowed_techniques": ["passive", "active"],
        "authorization_ref": "E2E-DIFFAUTH", "roe": {"note": "diff-auth proof"},
    })
    eid = sess["session_id"]
    EV["engagement_id"] = eid
    print(f"[1] engagement: {eid}")
    EV["counts_before"] = counts(eid, "before")

    # Import two distinct sessions; first import triggers autonomous discovery.
    put(f"/engagements/{eid}/sessions/user_a", {"user_label": "user_a", "cookies": cookie("dismiss")})
    put(f"/engagements/{eid}/sessions/user_b", {"user_label": "user_b", "cookies": cookie("seen")})
    print("[2] imported user_a + user_b sessions")

    # Wait for auto map_workflow, read workflow_id, wait for the extract to finish.
    print("[3] waiting for autonomous discovery (map->capture->extract)...")
    map_id = None
    t0 = time.time()
    while time.time() - t0 < 90 and not map_id:
        map_id = find_dispatch(eid)
        if map_id:
            break
        time.sleep(3)
    if not map_id:
        raise RuntimeError("map_workflow not auto-dispatched")
    mt = wait_task(map_id, "map_workflow")
    workflow_id = (mt.get("result") or {}).get("workflow_id", "")
    EV["workflow_id"] = workflow_id
    print(f"    workflow_id={workflow_id}")

    ext_id = None
    t0 = time.time()
    while time.time() - t0 < 120 and not ext_id:
        ext_id = find_dispatch(eid, "extract_har_api_inventory")
        if ext_id:
            break
        time.sleep(3)
    if ext_id:
        wait_task(ext_id, "extract")
    print(f"    APIEndpoints discovered: {counts(eid, 'after-discovery')['APIEndpoint']}")

    # Dispatch the differential-authorization analysis (the Phase 2 task).
    print("[4] dispatching run_diff_auth_analysis...")
    da = post("/tasks", {
        "task_type": "run_diff_auth_analysis", "agent_type": "workflow", "priority": 6,
        "engagement_id": eid,
        "payload": {"engagement_id": eid, "workflow_id": workflow_id,
                    "user_a": "user_a", "user_b": "user_b"},
    })
    da_id = da["id"]
    EV["diff_auth_task_id"] = da_id
    dt = wait_task(da_id, "diff_auth", timeout=400)
    EV["diff_auth_result"] = dt.get("result")
    res = dt.get("result") or {}
    print(f"[5] diff-auth result: status={dt['status']} "
          f"replays={res.get('replay_count')} tests={res.get('endpoints_tested')} "
          f"findings={res.get('findings_count')}")

    EV["counts_after"] = counts(eid, "after")

    # Sample findings from the graph.
    findings = cy(
        "MATCH (a:APIEndpoint)-[:HAS_DIFF_AUTH_FINDING]->(d:DiffAuthFinding {engagement_id:$e}) "
        "RETURN d.category AS category, d.test_identity_id AS identity, d.confidence AS confidence, "
        "a.method AS method, a.path AS path ORDER BY d.confidence DESC LIMIT 20", e=eid)
    EV["sample_findings"] = findings
    print(f"[6] findings ({len(findings)}):")
    for f in findings[:12]:
        print(f"      [{f['confidence']}] {f['category']} {f['method']} {f['path']} as {f['identity']}")

    # Category breakdown + confidence stats.
    by_cat = {}
    for f in findings:
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
    EV["findings_by_category"] = by_cat
    EV["confidence_scores"] = res.get("confidence_scores", [])

    # Verify the node graph relationships exist.
    rel = cy(
        "MATCH (a:APIEndpoint)-[:HAS_AUTH_TEST]->(t:AuthorizationTest {engagement_id:$e}) "
        "OPTIONAL MATCH (t)-[:PRODUCED]->(d:DiffAuthFinding) "
        "RETURN count(DISTINCT t) AS tests, count(DISTINCT d) AS findings_via_test", e=eid)[0]
    EV["graph_relationships"] = rel
    print(f"[7] graph: AuthorizationTest={rel['tests']} PRODUCED->findings={rel['findings_via_test']}")

    allaudit = audit(eid)
    by_type = {}
    for ev in allaudit:
        by_type[ev.get("event_type")] = by_type.get(ev.get("event_type"), 0) + 1
    EV["audit_event_counts"] = by_type
    print(f"[8] audit events: {json.dumps(by_type)}")

    EV["finished"] = datetime.utcnow().isoformat()
    out = f"e2e_diffauth_evidence_{stamp}.json"
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
            with open(f"e2e_diffauth_evidence_{stamp}_partial.json", "w") as f:
                json.dump(EV, f, indent=2, default=str)
        except Exception:
            pass
        sys.exit(1)
