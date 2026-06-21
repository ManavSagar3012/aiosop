"""PHASE 2–6 full end-to-end execution proof.

API -> Orchestrator -> PlaywrightAgent -> MCP Registry -> browser-mcp ->
Playwright -> evidence_vault -> Neo4j.

Drives a minimal verification engagement via HTTP, polls until done,
then queries Neo4j for the graph state and lists evidence files on disk.
"""

import asyncio
import json
import os
import sys
import time
import uuid

import requests

sys.path.insert(0, "src")
from ai_osop.memory.graph_memory import GraphMemory

API = "http://127.0.0.1:8200"
TOKEN = "test-token"
H = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}


def call(method: str, path: str, body=None, timeout=30):
    fn = getattr(requests, method.lower())
    url = f"{API}{path}"
    r = fn(url, headers=H, json=body, timeout=timeout)
    return r


def main() -> int:
    trace: dict = {"hops": []}

    # ============ HOP 1: API Request -> engagement_id ============
    print("[HOP 1] POST /engagements")
    engagement_id_suffix = f"e2e-{uuid.uuid4().hex[:8]}"
    r = call("POST", "/engagements", {
        "engagement_id": engagement_id_suffix,
        "domains": ["example.com"],
        "ips": [],
        "exclusions": [],
        "allowed_techniques": ["recon", "browser_navigation"],
        "restrictions": [],
        "approval_required_for": [],
        "roe": {"max_concurrent": 1, "rps_per_target": 1},
    })
    assert r.status_code == 200, f"engagement creation failed: {r.status_code} {r.text[:300]}"
    eng = r.json()
    session_id = eng["session_id"]
    print(f"  -> session_id={session_id}  phase={eng['phase']}")
    trace["hops"].append({"hop": "api_engagement", "session_id": session_id, "http_status": r.status_code})

    # ============ HOP 2: Orchestrator -> task_id ============
    print("[HOP 2] POST /tasks  (type=map_workflow, agent_type=workflow)")
    task_payload = {
        "user_label": "verify_user",
        "name": "e2e_verification_journey",
        "actions": [
            {"type": "navigate", "url": "https://example.com/", "name": "Landing"},
        ],
        "url": "https://example.com/",
    }
    r = call("POST", "/tasks", {
        "task_type": "map_workflow",
        "priority": 5,
        "agent_type": "workflow",
        "payload": task_payload,
        "dependencies": [],
        "approval_required": False,
        "engagement_id": session_id,
    })
    assert r.status_code == 200, f"task creation failed: {r.status_code} {r.text[:300]}"
    task = r.json()
    task_id = task["id"]
    print(f"  -> task_id={task_id}  initial_status={task['status']}")
    trace["hops"].append({"hop": "orchestrator_task", "task_id": task_id, "agent_type": task["agent_type"]})

    # ============ HOP 3: Agent -> poll task to completion ============
    print("[HOP 3] polling /tasks/{task_id} until non-running")
    deadline = time.time() + 180
    last_status = None
    final_task = None
    while time.time() < deadline:
        r = call("GET", f"/tasks/{task_id}")
        if r.status_code != 200:
            time.sleep(2)
            continue
        t = r.json()
        if t["status"] != last_status:
            print(f"  -> status={t['status']}  assigned_agent={t.get('assigned_agent_id')}")
            last_status = t["status"]
        if t["status"] in ("completed", "failed"):
            final_task = t
            break
        time.sleep(2)

    assert final_task is not None, "task never completed within 180s"
    trace["hops"].append({
        "hop": "agent_completed",
        "agent_id": final_task.get("assigned_agent_id"),
        "final_status": final_task["status"],
        "result_keys": list((final_task.get("result") or {}).keys()),
        "result": final_task.get("result"),
    })

    if final_task["status"] != "completed":
        print(f"  FAIL — task ended {final_task['status']}: {json.dumps(final_task.get('result', {}))[:500]}")
        # still continue to gather evidence — we want to see what we got
    else:
        print(f"  -> COMPLETED. result keys: {list(final_task['result'].keys())}")

    workflow_id = None
    if isinstance(final_task.get("result"), dict):
        workflow_id = final_task["result"].get("workflow_id")
    print(f"  -> workflow_id from result: {workflow_id}")

    # ============ HOP 4: Evidence vault ============
    print("[HOP 4] listing evidence_vault/{engagement}")
    ev_root = os.path.abspath("evidence_vault")
    ev_dir = os.path.join(ev_root, session_id)
    files = []
    if os.path.isdir(ev_dir):
        for root, _, names in os.walk(ev_dir):
            for n in names:
                p = os.path.join(root, n)
                files.append({"path": p, "size_bytes": os.path.getsize(p)})
    for f in files:
        print(f"  -> {f['path']} ({f['size_bytes']} B)")
    if not files:
        print(f"  WARN: no files under {ev_dir}")
    trace["hops"].append({"hop": "evidence_vault", "engagement_dir": ev_dir, "files": files})

    # ============ HOP 5: Neo4j -> graph state ============
    print("[HOP 5] querying Neo4j for Workflow + Step + Evidence")
    asyncio.run(_inspect_graph(session_id, workflow_id, trace))

    # Write the trace report
    with open("e2e_trace.json", "w") as f:
        json.dump(trace, f, indent=2, default=str)
    print(f"trace written to e2e_trace.json")
    return 0 if final_task["status"] == "completed" else 1


async def _inspect_graph(engagement_id: str, workflow_id, trace):
    gm = GraphMemory()
    await gm.connect()
    async with gm._driver.session() as session:
        # All workflows in this engagement
        wf_q = await session.run(
            "MATCH (w:Workflow {engagement_id: $eid}) RETURN w.id AS id, w.name AS name",
            {"eid": engagement_id},
        )
        workflows = [dict(r) async for r in wf_q]
        print(f"  -> workflows in graph: {workflows}")

        # Workflow -> Step -> Evidence chain
        chain_q = await session.run(
            """
            MATCH (w:Workflow {engagement_id: $eid})
            OPTIONAL MATCH (w)-[:HAS_STEP]->(s:Step)
            OPTIONAL MATCH (s)-[:HAS_EVIDENCE]->(ev:Evidence)
            RETURN w.id AS workflow_id, s.id AS step_id,
                   collect(DISTINCT {type: ev.type, path: ev.path}) AS evidence
            """,
            {"eid": engagement_id},
        )
        chain = [dict(r) async for r in chain_q]
        print(f"  -> Workflow->Step->Evidence chain rows: {len(chain)}")
        for row in chain:
            print(f"     workflow={row['workflow_id']}  step={row['step_id']}  evidence={row['evidence']}")

        # Workflow -> Evidence direct edge
        wf_ev_q = await session.run(
            "MATCH (w:Workflow {engagement_id: $eid})-[:HAS_EVIDENCE]->(ev:Evidence) "
            "RETURN w.id AS workflow_id, collect(ev.type) AS evidence_types",
            {"eid": engagement_id},
        )
        wf_ev = [dict(r) async for r in wf_ev_q]
        print(f"  -> Workflow->Evidence direct rows: {wf_ev}")

        trace["hops"].append({"hop": "neo4j_graph",
                              "workflows": workflows,
                              "chain": chain,
                              "workflow_evidence": wf_ev})


if __name__ == "__main__":
    sys.exit(main())
