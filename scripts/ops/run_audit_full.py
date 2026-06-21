"""Full E2E Audit and Verification Script.

Drives a minimal verification engagement, checks evidence artifacts,
validates Neo4j graph state, and checks live MCP invocation counts.
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

async def inspect_graph(engagement_id: str, workflow_id: str):
    gm = GraphMemory()
    await gm.connect()
    try:
        async with gm._driver.session() as session:
            # Check Workflow exists
            wf_res = await session.run(
                "MATCH (w:Workflow {engagement_id: $eid}) RETURN w.id AS id",
                {"eid": engagement_id}
            )
            workflows = [r["id"] async for r in wf_res]
            if not workflows:
                return False, "No workflows found in Neo4j for this engagement."

            # Check chain integrity
            chain_res = await session.run(
                """
                MATCH (w:Workflow {engagement_id: $eid})
                OPTIONAL MATCH (w)-[:HAS_STEP]->(s:Step)
                OPTIONAL MATCH (s)-[:HAS_EVIDENCE]->(ev:Evidence)
                RETURN w.id AS workflow_id, s.id AS step_id, ev.id as ev_id, ev.type as ev_type
                """,
                {"eid": engagement_id}
            )
            rows = [dict(r) async for r in chain_res]
            steps = {r["step_id"] for r in rows if r["step_id"]}
            evidence = {r["ev_type"] for r in rows if r["ev_type"]}
            
            print(f"    [Neo4j] Workflows: {workflows}")
            print(f"    [Neo4j] Steps found: {list(steps)}")
            print(f"    [Neo4j] Evidence types found: {list(evidence)}")
            
            if not steps:
                return False, "No steps found in Neo4j linked to the workflow."
            if "screenshot" not in evidence or "dom" not in evidence:
                return False, "Evidence nodes (screenshot/dom) missing in Neo4j step chain."
                
            return True, "Neo4j graph check passed."
    finally:
        await gm.close()

def main() -> int:
    print("=== AI-OSOP FULL E2E AUDIT AND VERIFICATION ===")
    
    # 1. Trigger Engagement
    print("\n[Step 1] Creating new engagement...")
    engagement_id = f"e2e-audit-{uuid.uuid4().hex[:8]}"
    r = call("POST", "/engagements", {
        "engagement_id": engagement_id,
        "domains": ["example.com"],
        "ips": [],
        "exclusions": [],
        "allowed_techniques": ["recon", "browser_navigation"],
        "restrictions": [],
        "approval_required_for": [],
        "roe": {"max_concurrent": 1, "rps_per_target": 1},
    })
    if r.status_code != 200:
        print(f"  FAIL: Engagement creation failed: {r.status_code} {r.text}")
        return 1
    session_id = r.json()["session_id"]
    print(f"  -> Session created: {session_id}")

    # 2. Trigger task
    print("\n[Step 2] Scheduling map_workflow task...")
    r = call("POST", "/tasks", {
        "task_type": "map_workflow",
        "priority": 5,
        "agent_type": "workflow",
        "payload": {
            "user_label": "audit_user",
            "name": "e2e_audit_journey",
            "actions": [
                {"type": "navigate", "url": "https://example.com/", "name": "Landing"},
            ],
            "url": "https://example.com/",
        },
        "dependencies": [],
        "approval_required": False,
        "engagement_id": session_id,
    })
    if r.status_code != 200:
        print(f"  FAIL: Task scheduling failed: {r.status_code} {r.text}")
        return 1
    task_id = r.json()["id"]
    print(f"  -> Task scheduled: {task_id}")

    # 3. Poll to completion
    print("\n[Step 3] Polling task status...")
    deadline = time.time() + 180
    final_task = None
    while time.time() < deadline:
        r = call("GET", f"/tasks/{task_id}")
        if r.status_code == 200:
            t = r.json()
            print(f"  -> Task status: {t['status']}")
            if t["status"] in ("completed", "failed"):
                final_task = t
                break
        time.sleep(3)
        
    if not final_task:
        print("  FAIL: Task timed out after 180 seconds.")
        return 1
    if final_task["status"] != "completed":
        print(f"  FAIL: Task finished with status: {final_task['status']}. Result: {final_task.get('result')}")
        return 1

    # 4. Check Evidence Vault on Disk
    print("\n[Step 4] Auditing Evidence Vault files...")
    ev_dir = os.path.join("evidence_vault", session_id)
    if not os.path.exists(ev_dir):
        print(f"  FAIL: Evidence directory {ev_dir} does not exist.")
        return 1

    screenshot_ok = False
    dom_ok = False
    har_ok = False
    trace_ok = False

    for root, _, files in os.walk(ev_dir):
        for name in files:
            path = os.path.join(root, name)
            size = os.path.getsize(path)
            print(f"  Found file: {path} ({size} bytes)")
            
            if name.endswith(".png") and "shot_" in name:
                if size > 0:
                    screenshot_ok = True
                    print("    -> Screenshot size > 0: YES")
                else:
                    print("    -> Screenshot size > 0: NO (EMPTY!)")
                    
            elif name.endswith(".html") and "dom_" in name:
                if size > 0:
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        dom_content = f.read()
                    if "<html" in dom_content.lower():
                        dom_ok = True
                        print("    -> DOM snapshot contains '<html': YES")
                    else:
                        print("    -> DOM snapshot contains '<html': NO")
                else:
                    print("    -> DOM snapshot size > 0: NO (EMPTY!)")
                    
            elif name.endswith(".har") and "audit_user" in name:
                if size > 0:
                    har_ok = True
                    print("    -> HAR file size > 0: YES")
                else:
                    print("    -> HAR file size > 0: NO (EMPTY!)")
                    
            elif name.endswith(".zip") and "trace_" in name:
                if size > 0:
                    trace_ok = True
                    print("    -> Trace file size > 0: YES")
                else:
                    print("    -> Trace file size > 0: NO (EMPTY!)")

    # Verify all files are present
    if not screenshot_ok:
        print("  FAIL: Screenshot validation failed.")
        return 1
    if not dom_ok:
        print("  FAIL: DOM snapshot validation failed.")
        return 1
    if not har_ok:
        print("  FAIL: HAR validation failed.")
        return 1
    if not trace_ok:
        print("  FAIL: Trace validation failed.")
        return 1
        
    print("  -> Evidence files validation: PASSED")

    # 5. Inspect Graph Memory in Neo4j
    print("\n[Step 5] Checking Neo4j Graph integrity...")
    workflow_id = final_task.get("result", {}).get("workflow_id")
    graph_ok, graph_msg = asyncio.run(inspect_graph(session_id, workflow_id))
    if not graph_ok:
        print(f"  FAIL: {graph_msg}")
        return 1
    print("  -> Neo4j Graph linkage: PASSED")

    # 6. Verify live MCP call counts
    print("\n[Step 6] Validating MCP call counts...")
    r = call("GET", "/system/health/full")
    if r.status_code != 200:
        print(f"  FAIL: Failed to fetch full health check: {r.status_code} {r.text}")
        return 1
    health = r.json()
    call_counts = health.get("mcp_call_counts", {})
    print(f"  mcp_call_counts: {call_counts}")
    browser_calls = call_counts.get("browser-mcp", 0)
    if browser_calls <= 0:
        print("  FAIL: browser-mcp call count is 0. Telemetry tracking failed.")
        return 1
    print(f"  -> browser-mcp call count: {browser_calls} (PASSED)")

    print("\n================ FINAL VERDICT ================")
    print("STATUS: ALL E2E VERIFICATION AUDITS PASSED!")
    print("Screenshot: OK  DOM: OK  HAR: OK  Trace: OK  Graph: OK  MCP Calls: OK")
    print("===============================================")
    return 0

if __name__ == "__main__":
    sys.exit(main())
