#!/usr/bin/env python3
"""Real-time monitor for qosmos.qnulabs.com engagement."""

import json
import os
import sys
import time
import urllib.request

TOKEN = ""
env_path = os.path.join(os.path.dirname(__file__), "..", "ui", ".env")
if os.path.exists(env_path):
    with open(env_path) as f:
        for line in f:
            if line.startswith("VITE_OSOP_TOKEN="):
                TOKEN = line.strip().split("=", 1)[1]

if not TOKEN:
    print("ERROR: Set OSOP_TOKEN or create ui/.env with VITE_OSOP_TOKEN")
    sys.exit(1)

BASE = "http://127.0.0.1:8200"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
TASK_IDS = ["task-69651fa189bf", "task-602e85f2a017", "task-cc51343d59b3"]


def api_get(path):
    try:
        req = urllib.request.Request(f"{BASE}{path}", headers=HEADERS)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception:
        return {}


def render():
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    print("\033[2J\033[H", end="")
    print("=" * 72)
    print(f"  QOSMOS.QNULABS.COM  --  Live Engagement Monitor")
    print(f"  {now}  |  Ctrl+C to stop")
    print("=" * 72)

    # Health + dispatch stats
    health = api_get("/health")
    if health:
        dispatch = health.get("dispatch", {})
        t = dispatch.get("tasks", {})
        print(f"\n  [SYSTEM]  Orchestrator: {'RUNNING' if dispatch.get('orchestrator_running') else 'DOWN'}")
        print(f"            Sessions: {dispatch.get('sessions', 0)}")
        print(f"            Tasks: pending={t.get('pending',0)} running={t.get('running',0)} completed={t.get('completed',0)} failed={t.get('failed',0)} blocked={t.get('blocked',0)}")

    # Engagement state
    eng = api_get("/engagements/eng-20260825140213-eng-qosmos-live")
    if eng and "phase" in eng:
        print(f"\n  [ENGAGEMENT]  Phase: {eng['phase']}")
        print(f"                Target: {eng['scope']['domains'][0]}")
        print(f"                Updated: {eng.get('updated_at', '?')[:19]}")

    # Our specific tasks
    print(f"\n  [TASKS]  (qosmos engagement)")
    for tid in TASK_IDS:
        t = api_get(f"/tasks/{tid}")
        if t and "type" in t:
            status = t.get("status", "?")
            agent = t.get("assigned_agent_id", "none")
            icon = {"pending": ".", "running": "*", "completed": "+", "failed": "x", "blocked": "B"}.get(status[0:3] if len(status) > 3 else status, "?")
            # Try matching by first 3 chars
            for k, v in {"pending": ".", "running": "*", "completed": "+", "failed": "x", "blocked": "B"}.items():
                if status.startswith(k[:3]):
                    icon = v
                    break
            result = t.get("result")
            result_str = ""
            if result and isinstance(result, dict):
                err = result.get("error", result.get("status", ""))
                if err:
                    result_str = f"  result={str(err)[:40]}"
            print(f"    {icon} {t['type']:25s} status={status:15s} agent={agent}{result_str}")

    # Findings
    findings = api_get("/engagements/eng-20260825140213-eng-qosmos-live/findings")
    if isinstance(findings, list):
        print(f"\n  [FINDINGS]  {len(findings)}")
        for f in findings[:10]:
            sev = f.get("severity", "?")
            icon = {"critical": "!!!", "high": "!!", "medium": "!", "low": "."}.get(sev, "?")
            print(f"    [{icon:3s}] [{sev:8s}] {f.get('title', '?')[:45]:45s} {f.get('status', '?')}")

    # Graph
    graph = api_get("/engagements/eng-20260825140213-eng-qosmos-live/graph")
    if isinstance(graph, dict) and "nodes" in graph:
        nodes = graph["nodes"]
        edges = graph["edges"]
        labels = {}
        for n in nodes:
            l = n.get("label", "Unknown")
            labels[l] = labels.get(l, 0) + 1
        label_str = "  ".join(f"{k}:{v}" for k, v in sorted(labels.items(), key=lambda x: -x[1]))
        print(f"\n  [GRAPH]  nodes={len(nodes)}  edges={len(edges)}  {label_str}")

    # Approvals
    approvals = api_get("/approvals/pending")
    if isinstance(approvals, list) and approvals:
        print(f"\n  [APPROVALS]  {len(approvals)} pending -- ACTION REQUIRED")
        for a in approvals[:3]:
            print(f"    ! {a.get('request_id', '?')[:30]} -- {a.get('action_type', '?')} target={a.get('target', '?')[:40]}")

    # Audit log
    audit = api_get("/engagements/eng-20260825140213-eng-qosmos-live/audit-log")
    if isinstance(audit, list):
        print(f"\n  [AUDIT]  last 5 of {len(audit)}")
        for e in audit[-5:]:
            print(f"    {str(e.get('timestamp', '?'))[:19]}  {e.get('event_type', '?')}")

    # MCP
    mcp = api_get("/health/mcp")
    if isinstance(mcp, dict) and "detail" in mcp:
        detail = mcp["detail"]
        healthy = sum(1 for v in detail.values() if isinstance(v, dict) and v.get("verdict", "") != "down")
        down = mcp.get("down_servers", [])
        print(f"\n  [MCP]  {healthy} healthy, {len(down)} down")
        for name, info in detail.items():
            if isinstance(info, dict):
                verdict = info.get("verdict", "?")
                icon = "+" if verdict != "down" else "x"
                tools = info.get("tool_count", 0)
                print(f"    {icon} {name:20s} tools={tools}  {verdict}")

    print(f"\n{'=' * 72}")


if __name__ == "__main__":
    try:
        while True:
            render()
            time.sleep(3)
    except KeyboardInterrupt:
        print("\n\nMonitor stopped.")
