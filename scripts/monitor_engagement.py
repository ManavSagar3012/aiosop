#!/usr/bin/env python3
"""Real-time engagement monitor - polls API every 3 seconds and prints live state."""

import json
import os
import sys
import time
import urllib.request
import urllib.error

TOKEN = os.environ.get("OSOP_TOKEN", "")
if not TOKEN:
    env_path = os.path.join(os.path.dirname(__file__), "..", "ui", ".env")
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                if line.startswith("VITE_OSOP_TOKEN="):
                    TOKEN = line.strip().split("=", 1)[1]
                    break

if not TOKEN:
    print("ERROR: Set OSOP_TOKEN or create ui/.env with VITE_OSOP_TOKEN")
    sys.exit(1)

BASE = "http://127.0.0.1:8200"
SID = "eng-20260825131835-eng-qosmos-live"
INTERVAL = 3
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


def api_get(path):
    try:
        req = urllib.request.Request(f"{BASE}{path}", headers=HEADERS)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return {"error": str(e)}


def render():
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    print("\033[2J\033[H", end="")
    print("=" * 70)
    print(f"  LIVE MONITOR -- qosmos.qnulabs.com")
    print(f"  {now}  |  Polling every {INTERVAL}s  |  Ctrl+C to stop")
    print("=" * 70)

    # Engagement state
    eng = api_get(f"/engagements/{SID}")
    if "error" not in eng:
        print(f"\n  [ENGAGEMENT]")
        print(f"     Phase:   {eng['phase']}")
        print(f"     Target:  {eng['scope']['domains'][0]}")
        print(f"     Updated: {eng.get('updated_at', '?')[:19]}")
    else:
        print(f"\n  [ENGAGEMENT] {eng.get('error','unknown')}")

    # Agents
    agents = api_get("/agents")
    if isinstance(agents, list):
        active = [a for a in agents if a["status"] != "idle"]
        idle = [a for a in agents if a["status"] == "idle"]
        print(f"\n  [AGENTS]  active: {len(active)}  idle: {len(idle)}  total: {len(agents)}")
        if active:
            for a in active:
                print(f"     * {a['agent_type']:20s} {a['agent_id'][:25]:25s} task={a.get('current_task', 'none')}")
        for atype in ["recon", "vuln_analysis", "exploit_validation"]:
            typed = [a for a in agents if a["agent_type"] == atype]
            for a in typed:
                icon = "*" if a["status"] != "idle" else "."
                q = a.get("task_queue_depth", 0)
                ct = a.get("current_task", "-")
                print(f"     {icon} {a['agent_type']:20s} {a['agent_id'][:25]:25s} status={a['status']:10s} q={q} task={ct}")

    # Approvals
    approvals = api_get("/approvals/pending")
    if isinstance(approvals, list):
        print(f"\n  [APPROVALS]  {len(approvals)} pending")
        for a in approvals[:3]:
            print(f"     ! {a.get('request_id', '?')[:30]} -- {a.get('description', '')[:50]}")

    # Findings
    findings = api_get(f"/engagements/{SID}/findings")
    if isinstance(findings, list):
        print(f"\n  [FINDINGS]  {len(findings)}")
        for f in findings[:8]:
            sev = f.get("severity", "?")
            icon = {"critical": "!!!", "high": "!!", "medium": "!", "low": "."}.get(sev, "?")
            status = f.get("status", "?")
            title = f.get("title", "?")[:40]
            print(f"     [{icon:3s}] [{sev:8s}] {title:40s} {status}")

    # Graph
    graph = api_get(f"/engagements/{SID}/graph")
    if isinstance(graph, dict) and "nodes" in graph:
        nodes = graph["nodes"]
        edges = graph["edges"]
        labels = {}
        for n in nodes:
            l = n.get("label", "Unknown")
            labels[l] = labels.get(l, 0) + 1
        label_str = "  ".join(f"{k}:{v}" for k, v in sorted(labels.items(), key=lambda x: -x[1]))
        print(f"\n  [GRAPH]  nodes: {len(nodes)}  edges: {len(edges)}")
        print(f"     {label_str}")

    # Audit log
    audit = api_get(f"/engagements/{SID}/audit-log")
    if isinstance(audit, list):
        print(f"\n  [AUDIT]  last 5 of {len(audit)}")
        for e in audit[-5:]:
            t = e.get("event_type", "?")
            ts = str(e.get("timestamp", "?"))[:19]
            print(f"     {ts}  {t}")

    # MCP Health
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
                print(f"     {icon} {name:20s} tools={tools}  {verdict}")

    print(f"\n{'=' * 70}")


if __name__ == "__main__":
    try:
        while True:
            render()
            time.sleep(INTERVAL)
    except KeyboardInterrupt:
        print("\n\nMonitor stopped.")
