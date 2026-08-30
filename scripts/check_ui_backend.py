"""Check UI frontend API calls vs backend endpoints."""
import re, os, json

# UI API calls
ui_calls = set()
for root, dirs, files in os.walk("ui/src"):
    for f in files:
        if f.endswith((".ts", ".tsx")):
            path = os.path.join(root, f)
            with open(path, "r", errors="ignore") as fh:
                content = fh.read()
                for m in re.finditer(r"API_BASE\}/([a-zA-Z_/\$\{\}]+)", content):
                    endpoint = m.group(1)
                    clean = re.sub(r"\$\{[^}]+\}", "{id}", endpoint)
                    clean = clean.rstrip("/")
                    ui_calls.add("/" + clean)

# Backend routes (from OpenAPI spec)
backend_routes = {
    "/agents", "/agents/{agent_id}",
    "/approvals/pending", "/approvals/{request_id}", "/approvals/{request_id}/resolve",
    "/dlq", "/dlq/{entry_id}", "/dlq/{entry_id}/discard", "/dlq/{entry_id}/requeue", "/dlq/{entry_id}/retry",
    "/engagements", "/engagements/{session_id}",
    "/engagements/{session_id}/attack-paths", "/engagements/{session_id}/audit-log",
    "/engagements/{session_id}/diff-auth", "/engagements/{session_id}/discovery/trigger",
    "/engagements/{session_id}/findings", "/engagements/{session_id}/findings/{finding_id}/replay",
    "/engagements/{session_id}/findings/{finding_id}/resolve",
    "/engagements/{session_id}/findings/{finding_id}/vault",
    "/engagements/{session_id}/findings/{finding_id}/verify",
    "/engagements/{session_id}/graph", "/engagements/{session_id}/halt",
    "/engagements/{session_id}/hypotheses", "/engagements/{session_id}/invariants",
    "/engagements/{session_id}/payouts", "/engagements/{session_id}/poc/generate",
    "/engagements/{session_id}/report", "/engagements/{session_id}/sessions",
    "/engagements/{session_id}/sessions/{user_label}",
    "/engagements/{session_id}/transition", "/engagements/{session_id}/uncertainty",
    "/engagements/{session_id}/waf-profiles",
    "/health", "/health/mcp", "/health/metrics", "/health/platform",
    "/health/startup", "/health/system", "/health/tooling", "/health/tooling/deep",
    "/intelligence/vulnerability-edu/{vuln_class}",
    "/metrics", "/ready",
    "/system/config", "/system/dlq/discard", "/system/dlq/entries",
    "/system/dlq/requeue", "/system/dlq/stats", "/system/mcp/health",
    "/system/readiness/trust-score", "/system/sandbox/status", "/system/skills/stats",
    "/tasks", "/tasks/{task_id}",
}

def normalize(route):
    return re.sub(r"\{[^}]+\}", "{id}", route)

normalized_backend = {normalize(r): r for r in backend_routes}

print("=== UI ENDPOINTS vs BACKEND ===")
for ep in sorted(ui_calls):
    norm = ep
    if norm in normalized_backend:
        print(f"  OK  {ep}  ->  {normalized_backend[norm]}")
    else:
        found = False
        for nb, orig in normalized_backend.items():
            if norm.startswith(nb.rstrip("/{id}")):
                found = True
                print(f"  OK  {ep}  ->  {orig}")
                break
        if not found:
            print(f"  MISSING  {ep}")

print()
print("=== WEBSOCKET ===")
print("  UI expects: /ws/engagements/{sessionId}")
ws_routes = [r for r in backend_routes if "ws" in r.lower()]
if ws_routes:
    print(f"  Backend: {ws_routes}")
else:
    print("  Backend: NOT in REST routes (check WS handler in main.py)")

print()
print("=== PORT MISMATCH ===")
print("  UI .env: VITE_API_BASE = http://127.0.0.1:8200")
print("  Server running on: 8201")
print("  MUST fix UI .env or start server on 8200")
