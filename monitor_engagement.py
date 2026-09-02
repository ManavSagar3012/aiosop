"""
Continuous engagement monitor for AI-OSOP.
Polls the API every 15 seconds, prints status updates,
and exits when the engagement completes or halts.
"""
import os, sys, time, json, urllib.request, urllib.error
from datetime import datetime
from jose import jwt
from dotenv import load_dotenv

load_dotenv()

ENG_ID = "eng-20260826163438-eng-qosmos-live-002"
BASE   = "http://localhost:8201"
secret = os.getenv("OSOP_JWT_SECRET")
token  = jwt.encode(
    {"sub": "senior_admin", "role": "senior_operator",
     "exp": datetime(2026, 8, 28).timestamp()},
    secret, algorithm="HS256",
)
HEADERS = {"Authorization": f"Bearer {token}"}
POLL_INTERVAL = 15  # seconds
TERMINAL_PHASES = {"halted", "completed", "reporting"}

seen_tasks = set()
seen_findings_count = 0
iteration = 0


def api_get(path: str):
    req = urllib.request.Request(f"{BASE}{path}", headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"_error": str(e)}


def fmt_time():
    return datetime.now().strftime("%H:%M:%S")


def print_banner(msg):
    print(f"\n{'='*70}")
    print(f"  [{fmt_time()}]  {msg}")
    print(f"{'='*70}")


def print_section(title, content):
    print(f"\n  --- {title} ---")
    if isinstance(content, str):
        print(f"  {content}")
    elif isinstance(content, list):
        for line in content:
            print(f"  {line}")


def check_engagement():
    data = api_get(f"/engagements/{ENG_ID}")
    if "_error" in data:
        return None, f"API error: {data['_error']}"
    phase = data.get("phase", "unknown")
    return phase, data


def check_agents():
    data = api_get("/agents")
    if isinstance(data, dict) and "_error" in data:
        return []
    running = [a for a in data if a.get("status") == "running"]
    return running


def check_tasks():
    data = api_get(f"/tasks/{ENG_ID}")
    if isinstance(data, dict) and "_error" in data:
        # Try individual task lookup
        return None
    return data


def check_dlq():
    data = api_get(f"/dlq?engagement_id={ENG_ID}")
    if isinstance(data, dict) and "_error" in data:
        return 0
    return data.get("total", 0)


def check_findings():
    data = api_get(f"/engagements/{ENG_ID}")
    if isinstance(data, dict) and "_error" not in data:
        findings = data.get("findings", [])
        return findings if isinstance(findings, list) else []
    return []


def read_recent_logs():
    """Read last N lines of backend.log for LLM output and errors."""
    try:
        with open("backend.log", "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        recent = lines[-80:]  # last 80 lines
        interesting = []
        for line in recent:
            line = line.strip()
            if not line:
                continue
            if any(kw in line for kw in [
                "llm_raw_output", "assign_task", "task_completed",
                "task_phase_violation", "primary_llm_failed",
                "llm_error_retrying", "phase_transition",
                "findings_stored", "vulnerability_stored",
                "approval_request", "exploit", "recon_complete",
                "nuclei", "scan_result", "tool_call",
            ]):
                # Truncate long lines
                if len(line) > 200:
                    line = line[:200] + "..."
                interesting.append(line)
        return interesting[-10:]  # last 10 interesting lines
    except Exception:
        return []


def monitor_loop():
    global iteration, seen_findings_count

    print_banner(f"MONITORING ENGAGEMENT: {ENG_ID}")
    print(f"  Target: qosmos.qnulabs.com")
    print(f"  Polling every {POLL_INTERVAL}s until completion...")
    print(f"  Press Ctrl+C to stop\n")

    while True:
        iteration += 1
        phase, eng_data = check_engagement()

        if phase is None:
            print(f"  [{fmt_time()}] iter={iteration}  ERROR: {eng_data}")
            time.sleep(POLL_INTERVAL)
            continue

        # Active agents
        running_agents = check_agents()
        agent_summary = ", ".join(
            f"{a['agent_id']}→{a.get('current_task','?')}"
            for a in running_agents
        ) if running_agents else "none"

        # DLQ
        dlq_count = check_dlq()

        # Findings
        findings = check_findings()
        new_findings = len(findings) - seen_findings_count
        if new_findings > 0:
            seen_findings_count = len(findings)

        # Print status line
        print(f"  [{fmt_time()}] iter={iteration:>3}  "
              f"phase={phase:<25} "
              f"active_agents={len(running_agents)}  "
              f"dlq={dlq_count}  "
              f"findings={len(findings)}"
              f"{f'  (+{new_findings} NEW!)' if new_findings > 0 else ''}")

        if running_agents:
            print(f"           agents: {agent_summary}")

        # Show recent interesting log lines
        log_lines = read_recent_logs()
        if log_lines:
            print(f"           recent_logs:")
            for ll in log_lines[-5:]:
                print(f"             {ll[:180]}")

        # Check for new findings detail
        if new_findings > 0 and findings:
            print_section("NEW FINDINGS", [
                f"  [{i+1}] {f.get('title', f.get('type', 'unknown'))} "
                f"severity={f.get('severity', '?')} "
                f"confidence={f.get('confidence', '?')}"
                for i, f in enumerate(findings[-new_findings:])
            ])

        # Terminal phase check
        if phase in TERMINAL_PHASES:
            print_banner(f"ENGAGEMENT REACHED PHASE: {phase}")
            if phase == "completed":
                print("  The engagement has completed successfully!")
            elif phase == "halted":
                reason = eng_data.get("halt_reason", "unknown") if isinstance(eng_data, dict) else "unknown"
                print(f"  The engagement was halted. Reason: {reason}")
            elif phase == "reporting":
                print("  The engagement has entered the reporting phase.")
                print("  Continuing to monitor until final completion...")
                # Don't exit for reporting - keep watching
                time.sleep(POLL_INTERVAL)
                continue

            # Print final summary
            print_section("FINAL SUMMARY", [
                f"  Phase: {phase}",
                f"  Total findings: {len(findings)}",
                f"  DLQ entries: {dlq_count}",
                f"  Monitor iterations: {iteration}",
            ])
            return phase

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    try:
        result = monitor_loop()
        sys.exit(0 if result in ("completed", "reporting") else 1)
    except KeyboardInterrupt:
        print(f"\n  [{fmt_time()}] Monitoring stopped by user.")
        sys.exit(0)
