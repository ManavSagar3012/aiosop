"""One-off hygiene helper (2026-08-30): move one-off fix/update scripts and
stale diagnostics from the repo root into archive/ so the root reflects the
actual product. Files are MOVED, not modified or deleted."""
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PATTERNS = [
    "fix_*.py", "update_*.py", "tmp_*.py", "get_status*.py", "clear_old_tasks.py",
    "halt_all_but_current.py", "move_startup_test.py", "restart_for_e2e.cmd",
    "session_memory_append.py", "instrument_graph_tracing.py", "instrument_memory.py",
    "start_qwen.sh", "start_with_openrouter.sh", "start_servers.py", "start_server.py",
    "test_api.py", "test_db.py", "test_lab.py", "test_llm_client.py", "monitor.py",
    "golden_path_target.py", "generate_jwt.py", "generate_jwt_senior.py",
    "mock_bundle.js", "mock_bundle.js.map", "nul", "restricted.json",
    "autonomous_findings.json", "autonomous_scorecard.json", "ai_findings_qosmos.json",
    "scan_results_qosmos.json", "config_debug.json", "config_debug2.json",
    "final_audit_report.json", "startup_health.json", "nuclei_mcp_exec.json",
    "nuclei_exec_result.json", "openrouter_test_result.json", "agent_password123",
    "ginandjuice_engagement.json", "ginandjuice_recon_task.json",
    "create_qosmos_eng.json", "create_qosmos_eng_live.json", "common_wordlist.txt",
]

moved = 0
for pattern in PATTERNS:
    for f in ROOT.glob(pattern):
        if not f.is_file():
            continue
        dest = ROOT / "archive" / "scripts" / f.name
        if dest.exists():
            dest = ROOT / "archive" / "scripts" / f"{f.stem}_dup{f.suffix}"
        shutil.move(str(f), str(dest))
        moved += 1
print(f"archived {moved} files")
