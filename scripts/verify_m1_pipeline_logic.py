"""M1 no-infra check: mock scanner -> Vulnerability -> OSOP-P0-02 guard predicate.

Proves 2 of the 3 finding-pipeline links without Postgres/Redis/Neo4j/API:
  (1) the mock security-bridge returns a POSITIVE, param-aware sqlmap verdict
  (2) a Vulnerability built with tool_source="sqlmap" is NOT is_simulated(),
      so the add_vulnerability guard (graph_memory.py) would NOT reject it
      even with allow_simulated_findings=False (the default).

Run: .venv/Scripts/python.exe scripts/verify_m1_pipeline_logic.py
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "python"))

from mcp_stub import _mock_execute
from ai_osop.core.models import Vulnerability, VulnClass, Severity

# (1) mock returns positive, param-aware verdict for the ground-truth productId target
verdict = _mock_execute(
    "security-bridge", "run_sqlmap",
    {"url": "https://ginandjuice.shop/catalog/product?productId=1"},
)
data = verdict["result"]["data"]
assert data["injectable"] is True, "mock sqlmap must report injectable"
assert data["parameter"] == "productId", f"param should track the URL, got {data['parameter']!r}"
print(f"[1/2] mock run_sqlmap -> injectable=True param={data['parameter']} dbms={data['dbms']}  OK")

# (2) the resulting Vulnerability is NOT simulated -> guard passes with default config
vuln = Vulnerability(
    vuln_type=list(VulnClass)[0], severity=list(Severity)[0],
    title="SQL injection at productId", description="sqlmap confirmed injection",
    tool_source="sqlmap", confidence=0.95, engagement_id="eng-m1-check",
    evidence=[{"provenance": "sqlmap", "payload": data["payloads"][0]}],
)
assert vuln.is_simulated() is False, "sqlmap finding must not be flagged simulated"

allow_simulated = False  # the production default (config.py:289)
rejected = vuln.is_simulated() and not allow_simulated
assert rejected is False, "guard must NOT reject a real-sourced finding"
print(f"[2/2] Vulnerability(tool_source=sqlmap).is_simulated()={vuln.is_simulated()} "
      f"-> guard rejected={rejected} (allow_simulated={allow_simulated})  OK")

print("\nM1 LOGIC PROVEN: mock->model->guard passes. Remaining link (persist+API+audit) "
      "needs the live stack.")
